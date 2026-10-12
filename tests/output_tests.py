import contextlib
import csv
import datetime
import hashlib
import hmac
import io
import json
import os
import tempfile
import unittest

from tests.helpers import access_token
from unittest.mock import MagicMock, patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

import requests

from modules import InitDB, Notify
from utils import db_utils, env_manager, export


def settings(**env):
    return patch.object(Notify, 'get_env', side_effect=lambda key, default=None: env.get(key, default))


def ok_response():
    r = MagicMock()
    r.status_code = 204
    r.raise_for_status.return_value = None
    return r


class NotifyTests(unittest.TestCase):
    def test_fans_out_to_configured_channels(self):
        env = dict(DISCORD_WEBHOOK_URL='https://discord.test/hook', DISCORD_USER_ID='42',
                   SLACK_WEBHOOK_URL='https://hooks.slack.com/services/T/B/X',
                   NOTIFY_WEBHOOK_URL='https://receiver.test/lazyeasm', NOTIFY_WEBHOOK_SECRET='s3cret')
        with settings(**env), patch.object(Notify.requests, 'post', return_value=ok_response()) as post:
            success, message = Notify.send_message('**Takeover Check**\nfound 1')

        self.assertTrue(success)
        self.assertEqual(message, 'Sent via discord, slack, webhook')
        calls = {c.args[0]: c.kwargs for c in post.call_args_list}
        self.assertEqual(calls['https://discord.test/hook']['json'], {'content': '<@42> **Takeover Check**\nfound 1'})
        self.assertEqual(calls['https://hooks.slack.com/services/T/B/X']['json'], {'text': '*Takeover Check*\nfound 1'})

        hook = calls['https://receiver.test/lazyeasm']
        body = json.loads(hook['data'])
        self.assertEqual((body['source'], body['title'], body['message']), ('lazyeasm', 'Takeover Check', 'Takeover Check\nfound 1'))
        expected = hmac.new(b's3cret', hook['data'], hashlib.sha256).hexdigest()
        self.assertEqual(hook['headers']['X-LazyEASM-Signature'], f'sha256={expected}')

    def test_no_channels_and_partial_failure(self):
        with settings():
            self.assertEqual(Notify.send_message('hi'), (False, 'No notification channel configured'))

        def post(url, **kwargs):
            if 'slack' in url:
                raise requests.exceptions.ConnectionError()
            return ok_response()

        with settings(DISCORD_WEBHOOK_URL='https://discord.test/hook', SLACK_WEBHOOK_URL='https://hooks.slack.com/x'), \
             patch.object(Notify.requests, 'post', side_effect=post):
            success, message = Notify.send_message('hi')
        self.assertTrue(success)
        self.assertIn('Failed: slack', message)

    def test_email(self):
        env = dict(SMTP_HOST='smtp.example.com', SMTP_PORT='587', SMTP_USERNAME='u', SMTP_PASSWORD='p',
                   SMTP_FROM='lazyeasm@example.com', SMTP_TO='a@example.com, b@example.com')
        server = MagicMock()
        server.__enter__.return_value = server
        with settings(**env), patch.object(Notify.smtplib, 'SMTP', return_value=server) as smtp:
            success, message = Notify.send_message('**Misconfiguration Check**\n• [HIGH] x')

        self.assertTrue(success, message)
        smtp.assert_called_once_with('smtp.example.com', 587, timeout=Notify.SMTP_TIMEOUT)
        server.starttls.assert_called_once()
        server.login.assert_called_once_with('u', 'p')
        sent = server.send_message.call_args.args[0]
        self.assertEqual(sent['Subject'], '[LazyEASM] Misconfiguration Check')
        self.assertEqual(sent['To'], 'a@example.com, b@example.com')
        self.assertNotIn('**', sent.get_content())

    def test_embed_alerts_reach_text_channels(self):
        with settings(SLACK_WEBHOOK_URL='https://hooks.slack.com/x'), \
             patch.object(Notify.requests, 'post', return_value=ok_response()) as post:
            success, _ = Notify.send_cert_expiry_threshold_alert({1: [{'hostname': 'shop.example.com'}]})
        self.assertTrue(success)
        text = post.call_args.kwargs['json']['text']
        self.assertIn('*SSL Certificate Expiry Alert*', text)
        self.assertIn('shop.example.com', text)


class SettingsValidationTests(unittest.TestCase):
    def test_newlines_rejected_everywhere(self):
        self.assertFalse(env_manager.validate_config('SMTP_HOST', 'smtp.example.com\nADMIN_PASS=x')[0])
        self.assertFalse(env_manager.validate_config('GEMINI_API_KEY', 'abc\rdef')[0])

    def test_channel_formats(self):
        self.assertTrue(env_manager.validate_config('SLACK_WEBHOOK_URL', 'https://hooks.slack.com/services/T/B/X')[0])
        self.assertFalse(env_manager.validate_config('SLACK_WEBHOOK_URL', 'https://evil.example.com/')[0])
        self.assertTrue(env_manager.validate_config('SMTP_TO', 'a@example.com, b@example.com')[0])
        self.assertFalse(env_manager.validate_config('SMTP_TO', 'not-an-email')[0])
        self.assertFalse(env_manager.validate_config('SMTP_SECURITY', 'tls')[0])


class ExportTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        for target, attr in ((InitDB, 'DB_NAME'), (db_utils, 'DB_PATH')):
            patcher = patch.object(target, attr, self.db_path)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        dom_id = db_utils.upsert_domain('example.com')
        db_utils.upsert_subdomain('=cmd.example.com', dom_id)
        conn = db_utils.get_db_connection()
        conn.executescript("""
            INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'example.com', 443, 1);
            INSERT INTO technologies (tech_id, http_id, tech_name, tech_version) VALUES (1, 1, 'Nginx', '1.20.1');
            INSERT INTO cve_intel (cve_id, epss, in_kev) VALUES ('CVE-2021-23017', 0.5, 1);
        """)
        conn.commit()
        conn.close()
        db_utils.upsert_vulnerability(1, 'CVE-2021-23017', 7.7, 'resolver bug')
        fixed = db_utils.upsert_vulnerability(1, 'CVE-2019-0001', 5.0, 'old')
        db_utils.set_vulnerability_status(fixed, 'fixed')
        db_utils.upsert_finding('exposed_env', 'example.com', 'Environment file exposed', 'high',
                                {'detail': 'A .env file is served.', 'urls': ['https://example.com/.env']})

        import jwt
        import main
        self.client = main.app.test_client()
        token = access_token(main)
        self.client.set_cookie('access_token', token)

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def rows(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('attachment', response.headers['Content-Disposition'])
        return list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))

    def test_formula_cells_are_neutralized(self):
        self.assertEqual(export.safe_cell('=HYPERLINK("x")'), '\'=HYPERLINK("x")')
        self.assertEqual(export.safe_cell('-1+2'), "'-1+2")
        self.assertEqual(export.safe_cell(-3), -3)
        self.assertEqual(export.safe_cell(['a', 'b']), 'a; b')

    def test_assets_csv(self):
        rows = self.rows('/api/export/assets.csv')
        self.assertEqual(sorted(r['name'] for r in rows), ["'=cmd.example.com", 'example.com'])
        self.assertEqual(list(rows[0].keys()), export.ASSET_COLUMNS)

    def test_findings_csv_and_status_filter(self):
        rows = self.rows('/api/export/findings.csv')
        self.assertEqual([(r['kind'], r['identifier'], r['status']) for r in rows], [
            ('cve', 'CVE-2019-0001', 'fixed'), ('cve', 'CVE-2021-23017', 'open'), ('finding', 'exposed_env', 'open')])
        kev_row = rows[1]
        self.assertEqual((kev_row['priority'], kev_row['in_kev'], kev_row['severity'], kev_row['technology']),
                         ('P1', 'yes', 'high', 'Nginx 1.20.1'))
        self.assertIn('https://example.com/.env', rows[2]['evidence'])

        open_rows = self.rows('/api/export/findings.csv?status=open')
        self.assertEqual(len(open_rows), 2)

    def test_json_and_errors(self):
        data = self.client.get('/api/export/findings.json?status=open').get_json()
        self.assertEqual({d['identifier'] for d in data}, {'CVE-2021-23017', 'exposed_env'})
        self.assertEqual(self.client.get('/api/export/assets.xml').status_code, 404)
        self.assertEqual(self.client.get('/api/export/findings.csv?status=bogus').status_code, 400)
        self.client.delete_cookie('access_token')
        self.assertEqual(self.client.get('/api/export/assets.csv').status_code, 401)


if __name__ == '__main__':
    unittest.main()
