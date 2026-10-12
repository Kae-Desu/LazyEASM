import contextlib
import io
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

os.environ.setdefault('FLASK_SECRET_KEY', 'test-secret')
os.environ.setdefault('JWT_SECRET', 'test-jwt-secret')

from PIL import Image, ImageDraw

from modules import InitDB
from tests.helpers import access_token
from utils import db_utils, screenshots as ss


def jpeg(draw_fn, size=(320, 200)) -> bytes:
    image = Image.new('RGB', size, 'white')
    draw_fn(ImageDraw.Draw(image))
    out = io.BytesIO()
    image.save(out, format='JPEG')
    return out.getvalue()


def fake_resolver(table):
    return lambda host: set(table.get(host, []))


class RequestFilterTests(unittest.TestCase):
    def test_internal_destinations_blocked_except_the_asset(self):
        f = ss.RequestFilter(allowed_ips={'10.0.0.5'}, resolver=fake_resolver({
            'intranet.example.com': ['10.0.0.5'], 'evil.example.com': ['127.0.0.1'],
            'cdn.example.net': ['93.184.216.34'], 'mixed.example.com': ['93.184.216.34', '192.168.1.1'],
        }))
        self.assertTrue(f.allows('http://intranet.example.com/login'))      # the asset itself
        self.assertTrue(f.allows('https://cdn.example.net/app.js'))
        self.assertTrue(f.allows('data:image/png;base64,AAAA'))
        self.assertFalse(f.allows('http://169.254.169.254/latest/meta-data/'))
        self.assertFalse(f.allows('http://evil.example.com/'))             # DNS pointing at loopback
        self.assertFalse(f.allows('http://mixed.example.com/'))            # any internal address blocks
        self.assertFalse(f.allows('http://[::1]:8080/'))
        self.assertFalse(f.allows('file:///etc/passwd'))
        self.assertEqual(len(f.blocked), 5)


class ImageTests(unittest.TestCase):
    def test_perceptual_hash_tolerates_small_changes(self):
        page = lambda d: d.rectangle((20, 20, 300, 60), fill='black')
        page_with_clock = lambda d: (page(d), d.rectangle((280, 180, 300, 190), fill='gray'))
        different = lambda d: d.ellipse((60, 40, 260, 180), fill='blue')
        a, b, c = (ss.average_hash(jpeg(fn)) for fn in (page, page_with_clock, different))
        self.assertLessEqual(ss.hash_distance(a, b), ss.CHANGE_THRESHOLD_BITS)
        self.assertGreater(ss.hash_distance(a, c), ss.CHANGE_THRESHOLD_BITS)

    def test_thumbnail_size(self):
        thumb = Image.open(io.BytesIO(ss.make_thumbnail(jpeg(lambda d: None, (1280, 800)))))
        self.assertLessEqual(thumb.size[0], ss.THUMB_SIZE[0])
        self.assertLessEqual(thumb.size[1], ss.THUMB_SIZE[1])


class StorageTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        self.shot_dir = tempfile.mkdtemp()
        for target, attr, value in ((InitDB, 'DB_NAME', self.db_path), (db_utils, 'DB_PATH', self.db_path),
                                    (ss, 'SCREENSHOT_DIR', self.shot_dir)):
            patcher = patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            InitDB.init_db()
        dom_id = db_utils.upsert_domain('example.com')
        self.sub_id = db_utils.upsert_subdomain('shop.example.com', dom_id)
        conn = db_utils.get_db_connection()
        conn.execute("INSERT INTO http_services (http_id, host, port_num, is_https) VALUES (1, 'shop.example.com', 443, 1)")
        conn.commit()
        conn.close()

    def tearDown(self):
        for suffix in ('', '-wal', '-shm'):
            if os.path.exists(self.db_path + suffix):
                os.remove(self.db_path + suffix)

    def capture(self, draw_fn, title='Shop'):
        image = jpeg(draw_fn)
        return ss.Capture(http_id=1, host='shop.example.com', url='https://shop.example.com/', ok=True,
                          image=image, thumbnail=ss.make_thumbnail(image), phash=ss.average_hash(image),
                          final_url='https://shop.example.com/', status_code=200, title=title)


class StorageTests(StorageTestCase):
    def test_targets(self):
        self.assertEqual(db_utils.get_screenshot_targets(), [{'http_id': 1, 'host': 'shop.example.com', 'url': 'https://shop.example.com/'}])
        self.assertEqual(db_utils.get_screenshot_targets([]), [])

    def test_change_detection_pruning_and_title(self):
        deleted = []
        store = lambda cap, n: db_utils.store_screenshot(cap, f'{n:032x}.jpg', f'{n:032x}_thumb.jpg', ss.CHANGE_THRESHOLD_BITS,
                                                         keep=2, delete_file=deleted.append)
        login = lambda d: d.rectangle((20, 20, 300, 60), fill='black')
        parked = lambda d: d.ellipse((60, 40, 260, 180), fill='blue')

        self.assertFalse(store(self.capture(login), 1))                       # first capture: nothing to compare
        self.assertFalse(store(self.capture(login), 2))                       # same look
        self.assertTrue(store(self.capture(parked, 'Domain for sale'), 3))   # page replaced

        changes = [c for c in db_utils.get_changes(host='shop.example.com') if c['change_type'] == 'appearance_changed']
        self.assertEqual(len(changes), 1)
        self.assertIn('Domain for sale', changes[0]['summary'])
        self.assertEqual(deleted, [f'{1:032x}.jpg', f'{1:032x}_thumb.jpg'])  # oldest pruned (keep=2)

        conn = db_utils.get_db_connection()
        try:
            self.assertEqual(conn.execute('SELECT title FROM http_services WHERE http_id = 1').fetchone()[0], 'Domain for sale')
            latest = db_utils._get_screenshots_for_host(conn.cursor(), 'shop.example.com')
        finally:
            conn.close()
        self.assertEqual((len(latest), latest[0]['capture_count'], latest[0]['image_file']), (1, 2, f'{3:032x}.jpg'))

    def test_disabled_and_unavailable(self):
        with patch.object(ss, 'screenshots_enabled', return_value=False):
            self.assertFalse(ss.run_screenshots()['available'])
        with patch.object(ss, 'capture_pages', side_effect=ss.ScreenshotUnavailable('Chromium missing')):
            result = ss.run_screenshots()
        self.assertEqual((result['available'], result['error']), (False, 'Chromium missing'))

    def test_run_writes_files_and_records(self):
        with patch.object(ss, 'capture_pages', return_value=[self.capture(lambda d: None)]):
            result = ss.run_screenshots()
        self.assertEqual(result['captured'], 1)
        self.assertEqual(len(os.listdir(self.shot_dir)), 2)
        self.assertTrue(db_utils.get_setting('last_screenshot_check'))


class WebTests(StorageTestCase):
    def setUp(self):
        super().setUp()
        with patch.object(ss, 'capture_pages', return_value=[self.capture(lambda d: None)]):
            ss.run_screenshots()
        import main
        self.main = main
        self.client = main.app.test_client()
        self.client.set_cookie('access_token', access_token(main))
        self.shot_id = db_utils.get_screenshot(1)['screenshot_id']

    def test_image_routes(self):
        for kind in ('full', 'thumb'):
            response = self.client.get(f'/screenshots/{self.shot_id}/{kind}')
            self.assertEqual((response.status_code, response.mimetype), (200, 'image/jpeg'))
            self.assertIn('private', response.headers['Cache-Control'])
        self.assertEqual(self.client.get(f'/screenshots/{self.shot_id}/other').status_code, 404)
        self.assertEqual(self.client.get('/screenshots/999/full').status_code, 404)
        self.assertEqual(self.main.app.test_client().get(f'/screenshots/{self.shot_id}/full').status_code, 302)

    def test_file_name_from_db_is_validated(self):
        conn = db_utils.get_db_connection()
        conn.execute("UPDATE screenshots SET image_file = '../../.env'")
        conn.commit()
        conn.close()
        self.assertEqual(self.client.get(f'/screenshots/{self.shot_id}/full').status_code, 404)

    def test_pages_show_screenshots(self):
        assets = self.client.get('/api/assets?q=shop').get_json()
        self.assertEqual(assets['items'][0]['screenshot_id'], self.shot_id)
        html = self.client.get(f'/assets/subdomain/{self.sub_id}').get_data(as_text=True)
        self.assertIn(f'/screenshots/{self.shot_id}/full', html)


class TrickyPage(BaseHTTPRequestHandler):
    body = (b'<html><head><title>Login portal</title></head><body><h1>Sign in</h1>'
            b'<img src="http://169.254.169.254/latest/meta-data/iam/x.png">'
            b'<script src="http://10.255.255.1/internal.js"></script></body></html>')

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


class RealBrowserTests(unittest.TestCase):
    """Uses the installed Chromium; skipped when it is not available."""

    def test_capture_blocks_internal_requests(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), TrickyPage)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_address[1]}/'
        try:
            result = ss.capture_pages([{'http_id': 1, 'host': '127.0.0.1', 'url': url}])[0]
        except ss.ScreenshotUnavailable as e:
            self.skipTest(str(e))
        self.assertTrue(result.ok, result.error)
        self.assertEqual((result.status_code, result.title), (200, 'Login portal'))
        self.assertTrue(result.image.startswith(b'\xff\xd8'))                 # JPEG
        self.assertIn('http://169.254.169.254/latest/meta-data/iam/x.png', result.blocked)
        self.assertIn('http://10.255.255.1/internal.js', result.blocked)


if __name__ == '__main__':
    unittest.main()
