import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import anthropic
import openai

from modules import AskAI


def settings(**env):
    """Patch AskAI.get_env with a fixed config."""
    return patch.object(AskAI, 'get_env', side_effect=lambda key, default=None: env.get(key, default))


def claude_response(text='📋 APA INI?\nTest.', stop_reason='end_turn', model='claude-opus-5-5', stop_details=None):
    blocks = [SimpleNamespace(type='text', text=text)] if text else []
    return SimpleNamespace(content=blocks, stop_reason=stop_reason, model=model, stop_details=stop_details)


class ProviderSelectionTests(unittest.TestCase):
    def test_defaults_to_gemini(self):
        with settings():
            self.assertEqual(AskAI.get_ai_settings(), {'provider': 'gemini', 'model': None, 'base_url': None})

    def test_unknown_provider(self):
        with settings(AI_PROVIDER='nope'):
            with self.assertRaisesRegex(AskAI.AIError, 'Unknown AI_PROVIDER'):
                AskAI.generate_text('hi')

    def test_gemini_requires_key(self):
        with settings(AI_PROVIDER='gemini'):
            with self.assertRaisesRegex(AskAI.AIError, 'GEMINI_API_KEY'):
                AskAI.generate_text('hi')


class AnthropicTests(unittest.TestCase):
    def run_claude(self, response=None, side_effect=None, **env):
        client = MagicMock()
        for create in (client.beta.messages.create, client.messages.create):
            create.return_value = response or claude_response()
            create.side_effect = side_effect
        with settings(AI_PROVIDER='anthropic', ANTHROPIC_API_KEY='sk-test', **env), \
             patch.object(anthropic, 'Anthropic', return_value=client) as ctor:
            result = AskAI.generate_text('prompt')
        return result, client, ctor

    def test_default_model_uses_refusal_fallback(self):
        (text, model), client, ctor = self.run_claude()
        self.assertEqual((text, model), ('📋 APA INI?\nTest.', 'claude-opus-5-5'))
        ctor.assert_called_once_with(api_key='sk-test', timeout=AskAI.REQUEST_TIMEOUT)
        kwargs = client.beta.messages.create.call_args.kwargs
        self.assertEqual(kwargs['model'], 'claude-opus-5-5')
        self.assertEqual(kwargs['fallbacks'], 'default')
        self.assertEqual(kwargs['betas'], ['server-side-fallback-2026-07-01'])
        self.assertEqual(kwargs['output_config'], {'effort': 'medium'})
        self.assertEqual(kwargs['messages'], [{'role': 'user', 'content': 'prompt'}])
        client.messages.create.assert_not_called()

    def test_other_models_skip_fallback(self):
        _, client, _ = self.run_claude(AI_MODEL='claude-haiku-4-5')
        client.beta.messages.create.assert_not_called()
        kwargs = client.messages.create.call_args.kwargs
        self.assertEqual(kwargs['model'], 'claude-haiku-4-5')
        self.assertNotIn('fallbacks', kwargs)

    def test_reports_model_that_answered_after_fallback(self):
        (_, model), _, _ = self.run_claude(claude_response(model='claude-opus-4-8'))
        self.assertEqual(model, 'claude-opus-4-8')

    def test_refusal_is_an_error_not_empty_text(self):
        refusal = claude_response(text=None, stop_reason='refusal', stop_details=SimpleNamespace(category='cyber'))
        with self.assertRaisesRegex(AskAI.AIError, r'declined this request \(cyber\)'):
            self.run_claude(refusal)

    def test_connection_error_is_mapped(self):
        import httpx2
        error = anthropic.APIConnectionError(request=httpx2.Request('POST', 'https://api.anthropic.com/v1/messages'))
        with self.assertRaisesRegex(AskAI.AIError, 'Could not reach the Anthropic API'):
            self.run_claude(side_effect=error)

    def test_no_key_lets_sdk_resolve_credentials(self):
        client = MagicMock()
        client.beta.messages.create.return_value = claude_response()
        with settings(AI_PROVIDER='anthropic'), patch.object(anthropic, 'Anthropic', return_value=client) as ctor:
            AskAI.generate_text('prompt')
        ctor.assert_called_once_with(timeout=AskAI.REQUEST_TIMEOUT)


class OpenAITests(unittest.TestCase):
    def run_openai(self, **env):
        client = MagicMock()
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='answer'))], model='served-model')
        with settings(**env), patch.object(openai, 'OpenAI', return_value=client) as ctor:
            result = AskAI.generate_text('prompt')
        return result, client, ctor

    def test_openai_requires_model(self):
        with self.assertRaisesRegex(AskAI.AIError, 'AI_MODEL'):
            self.run_openai(AI_PROVIDER='openai', OPENAI_API_KEY='k')

    def test_openai(self):
        result, client, ctor = self.run_openai(AI_PROVIDER='openai', AI_MODEL='my-model', OPENAI_API_KEY='k')
        self.assertEqual(result, ('answer', 'served-model'))
        ctor.assert_called_once_with(timeout=AskAI.REQUEST_TIMEOUT, api_key='k')
        self.assertEqual(client.chat.completions.create.call_args.kwargs,
                         {'model': 'my-model', 'messages': [{'role': 'user', 'content': 'prompt'}]})

    def test_compatible_requires_base_url(self):
        with self.assertRaisesRegex(AskAI.AIError, 'AI_BASE_URL'):
            self.run_openai(AI_PROVIDER='openai_compatible', AI_MODEL='llama3')

    def test_compatible_endpoint_without_key(self):
        _, _, ctor = self.run_openai(AI_PROVIDER='openai_compatible', AI_MODEL='llama3',
                                     AI_BASE_URL='http://localhost:11434/v1')
        ctor.assert_called_once_with(timeout=AskAI.REQUEST_TIMEOUT, base_url='http://localhost:11434/v1',
                                     api_key='not-needed')


class SendMessageTests(unittest.TestCase):
    ARGS = dict(cve_id='CVE-2021-23017', cve_score=7.7, cve_description='Off-by-one in resolver',
                tech_name='Nginx', tech_version='1.20.1', asset_name='shop.example.com',
                port=443, is_https=1, tech_stack=[('PHP', '8.1')])

    def test_success_adds_model_footer(self):
        with patch.object(AskAI, 'generate_text', return_value=('📋 APA INI?\nX', 'claude-opus-5-5')) as gen:
            text, error = AskAI.send_message(**self.ARGS)
        self.assertIsNone(error)
        self.assertTrue(text.endswith('_Generated by claude-opus-5-5_'))
        prompt = gen.call_args.args[0]
        self.assertIn('CVE-2021-23017', prompt)
        self.assertIn('443 (HTTPS)', prompt)
        self.assertIn('PHP 8.1', prompt)

    def test_errors_are_returned_not_raised(self):
        with patch.object(AskAI, 'generate_text', side_effect=AskAI.AIError('Claude declined this request.')):
            self.assertEqual(AskAI.send_message(**self.ARGS), (None, 'Claude declined this request.'))


if __name__ == '__main__':
    unittest.main()
