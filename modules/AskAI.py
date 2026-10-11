"""
Module: AskAI.py
Purpose: AI-powered vulnerability recommendations

Providers (set AI_PROVIDER in .env or the dashboard):
    - gemini             Google Gemini (default)
    - anthropic          Anthropic Claude
    - openai             OpenAI
    - openai_compatible  Any OpenAI-compatible endpoint (Ollama, vLLM,
                         LM Studio...) at AI_BASE_URL - keeps findings on
                         infrastructure you control

AI_MODEL overrides the provider's default model. It is required for
openai and openai_compatible.
"""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import get_env

PROVIDERS = ('gemini', 'anthropic', 'openai', 'openai_compatible')
DEFAULT_PROVIDER = 'gemini'

GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-2.5-pro"]
ANTHROPIC_DEFAULT_MODEL = "claude-opus-5-5"

# Claude models that accept server-side refusal fallback ("default" routing)
# and output_config.effort. CVE analysis can trip the cyber safeguards; the
# fallback re-runs a declined request on Anthropic's recommended model.
ANTHROPIC_FALLBACK_MODELS = {"claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5"}
ANTHROPIC_FALLBACK_BETA = "server-side-fallback-2026-07-01"

MAX_OUTPUT_TOKENS = 16000
REQUEST_TIMEOUT = 120.0


class AIError(Exception):
    """AI generation failed; the message is safe to show in the dashboard."""


def get_cvss_severity(score):
    if score is None:
        return "Tidak tersedia"
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    return "None"


def format_tech_stack(tech_stack, affected_tech_name):
    others = [(name, ver) for name, ver in tech_stack if name != affected_tech_name]
    if not others:
        return None
    return ", ".join([f"{name} {ver}" if ver else name for name, ver in others])


def format_ai_response(text: str) -> str:
    text = re.sub(r'(?<!\n\n)(\n)?(📋|🔴|🛠️)', r'\n\n\2', text)
    text = re.sub(r'(?<=\S) (\d\.\s)', r'\n\1', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def get_ai_settings() -> dict:
    """Current AI settings, read on every call so dashboard changes apply immediately."""
    provider = (get_env('AI_PROVIDER') or DEFAULT_PROVIDER).strip().lower()
    return {
        'provider': provider,
        'model': (get_env('AI_MODEL') or '').strip() or None,
        'base_url': (get_env('AI_BASE_URL') or '').strip() or None,
    }


def _generate_gemini(prompt: str, model: str = None) -> tuple:
    try:
        from google import genai
    except ImportError:
        raise AIError("Gemini SDK not installed (pip install google-genai)")

    api_key = get_env('GEMINI_API_KEY')
    if not api_key:
        raise AIError("Gemini API key not configured. Set GEMINI_API_KEY.")

    client = genai.Client(api_key=api_key)
    last_error = None
    for candidate in ([model] if model else GEMINI_MODELS):
        try:
            response = client.models.generate_content(model=candidate, contents=prompt)
            if response.text:
                return response.text, candidate
            last_error = "empty response"
        except Exception as e:
            last_error = str(e)
            print(f"Gemini API error ({candidate}): {e}")
    raise AIError(f"Gemini request failed: {last_error}")


def _generate_anthropic(prompt: str, model: str = None) -> tuple:
    try:
        import anthropic
    except ImportError:
        raise AIError("Anthropic SDK not installed (pip install anthropic)")

    model = model or ANTHROPIC_DEFAULT_MODEL
    api_key = get_env('ANTHROPIC_API_KEY')
    # Without a key in .env, the SDK resolves credentials from the environment
    client = anthropic.Anthropic(api_key=api_key, timeout=REQUEST_TIMEOUT) if api_key \
        else anthropic.Anthropic(timeout=REQUEST_TIMEOUT)

    request = {
        'model': model,
        'max_tokens': MAX_OUTPUT_TOKENS,
        'messages': [{'role': 'user', 'content': prompt}],
    }

    try:
        if model in ANTHROPIC_FALLBACK_MODELS:
            response = client.beta.messages.create(
                **request,
                output_config={'effort': 'medium'},
                betas=[ANTHROPIC_FALLBACK_BETA],
                fallbacks='default',
            )
        else:
            response = client.messages.create(**request)
    except anthropic.AuthenticationError:
        raise AIError("Anthropic rejected the API key. Check ANTHROPIC_API_KEY.")
    except anthropic.NotFoundError:
        raise AIError(f"Anthropic model not found: {model}. Check AI_MODEL.")
    except anthropic.RateLimitError:
        raise AIError("Anthropic rate limit reached. Try again later.")
    except anthropic.APIStatusError as e:
        raise AIError(f"Anthropic API error ({e.status_code}): {e.message}")
    except anthropic.APIConnectionError:
        raise AIError("Could not reach the Anthropic API. Check network connectivity.")

    if response.stop_reason == 'refusal':
        category = getattr(getattr(response, 'stop_details', None), 'category', None)
        raise AIError(f"Claude declined this request{f' ({category})' if category else ''}.")

    text = ''.join(block.text for block in response.content if block.type == 'text')
    if not text:
        raise AIError(f"Claude returned no text (stop reason: {response.stop_reason}).")
    # response.model names the model that actually answered (it differs after a fallback)
    return text, response.model


def _generate_openai(prompt: str, model: str = None, base_url: str = None, compatible: bool = False) -> tuple:
    try:
        import openai
    except ImportError:
        raise AIError("OpenAI SDK not installed (pip install openai)")

    if not model:
        raise AIError("Set AI_MODEL to the model to use with this provider.")
    if compatible and not base_url:
        raise AIError("Set AI_BASE_URL for the OpenAI-compatible endpoint (e.g. http://localhost:11434/v1).")

    api_key = get_env('OPENAI_API_KEY')
    kwargs = {'timeout': REQUEST_TIMEOUT}
    if compatible:
        kwargs['base_url'] = base_url
        # Local servers usually ignore the key, but the SDK requires one
        kwargs['api_key'] = api_key or 'not-needed'
    elif api_key:
        kwargs['api_key'] = api_key
    name = 'OpenAI-compatible endpoint' if compatible else 'OpenAI'

    try:
        client = openai.OpenAI(**kwargs)
        response = client.chat.completions.create(
            model=model,
            messages=[{'role': 'user', 'content': prompt}],
        )
    except openai.AuthenticationError:
        raise AIError(f"{name} rejected the API key. Check OPENAI_API_KEY.")
    except openai.NotFoundError:
        raise AIError(f"{name} model not found: {model}. Check AI_MODEL.")
    except openai.RateLimitError:
        raise AIError(f"{name} rate limit reached. Try again later.")
    except openai.APIStatusError as e:
        raise AIError(f"{name} error ({e.status_code}): {e.message}")
    except openai.APIConnectionError:
        raise AIError(f"Could not reach the {name}. Check AI_BASE_URL and network connectivity.")
    except openai.OpenAIError as e:
        # e.g. no API key configured
        raise AIError(f"{name} client error: {e}")

    choice = response.choices[0] if response.choices else None
    text = choice.message.content if choice and choice.message else None
    if not text:
        raise AIError(f"{name} returned no text.")
    return text, response.model or model


def generate_text(prompt: str) -> tuple:
    """
    Send a prompt to the configured provider.

    Returns:
        (text, model_used)

    Raises:
        AIError
    """
    settings = get_ai_settings()
    provider = settings['provider']

    if provider == 'gemini':
        return _generate_gemini(prompt, settings['model'])
    if provider == 'anthropic':
        return _generate_anthropic(prompt, settings['model'])
    if provider == 'openai':
        return _generate_openai(prompt, settings['model'], settings['base_url'])
    if provider == 'openai_compatible':
        return _generate_openai(prompt, settings['model'], settings['base_url'], compatible=True)
    raise AIError(f"Unknown AI_PROVIDER '{provider}'. Use one of: {', '.join(PROVIDERS)}.")


def build_prompt(cve_id: str, cve_score, cve_description: str,
                 tech_name: str, tech_version: str, asset_name: str,
                 port, is_https, tech_stack: list) -> str:
    severity = get_cvss_severity(cve_score)
    score_display = f"{cve_score} ({severity})" if cve_score is not None else "Tidak tersedia"
    tech_display = f"{tech_name} {tech_version}" if tech_version else tech_name

    port_display = str(port) if port else "tidak diketahui"
    protocol = "HTTPS" if is_https else "HTTP"
    port_info = f"{port_display} ({protocol})"

    stack_info = format_tech_stack(tech_stack, tech_name)
    if stack_info:
        tech_stack_data = f"\nTech Stack (teknologi lain di port yang sama): {stack_info}\n"
        tech_stack_note = f"\nTech stack: {stack_info}. Pastikan kompatibilitas saat patch diterapkan."
    else:
        tech_stack_data = ""
        tech_stack_note = ""

    return f"""Anda adalah Asisten Keamanan Siber. Berikan analisis kerentanan dalam Bahasa Indonesia.

--- DATA SUMBER ---
Aset: {asset_name}
Port: {port_info}
Teknologi Terdampak: {tech_display}
CVE ID: {cve_id}
Skor CVSS: {score_display}
Deskripsi: "{cve_description}"
{tech_stack_data}-------------------

STRICT OUTPUT FORMAT (IKUTI FORMAT INI PERSIS, GUNAKAN NEWLINE):

📋 APA INI?
[1 kalimat singkat, maksimal 30 kata]

🔴 3 RISIKO UTAMA:
1. [1 kalimat, maksimal 20 kata]
2. [1 kalimat, maksimal 20 kata]
3. [1 kalimat, maksimal 20 kata]

🛠️ PANDUAN PATCH (3 LANGKAH):
1. [WAJIB sebutkan versi aman: "Update {tech_name} dari versi {tech_version} ke versi X.X.X+", maksimal 25 kata]
2. [Langkah mitigasi alternatif, maksimal 25 kata]
3. [Langkah monitoring, sebutkan port {port_display} jika relevan, maksimal 25 kata]
{tech_stack_note}

CONTOH OUTPUT:

📋 APA INI?
Kerentanan XSS memungkinkan injeksi JavaScript berbahaya.

🔴 3 RISIKO UTAMA:
1. Pencurian cookie sesi pengguna.
2. Redirect ke situs phishing.
3. Defacement halaman website.

🛠️ PANDUAN PATCH (3 LANGKAH):
1. Update ke versi 2.1.0 atau lebih baru.
2. Tambahkan Content-Security-Policy header.
3. Monitor log di port 443 untuk pola XSS.

Tech stack: Node.js. Pastikan kompatibilitas saat patch.

PENTING: Setiap bagian harus di baris baru. Jangan gabungkan dalam satu baris. Ikuti contoh di atas persis."""


def send_message(cve_id: str, cve_score, cve_description: str,
                 tech_name: str, tech_version: str, asset_name: str,
                 port, is_https, tech_stack: list):
    """
    Generate AI-powered vulnerability recommendation.

    Args:
        cve_id: CVE identifier
        cve_score: CVSS score (float or None)
        cve_description: CVE description from NVD
        tech_name: Affected technology name (e.g., 'nginx')
        tech_version: Affected technology version (e.g., '1.18.0')
        asset_name: Host/asset name (e.g., 'example.com')
        port: Port number (int or None)
        is_https: Whether port is HTTPS (bool or int)
        tech_stack: List of (name, version) tuples for other techs on same service

    Returns:
        Tuple of (recommendation_text, error_message)
    """
    prompt = build_prompt(cve_id, cve_score, cve_description, tech_name, tech_version,
                          asset_name, port, is_https, tech_stack)
    try:
        text, model = generate_text(prompt)
    except AIError as e:
        return None, str(e)
    except Exception as e:
        print(f"AI generation error: {e}")
        return None, f"AI generation failed: {e}"

    return f"{format_ai_response(text)}\n\n_Generated by {model}_", None


if __name__ == '__main__':
    settings = get_ai_settings()
    print(f"Testing AskAI with provider={settings['provider']} model={settings['model'] or 'default'}")
    result, error = send_message(
        cve_id="CVE-2023-1234",
        cve_score=7.5,
        cve_description="A vulnerability in nginx allows remote attackers to cause a denial of service.",
        tech_name="nginx",
        tech_version="1.18.0",
        asset_name="test-server",
        port=443,
        is_https=True,
        tech_stack=[("Node.js", "18.0"), ("Express", "4.18")]
    )
    print(result[:500] if result else f"Error: {error}")
