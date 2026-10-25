"""
Screenshots and the README GIF, taken from the fictional demo data.

    python scripts/demo_capture.py          # writes docs/images/

Seeds a fresh demo (scripts/demo_seed.py), serves it on 127.0.0.1 without a
background worker, signs in with a session cookie and captures the pages
with Playwright. Nothing is scanned; the only network access is the page
styling from its CDNs (Tailwind, Font Awesome, Google Fonts).
"""

import argparse
import datetime
import io
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import demo_seed  # noqa: E402

OUT_DIR = os.path.join(demo_seed.ROOT, 'docs', 'images')
VIEWPORT = {'width': 1440, 'height': 900}
GIF_WIDTH = 960


def start_server():
    """Serve the demo app on 127.0.0.1 in a background thread."""
    import main as app_main
    from werkzeug.serving import make_server
    server = make_server('127.0.0.1', demo_seed.DEMO_PORT, app_main.app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return app_main, server


def session_cookie(app_main) -> dict:
    import jwt
    from utils import auth
    demo_seed.create_demo_account()
    admin = auth.get_admin()
    token = jwt.encode({'user': admin['username'], 'type': 'access', 'pv': admin['token_version'],
                        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)},
                       app_main.JWT_SECRET, algorithm='HS256')
    return {'name': 'access_token', 'value': token, 'domain': '127.0.0.1', 'path': '/'}


def asset_url(host: str) -> str:
    from utils.db_utils import get_db_connection
    conn = get_db_connection()
    try:
        row = conn.execute('SELECT sub_id FROM subdomain_asset WHERE subdomain_name = ?', (host,)).fetchone()
    finally:
        conn.close()
    return f'/assets/subdomain/{row[0]}'


def save_jpeg(png: bytes, path: str, width: int = None, quality: int = 82):
    from PIL import Image
    image = Image.open(io.BytesIO(png)).convert('RGB')
    if width and image.width != width:
        image = image.resize((width, round(image.height * width / image.width)), Image.LANCZOS)
    image.save(path, 'JPEG', quality=quality, optimize=True, progressive=True)


def make_gif(frames, path: str):
    """frames: [(png bytes, milliseconds)] -> one GIF with a shared palette."""
    from PIL import Image
    images = []
    for png, _ in frames:
        image = Image.open(io.BytesIO(png)).convert('RGB')
        images.append(image.resize((GIF_WIDTH, round(image.height * GIF_WIDTH / image.width)), Image.LANCZOS))
    palette = images[0].quantize(colors=255, method=Image.MEDIANCUT)
    converted = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in images]
    converted[0].save(path, save_all=True, append_images=converted[1:], duration=[ms for _, ms in frames],
                      loop=0, optimize=True, disposal=1)


def main():
    parser = argparse.ArgumentParser(description='Screenshots and GIF from the LazyEASM demo data')
    parser.add_argument('--out', default=OUT_DIR)
    args = parser.parse_args()

    demo_seed.use_demo_paths()
    demo_seed.seed()
    demo_seed.keep_heartbeat()
    app_main, server = start_server()
    cookie = session_cookie(app_main)
    os.makedirs(args.out, exist_ok=True)
    base = f'http://127.0.0.1:{demo_seed.DEMO_PORT}'
    asset = asset_url('legacy.example.org')

    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport=VIEWPORT, color_scheme='light', locale='en-US', timezone_id='UTC')
        context.add_cookies([cookie])
        page = context.new_page()

        def visit(path: str):
            page.goto(base + path, wait_until='networkidle')
            page.wait_for_timeout(600)          # Tailwind (CDN) styles the page after load

        def shot() -> bytes:
            return page.screenshot(type='png')

        pages = [('overview', '/'), ('assets', '/assets?sort=kev_count:desc'), ('asset-detail', asset),
                 ('findings', '/findings'), ('changes', '/changes'), ('settings', '/settings#schedule')]
        for name, path in pages:
            visit(path)
            save_jpeg(shot(), os.path.join(args.out, f'{name}.jpg'))
            print(f'docs/images/{name}.jpg')

        # GIF: Overview -> Findings -> an asset page
        frames = []

        def hold(ms):
            frames.append((shot(), ms))

        def scroll(pixels, steps=4, ms=140):
            for _ in range(steps):
                page.mouse.wheel(0, pixels / steps)
                page.wait_for_timeout(120)
                frames.append((shot(), ms))

        visit('/')
        hold(3200)
        scroll(500)
        hold(2200)
        visit('/findings')
        hold(3200)
        scroll(450)
        hold(2000)
        visit(asset)
        hold(3200)
        scroll(500)
        hold(2600)
        gif_path = os.path.join(args.out, 'demo.gif')
        make_gif(frames, gif_path)
        total = sum(ms for _, ms in frames) / 1000
        print(f'docs/images/demo.gif: {len(frames)} frames, {total:.1f} s, '
              f'{os.path.getsize(gif_path) / 1048576:.1f} MB')

        # Social preview (1280x640) from the Overview
        visit('/')
        from PIL import Image
        overview = Image.open(io.BytesIO(page.screenshot(type='png', clip={'x': 0, 'y': 0, 'width': 1440,
                                                                             'height': 720}))).convert('RGB')
        overview.resize((1280, 640), Image.LANCZOS).save(os.path.join(args.out, 'social-preview.png'),
                                                        optimize=True)
        print('docs/images/social-preview.png')
        browser.close()
    server.shutdown()


if __name__ == '__main__':
    main()
