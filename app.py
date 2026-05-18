import ipaddress
import os
import csv
import json
import threading
import time
import io
import re
import secrets
import uuid
import webbrowser
import zipfile
from pathlib import Path
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor

import requests
from flask import Flask, render_template, request, Response, jsonify, abort, session
from bs4 import BeautifulSoup

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# ------------------------------------------------------------------ #
#  環境変数から設定を読み込む                                          #
# ------------------------------------------------------------------ #

app.secret_key        = os.environ.get('SECRET_KEY',    secrets.token_hex(32))
CSRF_TOKEN_VALUE      = os.environ.get('CSRF_SECRET',   secrets.token_hex(32))
BASIC_AUTH_USER       = os.environ.get('BASIC_AUTH_USER', 'admin')
BASIC_AUTH_PASS       = os.environ.get('BASIC_AUTH_PASS', '')  # 空 = ローカル開発（認証スキップ）
IS_LOCAL              = not bool(BASIC_AUTH_PASS)              # ローカル実行かどうか

_default_download_dir = Path(os.environ.get('DOWNLOAD_DIR', 'downloads')).resolve()
_default_download_dir.mkdir(exist_ok=True)

# ランタイムで変更可能な保存先（ローカルモード専用）
_download_dir       = _default_download_dir
_download_dir_lock  = threading.Lock()


def get_download_dir() -> Path:
    with _download_dir_lock:
        return _download_dir


def set_download_dir(new_path: Path) -> None:
    global _download_dir
    with _download_dir_lock:
        _download_dir = new_path

TIMEOUT              = 10
MAX_RETRIES          = 3
MAX_CONCURRENT       = 3
MAX_FILE_BYTES       = 50 * 1024 * 1024
MAX_URLS_PER_SESSION = 5000
SESSION_TTL          = 3600  # 1時間でセッション削除

ALLOWED_CONTENT_TYPES = {
    'image/jpeg', 'image/png', 'image/gif', 'image/webp',
    'image/svg+xml', 'image/bmp', 'image/tiff', 'image/avif',
}

DANGEROUS_MAGIC = [
    (b'MZ',               2, 'Windows PE実行ファイル (.exe/.dll)'),
    (b'\x7fELF',          4, 'Linux ELF実行ファイル'),
    (b'PK\x03\x04',       4, 'ZIPアーカイブ'),
    (b'PK\x05\x06',       4, 'ZIPアーカイブ（空）'),
    (b'\xca\xfe\xba\xbe', 4, 'Javaクラスファイル'),
    (b'\xce\xfa\xed\xfe', 4, 'macOS Mach-O実行ファイル'),
    (b'\xcf\xfa\xed\xfe', 4, 'macOS Mach-O実行ファイル(64bit)'),
    (b'%PDF',             4, 'PDFファイル'),
    (b'#!/',              3, 'シェルスクリプト'),
    (b'#!',               2, 'スクリプトファイル'),
]

_BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

# ------------------------------------------------------------------ #
#  セッション別状態管理                                                #
# ------------------------------------------------------------------ #

all_states: dict = {}
all_states_lock = threading.Lock()


def get_or_create_state(sid: str) -> dict:
    with all_states_lock:
        if sid not in all_states:
            all_states[sid] = {
                'items': {}, 'order': [], 'events': [],
                'running': False, 'last_active': time.time(),
            }
        else:
            all_states[sid]['last_active'] = time.time()
        return all_states[sid]


def _cleanup_loop():
    while True:
        time.sleep(1800)
        cutoff = time.time() - SESSION_TTL
        with all_states_lock:
            stale = [k for k, v in all_states.items() if v.get('last_active', 0) < cutoff]
            for k in stale:
                del all_states[k]


threading.Thread(target=_cleanup_loop, daemon=True).start()


def get_sid() -> str:
    if 'sid' not in session:
        session['sid'] = str(uuid.uuid4())
    return session['sid']


# ------------------------------------------------------------------ #
#  セキュリティ: Basic 認証 / CSRF / Origin チェック                  #
# ------------------------------------------------------------------ #

@app.before_request
def check_basic_auth():
    if not BASIC_AUTH_PASS:
        return
    auth = request.authorization
    if not auth:
        return Response('認証が必要です', 401,
                        {'WWW-Authenticate': 'Basic realm="Image Downloader"',
                         'Cache-Control': 'no-cache'})
    user_ok = secrets.compare_digest(auth.username.encode(), BASIC_AUTH_USER.encode())
    pass_ok = secrets.compare_digest(auth.password.encode(), BASIC_AUTH_PASS.encode())
    if not (user_ok and pass_ok):
        return Response('ユーザー名またはパスワードが違います', 401,
                        {'WWW-Authenticate': 'Basic realm="Image Downloader"',
                         'Cache-Control': 'no-cache'})


@app.before_request
def check_request_security():
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return

    origin = request.headers.get('Origin', '')
    if origin:
        host = request.host
        allowed = {
            f'https://{host}', f'http://{host}',
            'http://localhost:5000', 'http://127.0.0.1:5000',
        }
        if origin not in allowed:
            abort(403, description=f'不正なOriginです: {origin}')

    token = request.headers.get('X-CSRF-Token', '')
    if not secrets.compare_digest(token, CSRF_TOKEN_VALUE):
        abort(403, description='CSRFトークンが無効です')


# ------------------------------------------------------------------ #
#  セキュリティ: マジックバイト検証                                    #
# ------------------------------------------------------------------ #

def check_dangerous_magic(filepath: Path) -> str | None:
    try:
        header = filepath.read_bytes()[:16]
    except Exception:
        return None
    for magic, length, desc in DANGEROUS_MAGIC:
        if header[:length] == magic:
            return desc
    return None


# ------------------------------------------------------------------ #
#  セキュリティ: URL バリデーション                                    #
# ------------------------------------------------------------------ #

def validate_url(url: str) -> str | None:
    try:
        parsed = urlparse(url)
    except Exception:
        return '不正なURL形式'
    if parsed.scheme not in ('http', 'https'):
        return f'スキーム "{parsed.scheme}" は許可されていません'
    hostname = parsed.hostname
    if not hostname:
        return 'ホスト名がありません'
    try:
        addr = ipaddress.ip_address(hostname)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return f'プライベートIP ({hostname}) へのアクセスは禁止'
    except ValueError:
        lower = hostname.lower()
        if lower == 'localhost' or lower.endswith('.local') or lower.endswith('.internal'):
            return f'内部ホスト名 "{hostname}" へのアクセスは禁止'
    return None


# ------------------------------------------------------------------ #
#  ファイル名生成                                                      #
# ------------------------------------------------------------------ #

def get_safe_filename(url: str, index: int) -> str:
    try:
        parsed = urlparse(url)
        path = unquote(parsed.path)
        basename = os.path.basename(path)
        name, ext = os.path.splitext(basename)
        ext = re.sub(r'[^a-zA-Z0-9]', '', ext)[:6]
        if not ext:
            ext = 'jpg'
        ext = '.' + ext.lower()
        name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)[:50] or 'image'
        filename = f'{index:04d}_{name}{ext}'
    except Exception:
        filename = f'{index:04d}_image.jpg'
    dl_dir = get_download_dir()
    candidate = (dl_dir / filename).resolve()
    if not str(candidate).startswith(str(dl_dir)):
        filename = f'{index:04d}_image.jpg'
    return filename


# ------------------------------------------------------------------ #
#  ダウンロード処理（セッション別）                                    #
# ------------------------------------------------------------------ #

def add_event(sid: str, event_data: dict):
    with all_states_lock:
        if sid in all_states:
            all_states[sid]['events'].append(event_data)


def download_one(sid: str, url: str, filename: str, index: int):
    filepath = get_download_dir() / filename
    last_error = ''

    for attempt in range(1, MAX_RETRIES + 1):
        with all_states_lock:
            if sid in all_states:
                all_states[sid]['items'][url].update({'status': 'downloading', 'attempts': attempt})
        add_event(sid, {'type': 'update', 'url': url, 'status': 'downloading',
                        'attempt': attempt, 'index': index})
        try:
            s = requests.Session()
            s.max_redirects = 5
            response = s.get(
                url, timeout=TIMEOUT, stream=True, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            )
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
            if content_type and content_type not in ALLOWED_CONTENT_TYPES:
                raise ValueError(f'画像以外のコンテンツ ({content_type})')

            total = 0
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        total += len(chunk)
                        if total > MAX_FILE_BYTES:
                            raise ValueError(f'ファイルサイズ上限超過 ({MAX_FILE_BYTES // 1024 // 1024}MB)')
                        f.write(chunk)

            danger = check_dangerous_magic(filepath)
            if danger:
                filepath.unlink(missing_ok=True)
                raise ValueError(f'危険なファイル形式を検出: {danger}')

            with all_states_lock:
                if sid in all_states:
                    all_states[sid]['items'][url].update({'status': 'success', 'filename': filename})
            add_event(sid, {'type': 'update', 'url': url, 'status': 'success',
                            'filename': filename, 'index': index})
            return

        except requests.exceptions.Timeout:
            last_error = f'タイムアウト ({TIMEOUT}秒超過)'
        except requests.exceptions.TooManyRedirects:
            last_error = 'リダイレクト上限超過'
        except requests.exceptions.HTTPError as e:
            last_error = f'HTTP エラー {e.response.status_code}'
        except requests.exceptions.ConnectionError:
            last_error = '接続エラー'
        except ValueError as e:
            last_error = str(e)
            break
        except Exception as e:
            last_error = str(e)[:80]

        if filepath.exists():
            filepath.unlink(missing_ok=True)

        if attempt < MAX_RETRIES:
            add_event(sid, {'type': 'update', 'url': url, 'status': 'retry',
                            'attempt': attempt, 'error': last_error, 'index': index})
            time.sleep(2)

    with all_states_lock:
        if sid in all_states:
            all_states[sid]['items'][url].update({'status': 'failed', 'error': last_error})
    add_event(sid, {'type': 'update', 'url': url, 'status': 'failed',
                    'error': last_error, 'index': index})


def run_downloads(sid: str):
    state = get_or_create_state(sid)
    urls = state['order']

    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = [
            executor.submit(download_one, sid, url, get_safe_filename(url, i), i)
            for i, url in enumerate(urls)
        ]
        for f in futures:
            f.result()

    with all_states_lock:
        if sid in all_states:
            all_states[sid]['running'] = False

    success = sum(1 for v in state['items'].values() if v['status'] == 'success')
    failed  = sum(1 for v in state['items'].values() if v['status'] == 'failed')
    add_event(sid, {'type': 'complete', 'total': len(urls), 'success': success, 'failed': failed})


# ------------------------------------------------------------------ #
#  Flask ルート                                                        #
# ------------------------------------------------------------------ #

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


@app.route('/')
def index():
    sid = get_sid()
    return render_template('index.html',
                           csrf_token=CSRF_TOKEN_VALUE,
                           session_id=sid,
                           is_local=IS_LOCAL,
                           download_dir=str(get_download_dir()))


@app.route('/download_dir', methods=['GET'])
def get_download_dir_route():
    return jsonify({'path': str(get_download_dir())})


@app.route('/download_dir', methods=['POST'])
def set_download_dir_route():
    if not IS_LOCAL:
        abort(403, description='保存先の変更はローカル実行時のみ可能です')

    path_str = request.json.get('path', '').strip()
    if not path_str:
        return jsonify({'error': 'パスを入力してください'}), 400

    try:
        new_path = Path(path_str).resolve()

        # 絶対パスであることを確認
        if not new_path.is_absolute():
            return jsonify({'error': '絶対パスで指定してください'}), 400

        # ディレクトリ作成（存在しない場合）
        new_path.mkdir(parents=True, exist_ok=True)

        set_download_dir(new_path)
        return jsonify({'path': str(new_path)})
    except PermissionError:
        return jsonify({'error': 'アクセス権限がありません'}), 400
    except Exception as e:
        return jsonify({'error': f'無効なパスです: {str(e)}'}), 400


@app.route('/parse_csv', methods=['POST'])
def parse_csv():
    content = request.json.get('content', '').strip()
    if not content:
        return jsonify({'error': 'CSVが空です'}), 400
    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        if len(rows) < 2:
            return jsonify({'error': 'ヘッダー行とデータ行が必要です'}), 400
        headers = rows[0]
        sample_rows = rows[1:6]
        html_columns = []
        for i in range(len(headers)):
            for row in rows[1:min(10, len(rows))]:
                if i < len(row) and '<img' in row[i].lower():
                    html_columns.append(i)
                    break
        return jsonify({
            'headers': headers,
            'sample': [[row[i] if i < len(row) else '' for i in range(len(headers))] for row in sample_rows],
            'html_columns': html_columns,
            'total_rows': len(rows) - 1,
        })
    except Exception as e:
        return jsonify({'error': f'CSV解析エラー: {str(e)}'}), 400


@app.route('/extract_urls', methods=['POST'])
def extract_urls():
    data = request.json
    content = data.get('content', '').strip()
    col_indices = data.get('columns')
    if col_indices is None:
        col_indices = [int(data.get('column', 0))]
    else:
        col_indices = [int(c) for c in col_indices]
    if not content:
        return jsonify({'error': 'CSVが空です'}), 400
    try:
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        all_urls, blocked = [], []
        for row in rows[1:]:
            for col_index in col_indices:
                if col_index < len(row):
                    soup = BeautifulSoup(row[col_index], 'html.parser')
                    for img in soup.find_all('img'):
                        src = img.get('src', '').strip()
                        if not src:
                            continue
                        reason = validate_url(src)
                        if reason:
                            blocked.append({'url': src, 'reason': reason})
                        else:
                            all_urls.append(src)
        seen, unique_urls = set(), []
        for url in all_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        return jsonify({
            'urls': unique_urls, 'total': len(unique_urls),
            'duplicates': len(all_urls) - len(unique_urls),
            'blocked': blocked[:50], 'blocked_count': len(blocked),
        })
    except Exception as e:
        return jsonify({'error': f'URL抽出エラー: {str(e)}'}), 400


@app.route('/start_download', methods=['POST'])
def start_download():
    sid = get_sid()
    state = get_or_create_state(sid)

    if state['running']:
        return jsonify({'error': 'ダウンロード中です。完了後に再試行してください。'}), 400

    urls = request.json.get('urls', [])
    if not urls:
        return jsonify({'error': 'URLがありません'}), 400
    if len(urls) > MAX_URLS_PER_SESSION:
        return jsonify({'error': f'上限は {MAX_URLS_PER_SESSION} 件です'}), 400

    invalid = [u for u in urls if validate_url(u) is not None]
    if invalid:
        return jsonify({'error': f'{len(invalid)} 件の不正なURLが含まれています',
                        'examples': invalid[:5]}), 400

    with all_states_lock:
        all_states[sid] = {
            'items': {url: {'status': 'pending', 'filename': None, 'error': None, 'attempts': 0}
                      for url in urls},
            'order': urls,
            'events': [{'type': 'start', 'total': len(urls)}],
            'running': True,
            'last_active': time.time(),
        }

    threading.Thread(target=run_downloads, args=(sid,), daemon=True).start()
    return jsonify({'status': 'started', 'total': len(urls)})


@app.route('/events')
def events_stream():
    sid = request.args.get('sid', '')
    if not sid:
        return Response('sid parameter required', 400)

    def generate():
        sent_index = 0
        done = False
        while not done:
            with all_states_lock:
                s = all_states.get(sid)
                if s is None:
                    yield f'data: {json.dumps({"type": "complete"}, ensure_ascii=False)}\n\n'
                    break
                new_events = s['events'][sent_index:]
                sent_index_new = len(s['events'])
                running = s['running']
            for event in new_events:
                yield f'data: {json.dumps(event, ensure_ascii=False)}\n\n'
                if event.get('type') == 'complete':
                    done = True
                    break
            sent_index = sent_index_new
            if not done:
                with all_states_lock:
                    ev_len = len(all_states.get(sid, {}).get('events', []))
                if not running and sent_index >= ev_len:
                    yield f'data: {json.dumps({"type": "complete"}, ensure_ascii=False)}\n\n'
                    done = True
                else:
                    time.sleep(0.15)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache',
                             'X-Accel-Buffering': 'no',
                             'Connection': 'keep-alive'})


@app.route('/download_zip')
def download_zip():
    sid = get_sid()
    state = get_or_create_state(sid)

    dl_dir = get_download_dir()
    success_items = [
        (url, item['filename'])
        for url, item in state['items'].items()
        if item['status'] == 'success' and item.get('filename')
    ]

    if not success_items:
        return jsonify({'error': '完了したファイルがありません'}), 400

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for _url, filename in success_items:
            filepath = dl_dir / filename
            if filepath.exists():
                zf.write(filepath, filename)
    zip_buffer.seek(0)

    return Response(
        zip_buffer.getvalue(),
        mimetype='application/zip',
        headers={'Content-Disposition': 'attachment; filename=images.zip'},
    )


@app.route('/export_failed')
def export_failed():
    sid = get_sid()
    state = get_or_create_state(sid)
    failed = [(url, item.get('error', ''), item.get('attempts', 0))
              for url, item in state['items'].items()
              if item['status'] == 'failed']
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['url', 'error', 'attempts'])
    safe_rows = [
        [("'" + url if url.startswith(('=', '+', '-', '@')) else url), error, attempts]
        for url, error, attempts in failed
    ]
    writer.writerows(safe_rows)
    return Response(output.getvalue(), mimetype='text/csv; charset=utf-8-sig',
                    headers={'Content-Disposition': 'attachment; filename=failed_downloads.csv'})


if __name__ == '__main__':
    print('=' * 50)
    print('画像ダウンロードツール 起動中...')
    print(f'画像保存先: {get_download_dir()}')
    if not BASIC_AUTH_PASS:
        print('認証: 無効（ローカルモード）')
    else:
        print(f'認証: 有効（ユーザー: {BASIC_AUTH_USER}）')
    print('http://localhost:5000 を開いてください')
    print('停止: Ctrl+C')
    print('=' * 50)
    threading.Timer(1.0, lambda: webbrowser.open('http://localhost:5000')).start()
    app.run(debug=False, threaded=True, host='127.0.0.1', port=5000)
