#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ФИНАЛЬНАЯ СТАБИЛЬНАЯ ВЕРСИЯ – без ошибок, без мерцания, с мгновенным вводом

import sqlite3
import datetime
import os
import base64
import threading
import time
import curses
import queue
import subprocess
import atexit
import logging
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests

# ------------------ ПОЛНОЕ ПОДАВЛЕНИЕ БАННЕРА FLASK ------------------
os.environ['WERKZEUG_RUN_MAIN'] = 'true'
os.environ['FLASK_ENV'] = 'production'
os.environ['FLASK_RUN_FROM_CLI'] = 'false'
logging.getLogger('werkzeug').disabled = True
logging.getLogger('flask').disabled = True

# Заглушки для внутренних функций Flask
import flask.cli
flask.cli.show_server_banner = lambda *args, **kwargs: None

from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.log_request = lambda *args, **kwargs: None
WSGIRequestHandler.log_error = lambda *args, **kwargs: None

# ------------------ Настройки ------------------
SOCKS5_PROXY = 'socks5://127.0.0.1:9050'
TOR_PROXY = {'http': SOCKS5_PROXY, 'https': SOCKS5_PROXY}
FLASK_PORT = 8080
FLASK_HOST = '127.0.0.1'
POLL_INTERVAL = 2
ONLINE_CHECK_INTERVAL = 5
NOTIFICATION_DURATION = 3
HTTP_TIMEOUT = 3

# Пути для Tor
TORRC_PATH = os.path.expanduser('~/.tor/torrc')
HIDDEN_SERVICE_DIR = os.path.expanduser('~/.tor/hidden_service/')
HOSTNAME_FILE = os.path.join(HIDDEN_SERVICE_DIR, 'hostname')
TOR_LOG_FILE = os.path.expanduser('~/tor.log')

# ------------------ Глобальные переменные ------------------
tor_process = None
flask_ready = threading.Event()

# ------------------ Управление Tor ------------------
def start_tor():
    global tor_process
    try:
        subprocess.run(['pgrep', 'tor'], check=True, stdout=subprocess.DEVNULL)
        return
    except subprocess.CalledProcessError:
        pass

    os.makedirs(os.path.dirname(TORRC_PATH), exist_ok=True)
    if not os.path.exists(TORRC_PATH):
        with open(TORRC_PATH, 'w') as f:
            f.write(f"""# Автоматически сгенерированный torrc для чата
HiddenServiceDir {HIDDEN_SERVICE_DIR}
HiddenServicePort 80 127.0.0.1:{FLASK_PORT}
""")

    os.makedirs(HIDDEN_SERVICE_DIR, mode=0o700, exist_ok=True)

    try:
        tor_process = subprocess.Popen(
            ['tor', '-f', TORRC_PATH],
            stdout=open(TOR_LOG_FILE, 'a'),
            stderr=subprocess.STDOUT,
            start_new_session=True
        )
        for _ in range(30):
            if os.path.exists(HOSTNAME_FILE):
                break
            time.sleep(1)
        else:
            print("Не удалось получить onion-адрес. Проверьте Tor.")
            sys.exit(1)
    except Exception as e:
        print(f"Ошибка запуска Tor: {e}")
        sys.exit(1)

def stop_tor():
    global tor_process
    if tor_process:
        tor_process.terminate()
        tor_process.wait()

atexit.register(stop_tor)

# ------------------ Flask сервер ------------------
app = Flask(__name__)
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'chat.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY,
                private_key TEXT,
                public_key TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS servers (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE,
                public_key TEXT,
                last_seen TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inbound (
                id INTEGER PRIMARY KEY,
                sender_domain TEXT,
                encrypted_content TEXT,
                timestamp TIMESTAMP,
                read BOOLEAN DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS outbound (
                id INTEGER PRIMARY KEY,
                recipient_domain TEXT,
                plaintext TEXT,
                timestamp TIMESTAMP,
                delivered BOOLEAN DEFAULT 0,
                remote_msg_id INTEGER
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_servers_domain ON servers(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_inbound_timestamp ON inbound(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_outbound_timestamp ON outbound(timestamp)')
        db.commit()

        cursor.execute('SELECT * FROM keys')
        if cursor.fetchone() is None:
            generate_own_keys()

def generate_own_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    db = get_db()
    db.execute('INSERT INTO keys (private_key, public_key) VALUES (?, ?)',
               (private_pem, public_pem))
    db.commit()

def get_own_keys():
    db = get_db()
    row = db.execute('SELECT * FROM keys').fetchone()
    if row is None:
        generate_own_keys()
        row = db.execute('SELECT * FROM keys').fetchone()
    private_key = serialization.load_pem_private_key(
        row['private_key'].encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    public_key = serialization.load_pem_public_key(
        row['public_key'].encode('utf-8'),
        backend=default_backend()
    )
    return private_key, public_key, row['public_key']

def get_own_domain():
    if os.path.exists(HOSTNAME_FILE):
        with open(HOSTNAME_FILE, 'r') as f:
            return f.read().strip()
    return None

def tor_request(method, url, **kwargs):
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    session = requests.Session()
    session.proxies = TOR_PROXY
    return session.request(method, url, **kwargs)

def encrypt_for(public_key_pem, plaintext):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    ciphertext = public_key.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_with_own(private_key, ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

# ---------- ЭНДПОИНТЫ FLASK ----------
@app.route('/api/own_domain', methods=['GET'])
def api_own_domain():
    domain = get_own_domain()
    return jsonify({'domain': domain})

@app.route('/api/friend_domain', methods=['GET', 'POST'])
def api_friend_domain():
    if request.method == 'GET':
        db = get_db()
        row = db.execute('SELECT domain FROM servers LIMIT 1').fetchone()
        if row:
            return jsonify({'domain': row['domain']})
        return jsonify({'domain': None})

    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Domain required'}), 400

    db = get_db()
    db.execute('INSERT OR IGNORE INTO servers (domain, last_seen) VALUES (?, ?)',
               (domain, datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)))
    db.commit()

    own_domain = get_own_domain()
    if not own_domain:
        return jsonify({'error': 'Own domain not generated yet'}), 500

    _, _, own_public_pem = get_own_keys()

    try:
        url = f'http://{domain}/api/register_key'
        resp = tor_request('POST', url, json={
            'domain': own_domain,
            'public_key': own_public_pem
        }, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            friend_public_key = data.get('public_key')
            db.execute('UPDATE servers SET public_key=? WHERE domain=?',
                       (friend_public_key, domain))
            db.commit()
            return jsonify({'status': 'ok', 'friend_public_key': friend_public_key})
        else:
            return jsonify({'error': 'Friend registration failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/register_key', methods=['POST'])
def api_register_key():
    data = request.get_json()
    friend_domain = data.get('domain')
    friend_public_key = data.get('public_key')
    if not friend_domain or not friend_public_key:
        return jsonify({'error': 'Missing data'}), 400

    db = get_db()
    db.execute('INSERT OR REPLACE INTO servers (domain, public_key, last_seen) VALUES (?, ?, ?)',
               (friend_domain, friend_public_key, datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)))
    db.commit()

    _, _, own_public_pem = get_own_keys()
    return jsonify({'public_key': own_public_pem})

@app.route('/api/send_message', methods=['POST'])
def api_send_message():
    data = request.get_json()
    recipient = data.get('recipient')
    plaintext = data.get('plaintext')
    if not recipient or not plaintext:
        return jsonify({'error': 'Missing recipient or text'}), 400

    db = get_db()
    row = db.execute('SELECT public_key FROM servers WHERE domain=?', (recipient,)).fetchone()
    if not row or not row['public_key']:
        return jsonify({'error': 'Friend public key not found'}), 400

    friend_public_key_pem = row['public_key']
    encrypted = encrypt_for(friend_public_key_pem, plaintext)

    own_domain = get_own_domain()
    if not own_domain:
        return jsonify({'error': 'Own domain unknown'}), 500

    url = f'http://{recipient}/api/receive'
    try:
        resp = tor_request('POST', url, json={
            'sender': own_domain,
            'encrypted': encrypted,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
        }, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            remote_msg_id = data.get('message_id')
            cur = db.execute('''
                INSERT INTO outbound (recipient_domain, plaintext, timestamp, remote_msg_id)
                VALUES (?, ?, ?, ?)
            ''', (recipient, plaintext, datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None), remote_msg_id))
            db.commit()
            return jsonify({'status': 'ok', 'local_id': cur.lastrowid, 'remote_id': remote_msg_id})
        else:
            return jsonify({'error': 'Friend server error'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/receive', methods=['POST'])
def api_receive():
    data = request.get_json()
    sender = data.get('sender')
    encrypted = data.get('encrypted')
    timestamp = data.get('timestamp')
    if not sender or not encrypted or not timestamp:
        return jsonify({'error': 'Missing data'}), 400

    db = get_db()
    cur = db.execute('''
        INSERT INTO inbound (sender_domain, encrypted_content, timestamp)
        VALUES (?, ?, ?)
    ''', (sender, encrypted, timestamp))
    db.commit()
    message_id = cur.lastrowid
    return jsonify({'message_id': message_id})

@app.route('/api/poll', methods=['GET'])
def api_poll():
    last_id = request.args.get('last_id', 0, type=int)
    db = get_db()
    rows = db.execute('''
        SELECT * FROM inbound WHERE id > ? ORDER BY timestamp
    ''', (last_id,)).fetchall()
    messages = []
    private_key, _, _ = get_own_keys()
    for row in rows:
        try:
            plaintext = decrypt_with_own(private_key, row['encrypted_content'])
        except:
            plaintext = '[Ошибка расшифровки]'
        messages.append({
            'id': row['id'],
            'sender': row['sender_domain'],
            'content': plaintext,
            'timestamp': row['timestamp'],
            'read': row['read']
        })
    return jsonify(messages)

@app.route('/api/outbound_status/<int:msg_id>', methods=['GET'])
def api_outbound_status(msg_id):
    db = get_db()
    row = db.execute('SELECT * FROM outbound WHERE id=?', (msg_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404

    if row['delivered']:
        return jsonify({'delivered': True})

    recipient = row['recipient_domain']
    remote_id = row['remote_msg_id']
    if not remote_id:
        return jsonify({'delivered': False})

    try:
        url = f'http://{recipient}/api/message_status/{remote_id}'
        resp = tor_request('GET', url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            delivered = data.get('delivered', False)
            if delivered:
                db.execute('UPDATE outbound SET delivered=1 WHERE id=?', (msg_id,))
                db.commit()
            return jsonify({'delivered': delivered})
        else:
            return jsonify({'delivered': False})
    except:
        return jsonify({'delivered': False})

@app.route('/api/message_status/<int:msg_id>', methods=['GET'])
def api_message_status(msg_id):
    db = get_db()
    row = db.execute('SELECT read FROM inbound WHERE id=?', (msg_id,)).fetchone()
    if row:
        return jsonify({'delivered': bool(row['read'])})
    return jsonify({'delivered': False})

@app.route('/api/confirm_read', methods=['POST'])
def api_confirm_read():
    data = request.get_json()
    msg_id = data.get('message_id')
    friend_domain = data.get('friend_domain')
    if not msg_id or not friend_domain:
        return jsonify({'error': 'Missing data'}), 400

    db = get_db()
    db.execute('UPDATE inbound SET read=1 WHERE id=?', (msg_id,))
    db.commit()

    try:
        url = f'http://{friend_domain}/api/delivery_ack'
        tor_request('POST', url, json={'message_id': msg_id}, timeout=5)
    except:
        pass
    return jsonify({'status': 'ok'})

@app.route('/api/delivery_ack', methods=['POST'])
def api_delivery_ack():
    data = request.get_json()
    remote_msg_id = data.get('message_id')
    if not remote_msg_id:
        return jsonify({'error': 'Missing message_id'}), 400

    db = get_db()
    db.execute('UPDATE outbound SET delivered=1 WHERE remote_msg_id=?', (remote_msg_id,))
    db.commit()
    return jsonify({'status': 'ok'})

@app.route('/api/history', methods=['GET'])
def api_history():
    db = get_db()
    inbound = db.execute('''
        SELECT 'in' as direction, id, sender_domain as peer, encrypted_content,
               timestamp, read
        FROM inbound
    ''').fetchall()
    outbound = db.execute('''
        SELECT 'out' as direction, id, recipient_domain as peer, plaintext,
               timestamp, delivered
        FROM outbound
    ''').fetchall()

    private_key, _, _ = get_own_keys()
    messages = []
    for row in inbound:
        try:
            content = decrypt_with_own(private_key, row['encrypted_content'])
        except:
            content = '[Ошибка расшифровки]'
        messages.append({
            'direction': 'in',
            'id': row['id'],
            'peer': row['peer'],
            'content': content,
            'timestamp': row['timestamp'],
            'delivered': bool(row['read'])
        })
    for row in outbound:
        messages.append({
            'direction': 'out',
            'id': row['id'],
            'peer': row['peer'],
            'content': row['plaintext'],
            'timestamp': row['timestamp'],
            'delivered': bool(row['delivered'])
        })
    messages.sort(key=lambda x: x['timestamp'])
    return jsonify(messages)

@app.route('/api/check_online', methods=['POST'])
def api_check_online():
    data = request.get_json()
    domain = data.get('domain')
    if not domain:
        return jsonify({'online': False})
    try:
        url = f'http://{domain}/api/ping'
        resp = tor_request('GET', url, timeout=5)
        return jsonify({'online': resp.status_code == 200})
    except:
        return jsonify({'online': False})

@app.route('/api/ping', methods=['GET'])
def api_ping():
    return 'pong'

# ------------------ КЛИЕНТ CURSES ------------------
class ChatClient:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.message_queue = queue.Queue()
        self.action_queue = queue.Queue()
        self.running = True
        self.friend_domain = None
        self.friend_online = False
        self.own_domain = None
        self.messages = []
        self.input_buffer = ""
        self.last_poll_id = 0
        self.notification = {"text": "", "color": 0, "end_time": 0}
        self.needs_redraw = True

        curses.start_color()
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)
        self.color_green = curses.color_pair(1)
        self.color_yellow = curses.color_pair(2)
        self.color_red = curses.color_pair(3)
        self.color_cyan = curses.color_pair(4)

        curses.curs_set(1)
        curses.mousemask(0)
        curses.use_default_colors()
        curses.cbreak()
        curses.noecho()
        self.stdscr.keypad(True)
        self.stdscr.nodelay(True)  # неблокирующий ввод

        if not flask_ready.wait(5):  # ждём запуска Flask до 5 сек
            self.show_notification("Сервер не запущен!", self.color_red)

        self.load_initial_data()
        self.start_poll_thread()
        self.start_online_check_thread()
        self.start_action_thread()

    def load_initial_data(self):
        for attempt in range(5):
            try:
                resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/own_domain', timeout=2)
                if resp.status_code == 200:
                    self.own_domain = resp.json().get('domain')
                    if self.own_domain:
                        break
            except:
                pass
            time.sleep(1)
        else:
            self.own_domain = get_own_domain()

        try:
            resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/friend_domain', timeout=2)
            if resp.status_code == 200:
                self.friend_domain = resp.json().get('domain')
        except:
            self.friend_domain = None

        self.load_history()

    def load_history(self):
        try:
            resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/history', timeout=3)
            if resp.status_code == 200:
                self.messages = resp.json()
                for msg in self.messages:
                    if msg.get('direction') == 'in' and msg.get('id', 0) > self.last_poll_id:
                        self.last_poll_id = msg['id']
        except:
            pass

    def start_poll_thread(self):
        def poll():
            while self.running:
                if self.friend_domain:
                    try:
                        resp = requests.get(
                            f'http://{FLASK_HOST}:{FLASK_PORT}/api/poll?last_id={self.last_poll_id}',
                            timeout=HTTP_TIMEOUT
                        )
                        if resp.status_code == 200:
                            new_msgs = resp.json()
                            for msg in new_msgs:
                                self.message_queue.put(('incoming', msg))
                                threading.Thread(target=self._confirm_read, args=(msg,), daemon=True).start()
                                if msg['id'] > self.last_poll_id:
                                    self.last_poll_id = msg['id']
                    except:
                        pass
                time.sleep(POLL_INTERVAL)
        threading.Thread(target=poll, daemon=True).start()

    def _confirm_read(self, msg):
        try:
            requests.post(
                f'http://{FLASK_HOST}:{FLASK_PORT}/api/confirm_read',
                json={'message_id': msg['id'], 'friend_domain': self.friend_domain},
                timeout=HTTP_TIMEOUT
            )
        except:
            pass

    def start_online_check_thread(self):
        def check():
            while self.running:
                if self.friend_domain:
                    try:
                        resp = requests.post(
                            f'http://{FLASK_HOST}:{FLASK_PORT}/api/check_online',
                            json={'domain': self.friend_domain},
                            timeout=HTTP_TIMEOUT
                        )
                        if resp.status_code == 200:
                            online = resp.json().get('online', False)
                            if online != self.friend_online:
                                self.friend_online = online
                                if online:
                                    self.show_notification("Собеседник в онлайне!", self.color_green)
                                else:
                                    self.show_notification("Собеседник в офлайне!", self.color_yellow)
                    except:
                        pass
                time.sleep(ONLINE_CHECK_INTERVAL)
        threading.Thread(target=check, daemon=True).start()

    def start_action_thread(self):
        def worker():
            while self.running:
                try:
                    action, data = self.action_queue.get(timeout=0.5)
                    if action == 'add_friend':
                        self._add_friend_async(data)
                    elif action == 'send_message':
                        self._send_message_async(data)
                except queue.Empty:
                    continue
        threading.Thread(target=worker, daemon=True).start()

    def _add_friend_async(self, domain):
        self.show_notification("Подключение...", self.color_yellow)
        try:
            resp = requests.post(
                f'http://{FLASK_HOST}:{FLASK_PORT}/api/friend_domain',
                json={'domain': domain},
                timeout=HTTP_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'ok':
                    self.friend_domain = domain
                    self.show_notification("Домен добавлен!", self.color_green)
                    self.load_history()
                else:
                    self.show_notification(f"Ошибка: {data.get('error')}", self.color_red)
            else:
                self.show_notification("Не удалось добавить друга", self.color_red)
        except Exception as e:
            self.show_notification(f"Ошибка: {str(e)}", self.color_red)

    def _send_message_async(self, text):
        self.show_notification("Отправка...", self.color_yellow)
        try:
            resp = requests.post(
                f'http://{FLASK_HOST}:{FLASK_PORT}/api/send_message',
                json={'recipient': self.friend_domain, 'plaintext': text},
                timeout=HTTP_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                local_id = data['local_id']
                new_msg = {
                    'direction': 'out',
                    'id': local_id,
                    'peer': self.friend_domain,
                    'content': text,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
                    'delivered': False
                }
                self.messages.append(new_msg)
                self.show_notification("Сообщение отправлено!", self.color_green)
            else:
                self.show_notification("Ошибка отправки", self.color_red)
        except Exception as e:
            self.show_notification(f"Ошибка: {str(e)}", self.color_red)

    def show_notification(self, text, color, duration=NOTIFICATION_DURATION):
        self.notification = {
            "text": text,
            "color": color,
            "end_time": time.time() + duration
        }
        self.needs_redraw = True

    def truncate_domain(self, domain, max_len):
        if len(domain) <= max_len:
            return domain
        half = (max_len - 3) // 2
        return domain[:half] + "..." + domain[-half:]

    def draw(self):
        self.height, self.width = self.stdscr.getmaxyx()
        self.stdscr.erase()

        # Заголовок
        header = "• Чат"
        if self.friend_domain:
            max_domain_len = self.width - len(header) - 3
            if max_domain_len > 10:
                short_domain = self.truncate_domain(self.friend_domain, max_domain_len)
                header += f" • {short_domain}"
                if self.friend_online:
                    header += " • (в сети)"
        try:
            self.stdscr.addstr(0, 0, header[:self.width-1], self.color_cyan)
            self.stdscr.addstr(1, 0, "─" * (self.width-1), self.color_cyan)
        except curses.error:
            pass

        # Сообщения
        chat_height = self.height - 5
        start_y = 2
        display_messages = self.messages[-chat_height:] if len(self.messages) > chat_height else self.messages
        y = start_y
        for msg in display_messages:
            if y >= self.height - 3:
                break
            prefix = "● " if msg['direction'] == 'out' else "○ "
            try:
                dt = datetime.datetime.fromisoformat(msg['timestamp'])
                time_str = dt.strftime('%H:%M')
            except:
                time_str = "??:??"
            line = f"{prefix}{time_str} {msg['content']}"
            if msg['direction'] == 'out' and not msg.get('delivered', True):
                line += " . . ."
            if len(line) > self.width-1:
                line = line[:self.width-4] + "..."
            try:
                self.stdscr.addstr(y, 0, line)
            except curses.error:
                pass
            y += 1

        # Нижняя линия
        try:
            self.stdscr.addstr(self.height-3, 0, "─" * (self.width-1), self.color_cyan)
        except curses.error:
            pass

        # Уведомление
        if self.notification and time.time() < self.notification["end_time"]:
            notif_text = self.notification["text"]
            if len(notif_text) > self.width-1:
                notif_text = notif_text[:self.width-4] + "..."
            try:
                self.stdscr.addstr(self.height-2, 0, notif_text, self.notification["color"])
            except curses.error:
                pass
        else:
            self.notification = {"text": "", "color": 0, "end_time": 0}

        # Поле ввода
        prompt = "> "
        try:
            self.stdscr.addstr(self.height-1, 0, prompt)
            self.stdscr.addstr(self.height-1, len(prompt), self.input_buffer)
            self.stdscr.clrtoeol()
            self.stdscr.move(self.height-1, len(prompt) + len(self.input_buffer))
        except curses.error:
            pass

        self.stdscr.refresh()
        self.needs_redraw = False

    def handle_input(self, key):
        if key == 10:  # Enter
            cmd = self.input_buffer.strip()
            self.input_buffer = ""
            if cmd == "":
                return
            if cmd.startswith('/'):
                self.handle_command(cmd)
            elif not self.friend_domain:
                self.action_queue.put(('add_friend', cmd))
            else:
                self.action_queue.put(('send_message', cmd))
            self.needs_redraw = True
        elif key in (27, ord('c'), ord('x'), 3):  # ESC, c, x, Ctrl+C
            self.running = False
        elif key == curses.KEY_BACKSPACE or key == 127:
            self.input_buffer = self.input_buffer[:-1]
            self.needs_redraw = True
        elif key == curses.KEY_RESIZE:
            self.height, self.width = self.stdscr.getmaxyx()
            curses.resizeterm(self.height, self.width)
            self.needs_redraw = True
        elif 32 <= key < 127:
            self.input_buffer += chr(key)
            self.needs_redraw = True

    def handle_command(self, cmd):
        if cmd == '/onion':
            try:
                resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/own_domain', timeout=2)
                if resp.status_code == 200:
                    self.own_domain = resp.json().get('domain')
            except:
                pass
            if self.own_domain:
                temp_msg = {
                    'direction': 'out',
                    'id': -1,
                    'peer': '',
                    'content': f"Ваш домен: {self.own_domain}",
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
                    'delivered': True
                }
                self.messages.append(temp_msg)
                self.show_notification("Домен показан", self.color_green)
            else:
                self.show_notification("Домен ещё не сгенерирован", self.color_red)
        else:
            self.show_notification(f"Неизвестная команда: {cmd}", self.color_red)

    def process_queue(self):
        changed = False
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                if msg_type == 'incoming':
                    self.messages.append({
                        'direction': 'in',
                        'id': data['id'],
                        'peer': data['sender'],
                        'content': data['content'],
                        'timestamp': data['timestamp'],
                        'delivered': True
                    })
                    self.show_notification("Новое сообщение", self.color_green)
                    changed = True
        except queue.Empty:
            pass
        if changed:
            self.needs_redraw = True

    def run(self):
        while self.running:
            self.process_queue()
            if self.needs_redraw:
                self.draw()
            key = self.stdscr.getch()
            if key != -1:
                self.handle_input(key)
            else:
                curses.napms(20)

# ------------------ ЗАПУСК FLASK ------------------
def run_flask():
    init_db()
    flask_ready.set()
    # Подавление ошибки WERKZEUG_SERVER_FD
    os.environ.pop('WERKZEUG_SERVER_FD', None)
    os.environ['WERKZEUG_SERVER_FD'] = ''
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)

def main(stdscr):
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    client = ChatClient(stdscr)
    try:
        client.run()
    except KeyboardInterrupt:
        pass
    finally:
        client.running = False

if __name__ == '__main__':
    start_tor()
    time.sleep(1)  # даём Tor время на генерацию адреса
    curses.wrapper(main)