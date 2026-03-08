#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ПРОСТОЙ И СТАБИЛЬНЫЙ ЧАТ – без лишних сообщений, с надёжным вводом

import sqlite3
import datetime
import os
import base64
import threading
import time
import curses
import queue
import subprocess
import sys
import atexit
import signal
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives import hashes
from cryptography.hmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests

# ------------------ Настройки ------------------
SOCKS5_PROXY = 'socks5://127.0.0.1:9050'
TOR_PROXY = {'http': SOCKS5_PROXY, 'https': SOCKS5_PROXY}
FLASK_PORT = 8080
FLASK_HOST = '127.0.0.1'
POLL_INTERVAL = 2
HTTP_TIMEOUT = 3

# Пути для Tor
TORRC_PATH = os.path.expanduser('~/.tor/torrc')
HIDDEN_SERVICE_DIR = os.path.expanduser('~/.tor/hidden_service/')
HOSTNAME_FILE = os.path.join(HIDDEN_SERVICE_DIR, 'hostname')
TOR_LOG_FILE = os.path.expanduser('~/tor.log')

# ------------------ Управление Tor ------------------
tor_process = None

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
            f.write(f"""HiddenServiceDir {HIDDEN_SERVICE_DIR}
HiddenServicePort 80 127.0.0.1:{FLASK_PORT}
""")

    os.makedirs(HIDDEN_SERVICE_DIR, mode=0o700, exist_ok=True)
    try:
        tor_process = subprocess.Popen(
            ['tor', '-f', TORRC_PATH],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        for _ in range(30):
            if os.path.exists(HOSTNAME_FILE):
                break
            time.sleep(1)
        else:
            print("Ошибка: не удалось получить onion-адрес.")
            sys.exit(1)
    except Exception as e:
        print(f"Ошибка запуска Tor: {e}")
        sys.exit(1)

def stop_tor():
    if tor_process:
        tor_process.terminate()
        tor_process.wait()

atexit.register(stop_tor)

# ------------------ Flask сервер (в отдельном процессе) ------------------
def run_flask_server():
    """Запускает Flask с полным подавлением вывода."""
    # Перенаправляем stdout/stderr в /dev/null
    sys.stdout = open(os.devnull, 'w')
    sys.stderr = open(os.devnull, 'w')

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
            db.execute('''
                CREATE TABLE IF NOT EXISTS keys (
                    id INTEGER PRIMARY KEY,
                    private_key TEXT,
                    public_key TEXT
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY,
                    domain TEXT UNIQUE,
                    public_key TEXT,
                    last_seen TIMESTAMP
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS inbound (
                    id INTEGER PRIMARY KEY,
                    sender_domain TEXT,
                    encrypted_content TEXT,
                    timestamp TIMESTAMP,
                    read BOOLEAN DEFAULT 0
                )
            ''')
            db.execute('''
                CREATE TABLE IF NOT EXISTS outbound (
                    id INTEGER PRIMARY KEY,
                    recipient_domain TEXT,
                    plaintext TEXT,
                    timestamp TIMESTAMP,
                    delivered BOOLEAN DEFAULT 0,
                    remote_msg_id INTEGER
                )
            ''')
            db.commit()

            # Генерация ключей, если их нет
            row = db.execute('SELECT * FROM keys').fetchone()
            if row is None:
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
                db.execute('INSERT INTO keys (private_key, public_key) VALUES (?, ?)',
                           (private_pem, public_pem))
                db.commit()

    init_db()

    # ---------- Вспомогательные функции ----------
    def get_own_keys():
        db = get_db()
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

    # ---------- Эндпоинты (только необходимые) ----------
    @app.route('/api/own_domain', methods=['GET'])
    def api_own_domain():
        return jsonify({'domain': get_own_domain()})

    @app.route('/api/friend_domain', methods=['GET', 'POST'])
    def api_friend_domain():
        if request.method == 'GET':
            db = get_db()
            row = db.execute('SELECT domain FROM servers LIMIT 1').fetchone()
            return jsonify({'domain': row['domain'] if row else None})
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
            return jsonify({'error': 'Own domain not generated'}), 500

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
                return jsonify({'status': 'ok'})
            else:
                return jsonify({'error': 'Registration failed'}), 500
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
            return jsonify({'error': 'Missing data'}), 400
        db = get_db()
        row = db.execute('SELECT public_key FROM servers WHERE domain=?', (recipient,)).fetchone()
        if not row or not row['public_key']:
            return jsonify({'error': 'Friend public key not found'}), 400

        encrypted = encrypt_for(row['public_key'], plaintext)
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
                remote_msg_id = resp.json().get('message_id')
                cur = db.execute('''
                    INSERT INTO outbound (recipient_domain, plaintext, timestamp, remote_msg_id)
                    VALUES (?, ?, ?, ?)
                ''', (recipient, plaintext, datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None), remote_msg_id))
                db.commit()
                return jsonify({'status': 'ok', 'local_id': cur.lastrowid})
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
        return jsonify({'message_id': cur.lastrowid})

    @app.route('/api/poll', methods=['GET'])
    def api_poll():
        last_id = request.args.get('last_id', 0, type=int)
        db = get_db()
        rows = db.execute('''
            SELECT * FROM inbound WHERE id > ? ORDER BY timestamp
        ''', (last_id,)).fetchall()
        private_key, _, _ = get_own_keys()
        messages = []
        for row in rows:
            try:
                plaintext = decrypt_with_own(private_key, row['encrypted_content'])
            except:
                plaintext = '[Ошибка]'
            messages.append({
                'id': row['id'],
                'sender': row['sender_domain'],
                'content': plaintext,
                'timestamp': row['timestamp']
            })
        return jsonify(messages)

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
            SELECT 'in' as direction, id, sender_domain as peer, encrypted_content, timestamp
            FROM inbound
        ''').fetchall()
        outbound = db.execute('''
            SELECT 'out' as direction, id, recipient_domain as peer, plaintext, timestamp, delivered
            FROM outbound
        ''').fetchall()
        private_key, _, _ = get_own_keys()
        messages = []
        for row in inbound:
            try:
                content = decrypt_with_own(private_key, row['encrypted_content'])
            except:
                content = '[Ошибка]'
            messages.append({
                'direction': 'in',
                'id': row['id'],
                'content': content,
                'timestamp': row['timestamp'],
                'delivered': True
            })
        for row in outbound:
            messages.append({
                'direction': 'out',
                'id': row['id'],
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

    # Запуск без логов
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)

# Запускаем Flask в отдельном процессе
flask_process = None

def start_flask():
    global flask_process
    flask_process = subprocess.Popen(
        [sys.executable, '-c', 'import chat; chat.run_flask_server()'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True
    )
    # Ждём готовности
    time.sleep(2)

def stop_flask():
    if flask_process:
        flask_process.terminate()
        flask_process.wait()

atexit.register(stop_flask)

# ------------------ Клиент curses ------------------
class ChatClient:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.running = True
        self.friend_domain = None
        self.friend_online = False
        self.own_domain = None
        self.messages = []
        self.input_buffer = ""
        self.last_poll_id = 0
        self.needs_redraw = True

        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.curs_set(1)
        curses.cbreak()
        curses.noecho()
        self.stdscr.keypad(True)
        self.stdscr.timeout(50)  # 50 мс таймаут для getch()

        self.load_initial_data()
        self.start_poll_thread()

    def load_initial_data(self):
        try:
            resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/own_domain', timeout=2)
            if resp.status_code == 200:
                self.own_domain = resp.json().get('domain')
        except:
            pass
        try:
            resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/friend_domain', timeout=2)
            if resp.status_code == 200:
                self.friend_domain = resp.json().get('domain')
        except:
            pass
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
                                self.messages.append({
                                    'direction': 'in',
                                    'id': msg['id'],
                                    'content': msg['content'],
                                    'timestamp': msg['timestamp'],
                                    'delivered': True
                                })
                                if msg['id'] > self.last_poll_id:
                                    self.last_poll_id = msg['id']
                                self.needs_redraw = True
                                # Подтверждение прочтения
                                threading.Thread(target=self._confirm_read, args=(msg,), daemon=True).start()
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
        try:
            self.stdscr.addstr(0, 0, header[:self.width-1], curses.color_pair(1))
            self.stdscr.addstr(1, 0, "─" * (self.width-1), curses.color_pair(1))
        except:
            pass

        # Сообщения
        chat_height = self.height - 4
        start_y = 2
        display = self.messages[-chat_height:] if len(self.messages) > chat_height else self.messages
        y = start_y
        for msg in display:
            if y >= self.height - 2:
                break
            prefix = "● " if msg['direction'] == 'out' else "○ "
            try:
                dt = datetime.datetime.fromisoformat(msg['timestamp'])
                time_str = dt.strftime('%H:%M')
            except:
                time_str = "??:??"
            line = f"{prefix}{time_str} {msg['content']}"
            if msg['direction'] == 'out' and not msg.get('delivered', True):
                line += " ..."
            if len(line) > self.width-1:
                line = line[:self.width-4] + "..."
            try:
                self.stdscr.addstr(y, 0, line)
            except:
                pass
            y += 1

        # Поле ввода
        try:
            self.stdscr.addstr(self.height-1, 0, "> " + self.input_buffer)
            self.stdscr.clrtoeol()
            self.stdscr.move(self.height-1, len(self.input_buffer) + 2)
        except:
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
                self.add_friend_domain(cmd)
            else:
                self.send_message(cmd)
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

    def add_friend_domain(self, domain):
        try:
            resp = requests.post(
                f'http://{FLASK_HOST}:{FLASK_PORT}/api/friend_domain',
                json={'domain': domain},
                timeout=HTTP_TIMEOUT
            )
            if resp.status_code == 200 and resp.json().get('status') == 'ok':
                self.friend_domain = domain
                self.load_history()
        except:
            pass

    def send_message(self, text):
        try:
            resp = requests.post(
                f'http://{FLASK_HOST}:{FLASK_PORT}/api/send_message',
                json={'recipient': self.friend_domain, 'plaintext': text},
                timeout=HTTP_TIMEOUT
            )
            if resp.status_code == 200:
                data = resp.json()
                self.messages.append({
                    'direction': 'out',
                    'id': data['local_id'],
                    'content': text,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
                    'delivered': False
                })
        except:
            pass

    def handle_command(self, cmd):
        if cmd == '/onion':
            if self.own_domain:
                self.messages.append({
                    'direction': 'out',
                    'id': -1,
                    'content': f"Ваш домен: {self.own_domain}",
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
                    'delivered': True
                })
            else:
                self.messages.append({
                    'direction': 'out',
                    'id': -1,
                    'content': "Домен ещё не сгенерирован",
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat(),
                    'delivered': True
                })

    def run(self):
        while self.running:
            if self.needs_redraw:
                self.draw()
            key = self.stdscr.getch()
            if key != -1:
                self.handle_input(key)

def main(stdscr):
    client = ChatClient(stdscr)
    client.run()

if __name__ == '__main__':
    start_tor()
    start_flask()
    curses.wrapper(main)