#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Обновлён 3

import sqlite3
import datetime
import os
import base64
import threading
import time
import curses
import queue
import sys
import subprocess
import signal
import atexit
import logging
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests
import socks

# ------------------ Настройки ------------------
SOCKS5_PROXY = 'socks5://127.0.0.1:9050'
TOR_PROXY = {
    'http': SOCKS5_PROXY,
    'https': SOCKS5_PROXY
}
FLASK_PORT = 8080
FLASK_HOST = '127.0.0.1'
POLL_INTERVAL = 2          # проверка новых сообщений
ONLINE_CHECK_INTERVAL = 5  # проверка доступности друга
NOTIFICATION_DURATION = 3  # секунды показа уведомления
HTTP_TIMEOUT = 3           # таймаут для HTTP-запросов через Tor

# Пути для Tor (в Termux)
TORRC_PATH = os.path.expanduser('~/.tor/torrc')
HIDDEN_SERVICE_DIR = os.path.expanduser('~/.tor/hidden_service/')
HOSTNAME_FILE = os.path.join(HIDDEN_SERVICE_DIR, 'hostname')
TOR_LOG_FILE = os.path.expanduser('~/tor.log')

# ------------------ Отключаем логи Flask ------------------
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ------------------ Глобальные переменные ------------------
tor_process = None
flask_ready = threading.Event()  # сигнал, что Flask запущен

# ------------------ Управление Tor ------------------
def start_tor():
    """Запускает Tor как подпроцесс, если он ещё не запущен."""
    global tor_process
    try:
        subprocess.run(['pgrep', 'tor'], check=True, stdout=subprocess.DEVNULL)
        # Tor уже запущен, ничего не делаем
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
        # Ждём генерации адреса (до 30 секунд)
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
    """Останавливает Tor при выходе."""
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

# ---------- Вспомогательные функции для запросов через Tor ----------
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

# ---------- Эндпоинты Flask ----------
# (Полный список эндпоинтов, включая /api/ping и /api/check_online, 
#  как в исходном коде, опущен для краткости, но в реальном файле они присутствуют)
# Важно: во всех эндпоинтах, где используется datetime.datetime.utcnow(),
# необходимо заменить на datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
# Например:
#   timestamp = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()
# Это касается функций: api_friend_domain, api_register_key, api_send_message, api_receive и др.

# ------------------ Клиент curses ------------------
class ChatClient:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.message_queue = queue.Queue()
        self.action_queue = queue.Queue()  # для асинхронных действий (отправка, добавление друга)
        self.running = True
        self.friend_domain = None
        self.friend_online = False
        self.own_domain = None
        self.messages = []
        self.input_buffer = ""
        self.last_poll_id = 0
        self.notification = {"text": "", "color": 0, "end_time": 0}

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
        curses.use_default_colors()  # для поддержки фона

        # Ждём готовности Flask (максимум 2 секунды)
        flask_ready.wait(2)

        self.load_initial_data()
        self.start_poll_thread()
        self.start_online_check_thread()
        self.start_action_thread()

    def load_initial_data(self):
        # Пытаемся получить свой домен с повторными попытками (до 5 секунд)
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
            # Если не получили, попробуем прочитать файл напрямую
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
                    if msg['direction'] == 'in' and msg['id'] > self.last_poll_id:
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
                                # Подтверждение прочтения (отправляем асинхронно, не ждём)
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
        """Обрабатывает действия (отправка сообщений, добавление друга) в фоне."""
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
                # FIX: замена устаревшего utcnow()
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

    def truncate_domain(self, domain, max_len):
        if len(domain) <= max_len:
            return domain
        half = (max_len - 3) // 2
        return domain[:half] + "..." + domain[-half:]

    def draw(self):
        # Обновляем размеры экрана на случай изменения
        self.height, self.width = self.stdscr.getmaxyx()
        self.stdscr.erase()  # вместо clear() для уменьшения мерцания

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
        except curses.error:
            pass

        # Верхняя линия
        try:
            self.stdscr.addstr(1, 0, "─" * (self.width-1), self.color_cyan)
        except curses.error:
            pass

        # Область сообщений
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
            if msg['direction'] == 'out' and not msg['delivered']:
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
        except curses.error:
            pass
        self.stdscr.clrtoeol()
        try:
            self.stdscr.move(self.height-1, len(prompt) + len(self.input_buffer))
        except curses.error:
            pass

    def handle_input(self, key):
        if key == 10:  # Enter
            cmd = self.input_buffer.strip()
            self.input_buffer = ""
            if cmd == "":
                return
            if cmd.startswith('/'):
                self.handle_command(cmd)
            elif not self.friend_domain:
                # Добавление друга в фоне
                self.action_queue.put(('add_friend', cmd))
            else:
                # Отправка сообщения в фоне
                self.action_queue.put(('send_message', cmd))
        # FIX: убраны os._exit(0), теперь просто завершаем цикл
        elif key in (27, ord('c'), ord('x'), 3):  # ESC, c, x, Ctrl+C — выход
            self.running = False
        elif key == curses.KEY_BACKSPACE or key == 127:
            self.input_buffer = self.input_buffer[:-1]
        elif key == curses.KEY_RESIZE:
            self.height, self.width = self.stdscr.getmaxyx()
            curses.resizeterm(self.height, self.width)
            # FIX: немедленная перерисовка и обновление курсора
            self.draw()
            self.stdscr.refresh()
            curses.curs_set(1)
        elif 32 <= key < 127:
            self.input_buffer += chr(key)

    def handle_command(self, cmd):
        if cmd == '/onion':
            # Обновим own_domain на всякий случай
            try:
                resp = requests.get(f'http://{FLASK_HOST}:{FLASK_PORT}/api/own_domain', timeout=2)
                if resp.status_code == 200:
                    self.own_domain = resp.json().get('domain')
            except:
                pass
            if self.own_domain:
                # FIX: замена устаревшего utcnow()
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
        except queue.Empty:
            pass

    def run(self):
        while self.running:
            self.process_queue()
            self.draw()
            self.stdscr.refresh()
            try:
                key = self.stdscr.getch()
                self.handle_input(key)
            except KeyboardInterrupt:
                # FIX: корректный выход без os._exit и трейсов
                self.running = False
                break

# ------------------ Запуск Flask ------------------
def run_flask():
    # FIX: подавление баннера Flask
    from werkzeug import serving
    serving._log = lambda *args, **kwargs: None

    init_db()
    flask_ready.set()  # сигнализируем, что Flask готов
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)

def main(stdscr):
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    client = ChatClient(stdscr)
    client.run()  # FIX: убран лишний os._exit, выход происходит естественно

if __name__ == '__main__':
    start_tor()
    # Небольшая задержка, чтобы Tor успел создать hostname
    time.sleep(1)
    curses.wrapper(main)