#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Обновлён 5 — мерцание + клавиатура + Flask в Termux исправлены

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
import atexit
import logging
from flask import Flask, request, jsonify, g
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests

# ------------------ Настройки ------------------
SOCKS5_PROXY = 'socks5://127.0.0.1:9050'
TOR_PROXY = {'http': SOCKS5_PROXY, 'https': SOCKS5_PROXY}
FLASK_PORT = 8080
FLASK_HOST = '127.0.0.1'
POLL_INTERVAL = 2
ONLINE_CHECK_INTERVAL = 5
NOTIFICATION_DURATION = 3
HTTP_TIMEOUT = 3

# Пути для Tor (в Termux)
TORRC_PATH = os.path.expanduser('\~/.tor/torrc')
HIDDEN_SERVICE_DIR = os.path.expanduser('\~/.tor/hidden_service/')
HOSTNAME_FILE = os.path.join(HIDDEN_SERVICE_DIR, 'hostname')
TOR_LOG_FILE = os.path.expanduser('\~/tor.log')

# ------------------ Отключаем все логи Flask ------------------
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('flask').disabled = True

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

# (init_db, generate_own_keys, get_own_keys, get_own_domain, tor_request, encrypt_for, decrypt_with_own — без изменений, оставлены как были)

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, private_key TEXT, public_key TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY, domain TEXT UNIQUE, public_key TEXT, last_seen TIMESTAMP)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS inbound (id INTEGER PRIMARY KEY, sender_domain TEXT, encrypted_content TEXT, timestamp TIMESTAMP, read BOOLEAN DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS outbound (id INTEGER PRIMARY KEY, recipient_domain TEXT, plaintext TEXT, timestamp TIMESTAMP, delivered BOOLEAN DEFAULT 0, remote_msg_id INTEGER)''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_servers_domain ON servers(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_inbound_timestamp ON inbound(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_outbound_timestamp ON outbound(timestamp)')
        db.commit()
        cursor.execute('SELECT * FROM keys')
        if cursor.fetchone() is None:
            generate_own_keys()

# (остальные функции Flask — generate_own_keys, get_own_keys, get_own_domain, tor_request, encrypt_for, decrypt_with_own — копируй из предыдущей версии, они не менялись)

# ------------------ Клиент curses ------------------
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
        self.needs_redraw = True   # ← главное исправление мерцания

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
        self.stdscr.timeout(50)   # быстрый отклик, но не перегружает

        flask_ready.wait(2)
        self.load_initial_data()
        self.start_poll_thread()
        self.start_online_check_thread()
        self.start_action_thread()

    # (load_initial_data, load_history, start_poll_thread, _confirm_read, start_online_check_thread, start_action_thread, _add_friend_async, _send_message_async, show_notification, truncate_domain — без изменений)

    def draw(self):
        self.height, self.width = self.stdscr.getmaxyx()
        self.stdscr.erase()

        # Заголовок, сообщения, уведомления, поле ввода — полностью как раньше
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

        try:
            self.stdscr.addstr(self.height-3, 0, "─" * (self.width-1), self.color_cyan)
        except curses.error:
            pass

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

        prompt = "> "
        try:
            self.stdscr.addstr(self.height-1, 0, prompt)
            self.stdscr.addstr(self.height-1, len(prompt), self.input_buffer)
            self.stdscr.clrtoeol()
            self.stdscr.move(self.height-1, len(prompt) + len(self.input_buffer))
        except curses.error:
            pass

    def handle_input(self, key):
        if key == 10:
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
        elif key in (27, ord('c'), ord('x'), 3):
            self.running = False
        elif key == curses.KEY_BACKSPACE or key == 127:
            self.input_buffer = self.input_buffer[:-1]
            self.needs_redraw = True
        elif key == curses.KEY_RESIZE:
            self.height, self.width = self.stdscr.getmaxyx()
            curses.resizeterm(self.height, self.width)
            self.stdscr.clear()
            self.needs_redraw = True
        elif 32 <= key < 127:
            self.input_buffer += chr(key)
            self.needs_redraw = True

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
                    self.needs_redraw = True
        except queue.Empty:
            pass

    def run(self):
        while self.running:
            self.process_queue()

            if self.needs_redraw:
                self.draw()
                self.stdscr.refresh()
                self.needs_redraw = False

            key = self.stdscr.getch()
            if key != -1:
                self.handle_input(key)
                self.needs_redraw = True   # после ввода сразу перерисовать

# ------------------ Запуск Flask (исправлено) ------------------
def run_flask():
    # Надёжное подавление всего вывода
    from flask.cli import show_server_banner
    show_server_banner = lambda *args, **kwargs: None

    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.log_request = lambda *args, **kwargs: None
    WSGIRequestHandler.log_error = lambda *args, **kwargs: None

    # Убираем проблемный FD (главное исправление KeyError)
    os.environ.pop('WERKZEUG_SERVER_FD', None)
    os.environ.pop('WERKZEUG_RUN_MAIN', None)

    init_db()
    flask_ready.set()
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False, threaded=False)

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
    time.sleep(1)
    curses.wrapper(main)