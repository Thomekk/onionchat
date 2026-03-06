#!/data/data/com.termux/files/usr/bin/bash

# Получаем абсолютный путь к папке, где находится install.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAT_PY="$SCRIPT_DIR/chat.py"

echo "🔧 Установка необходимых пакетов..."
pkg update -y && pkg upgrade -y
pkg install -y tor python python-cryptography

echo "📦 Установка Python-зависимостей..."
pip install flask requests pysocks

# Создаём исполняемую команду onionchat в $PREFIX/bin
COMMAND_PATH="$PREFIX/bin/onionchat"
cat > "$COMMAND_PATH" <<EOF
#!/data/data/com.termux/files/usr/bin/bash
cd "$SCRIPT_DIR"
python chat.py
EOF

chmod +x "$COMMAND_PATH"

echo "✅ Установка завершена! Теперь вы можете запустить чат командой: onionchat"
echo "🚀 Запуск чата..."
python "$CHAT_PY"