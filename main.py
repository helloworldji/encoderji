# Simple Telegram Encoder Bot for Render
import os
import marshal
import zlib
import base64
import tempfile
from flask import Flask
import telebot
from threading import Thread

# Bot configuration
BOT_TOKEN = "8241335689:AAHV4hZmiZrTxgVeidJw4QU5kuMM09irV24"
bot = telebot.TeleBot(BOT_TOKEN)

# Flask app for health check (required by Render)
app = Flask(__name__)

@app.route('/')
@app.route('/health')
def health():
    return "Bot is running!", 200

# Encoder functions
def encode_layer(data: bytes, key: int) -> bytes:
    xored = bytes([b ^ key for b in data])
    compressed = zlib.compress(xored)
    return base64.b64encode(compressed)

def multilayer_encode(source: str, layers: int = 4, key: int = 37) -> str:
    try:
        code = compile(source, "<encoded>", "exec")
        payload = marshal.dumps(code)
        
        for _ in range(layers):
            payload = encode_layer(payload, key)
        
        wrapper = f'''# Auto-Generated Encrypted Script
import marshal, zlib, base64

def decode_layer(data, key):
    data = base64.b64decode(data)
    data = zlib.decompress(data)
    return bytes([b ^ key for b in data])

key = {key}
payload = {repr(payload)}

for _ in range({layers}):
    payload = decode_layer(payload, key)

exec(marshal.loads(payload))
'''
        return wrapper
    except Exception as e:
        raise ValueError(f"Error encoding: {e}")

# Bot handlers
@bot.message_handler(commands=['start'])
def start_command(message):
    welcome = """🔐 **Multi-Layer Python Encoder Bot**

Welcome! Send me Python code and I'll encode it with 4-layer encryption.

**How to use:**
1. Send me a .py file OR
2. Send Python code as text

**Features:**
• 4-layer encoding (Marshal + XOR + Zlib + Base64)
• Secure code obfuscation
• Easy to use

Ready to encode! 🚀"""
    
    bot.reply_to(message, welcome, parse_mode='Markdown')

@bot.message_handler(commands=['help'])
def help_command(message):
    help_text = """🔐 **Help - Python Encoder Bot**

**Commands:**
• /start - Welcome message
• /help - This help message

**Usage:**
1. Send a .py file - I'll encode it
2. Send Python code as text - I'll encode it

**Example:**
```python
print("Hello World!")
x = 10
print(f"Number: {x}")
```

The bot will return an encoded version of your code!"""
    
    bot.reply_to(message, help_text, parse_mode='Markdown')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        # Check if it's a Python file
        if not message.document.file_name.endswith('.py'):
            bot.reply_to(message, "❌ Please send a Python (.py) file only!")
            return
        
        bot.reply_to(message, "📥 Processing your file...")
        
        # Download file
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        # Read content
        source_code = downloaded_file.decode('utf-8')
        
        if not source_code.strip():
            bot.reply_to(message, "❌ File is empty!")
            return
        
        # Encode the code
        encoded_code = multilayer_encode(source_code)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(encoded_code)
            temp_path = f.name
        
        # Send encoded file
        with open(temp_path, 'rb') as f:
            bot.send_document(
                message.chat.id, 
                f, 
                caption="🔐 Your encoded Python file!",
                visible_file_name=f"encoded_{message.document.file_name}"
            )
        
        # Clean up
        os.unlink(temp_path)
        
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

@bot.message_handler(func=lambda message: True)
def handle_text(message):
    try:
        text = message.text
        
        # Check if it looks like Python code
        python_keywords = ['import', 'def ', 'class ', 'print(', 'if ', 'for ', 'while ']
        if not any(keyword in text.lower() for keyword in python_keywords):
            bot.reply_to(message, """📝 **Send me Python code to encode!**

Example:
```python
print("Hello World!")
x = 10
print(f"Value: {x}")
```

Or send a .py file directly!""", parse_mode='Markdown')
            return
        
        bot.reply_to(message, "🔄 Encoding your code...")
        
        # Encode the code
        encoded_code = multilayer_encode(text)
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(encoded_code)
            temp_path = f.name
        
        # Send encoded file
        with open(temp_path, 'rb') as f:
            bot.send_document(
                message.chat.id, 
                f, 
                caption="🔐 Your encoded Python code!",
                visible_file_name="encoded_script.py"
            )
        
        # Clean up
        os.unlink(temp_path)
        
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)}")

# Run bot in a separate thread
def run_bot():
    print("🤖 Bot started!")
    bot.infinity_polling()

# Main function
if __name__ == "__main__":
    # Start bot in background
    bot_thread = Thread(target=run_bot)
    bot_thread.daemon = True
    bot_thread.start()
    
    # Start Flask server (required by Render)
    port = int(os.environ.get('PORT', 5000))
    print(f"🌐 Starting server on port {port}")
    app.run(host='0.0.0.0', port=port)
