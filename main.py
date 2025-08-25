# Ultra Secure Telegram Python Encoder Bot
import os
import marshal
import zlib
import base64
import tempfile
import random
import hashlib
import binascii
import struct
from flask import Flask
import telebot
from threading import Thread
import time

# Bot configuration
BOT_TOKEN = "8241335689:AAHV4hZmiZrTxgVeidJw4QU5kuMM09irV24"
bot = telebot.TeleBot(BOT_TOKEN)

# Flask app for health check (required by Render)
app = Flask(__name__)

@app.route('/')
@app.route('/health')
def health():
    return "Bot is running!", 200

# Advanced encryption functions
def generate_dynamic_key(seed, length):
    """Generate a dynamic key based on seed"""
    random.seed(seed)
    return bytes([random.randint(0, 255) for _ in range(length)])

def polymorphic_xor(data, key):
    """Polymorphic XOR encryption with multiple rounds"""
    result = bytearray(data)
    key_len = len(key)
    
    for round_num in range(3):
        for i in range(len(result)):
            result[i] ^= key[(i + round_num) % key_len]
            result[i] = (result[i] + round_num) % 256
            # Add more confusion with bit rotations
            result[i] = ((result[i] << 2) | (result[i] >> 6)) & 0xFF
    
    return bytes(result)

def multi_layer_compress(data):
    """Multiple compression layers"""
    # First compression
    compressed = zlib.compress(data, level=9)
    
    # Second compression with custom header
    header = b'CZ' + struct.pack('>I', len(compressed))
    compressed = header + compressed
    
    # Third compression
    compressed = zlib.compress(compressed, level=9)
    
    return compressed

def multi_layer_encode(data):
    """Multiple encoding layers with different algorithms"""
    # First encoding
    encoded = base64.b85encode(data)
    
    # Second encoding
    encoded = base64.urlsafe_b64encode(encoded)
    
    # Third encoding
    encoded = binascii.hexlify(encoded)
    
    # Fourth encoding with custom format
    encoded = base64.b64encode(encoded)
    
    return encoded

def ultra_encode(source: str, layers: int = 7) -> str:
    """Ultra secure encoding with multiple protection layers"""
    try:
        # Compile and marshal the source code
        code = compile(source, "<ultra_encoded>", "exec")
        payload = marshal.dumps(code)
        
        # Generate unique seeds for each layer
        timestamp = int(time.time() * 1000)
        seeds = [hashlib.sha256(f"{timestamp}{i}{random.random()}".encode()).digest() for i in range(layers)]
        
        # Apply multiple encoding layers
        for i in range(layers):
            # Generate dynamic key for this layer
            key = generate_dynamic_key(seeds[i], 32)
            
            # Polymorphic XOR encryption
            payload = polymorphic_xor(payload, key)
            
            # Multi-layer compression
            if i % 2 == 0:
                payload = multi_layer_compress(payload)
            
            # Multi-layer encoding
            payload = multi_layer_encode(payload)
            
            # Add junk data to confuse analysis
            junk = os.urandom(random.randint(5, 15))
            payload = junk + payload + junk[::-1]
        
        # Create the decoder stub with anti-tampering
        decoder_stub = f'''# ULTRA SECURE ENCODED PYTHON - DO NOT MODIFY
import marshal, zlib, base64, binascii, hashlib, time, struct, random

def generate_dynamic_key(seed, length):
    random.seed(seed)
    return bytes([random.randint(0, 255) for _ in range(length)])

def polymorphic_xor(data, key):
    result = bytearray(data)
    key_len = len(key)
    
    for round_num in range(3):
        for i in range(len(result)):
            result[i] ^= key[(i + round_num) % key_len]
            result[i] = (result[i] + round_num) % 256
            # Reverse bit rotations
            result[i] = ((result[i] >> 2) | (result[i] << 6)) & 0xFF
    
    return bytes(result)

def multi_layer_decompress(data):
    data = zlib.decompress(data)
    # Remove custom header
    if data[:2] == b'CZ':
        data = data[6:]  # Skip 'CZ' + 4-byte length
    data = zlib.decompress(data)
    return data

def multi_layer_decode(data):
    data = base64.b64decode(data)
    data = binascii.unhexlify(data)
    data = base64.urlsafe_b64decode(data)
    data = base64.b85decode(data)
    return data

# Anti-debugging and anti-tampering measures
if hasattr(__import__('sys'), 'gettrace') and __import__('sys').gettrace() is not None:
    print("DEBUGGER DETECTED! TERMINATING...")
    __import__('os')._exit(1)

try:
    # Decoding parameters
    seeds = {seeds}
    layers = {layers}
    encrypted_payload = {repr(payload)}
    
    # Reverse the encoding process
    for i in range(layers-1, -1, -1):
        # Remove junk data
        junk_len = random.randint(5, 15)
        encrypted_payload = encrypted_payload[junk_len:-junk_len]
        
        # Multi-layer decoding
        encrypted_payload = multi_layer_decode(encrypted_payload)
        
        # Multi-layer decompression if needed
        if i % 2 == 0:
            encrypted_payload = multi_layer_decompress(encrypted_payload)
        
        # Polymorphic XOR decryption
        key = generate_dynamic_key(seeds[i], 32)
        encrypted_payload = polymorphic_xor(encrypted_payload, key)
    
    # Execute the decoded payload
    exec(marshal.loads(encrypted_payload))
except Exception as e:
    print("DECODING ERROR: This file may have been tampered with!")
    __import__('os')._exit(1)
'''
        return decoder_stub
    except Exception as e:
        raise ValueError(f"Ultra encoding failed: {e}")

# Bot handlers
@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    welcome = """🔐 **ULTRA SECURE Python Encoder Bot**

Welcome to the most secure Python code encoder available!

**Features:**
• 7-layer polymorphic encryption
• Dynamic key generation
• Multiple compression algorithms
• Multiple encoding schemes (Base64, Base85, Hex)
• Anti-debugging and anti-tampering protection
• Junk data injection to confuse analysis
• Bit rotation obfuscation

Send me any Python code or .py file to get started!"""
    
    bot.reply_to(message, welcome, parse_mode='Markdown')

@bot.message_handler(content_types=['document'])
def handle_document(message):
    try:
        if not message.document.file_name.endswith('.py'):
            bot.reply_to(message, "❌ Please send a Python (.py) file!")
            return
        
        bot.reply_to(message, "🔒 Processing your file with ULTRA encryption...")
        
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        source_code = downloaded_file.decode('utf-8')
        
        if not source_code.strip():
            bot.reply_to(message, "❌ File is empty!")
            return
        
        encoded_code = ultra_encode(source_code)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(encoded_code)
            temp_path = f.name
        
        with open(temp_path, 'rb') as f:
            bot.send_document(
                message.chat.id, 
                f, 
                caption="🔐 Your ULTRA SECURE encoded Python file!",
                visible_file_name=f"ultra_secure_{message.document.file_name}"
            )
        
        os.unlink(temp_path)
        
    except Exception as e:
        bot.reply_to(message, f"❌ Encryption error: {str(e)}")

@bot.message_handler(func=lambda message: True)
def handle_text(message):
    try:
        text = message.text
        
        python_keywords = ['import', 'def ', 'class ', 'print(', 'if ', 'for ', 'while ']
        if not any(keyword in text.lower() for keyword in python_keywords):
            bot.reply_to(message, """📝 **Send me Python code to encode!**

Example:
```python
print("Hello World!")
for i in range(10):
    print(f"Number: {i}")
```""", parse_mode='Markdown')
            return
        
        bot.reply_to(message, "🔒 Applying ULTRA encryption to your code...")
        
        encoded_code = ultra_encode(text)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(encoded_code)
            temp_path = f.name
        
        with open(temp_path, 'rb') as f:
            bot.send_document(
                message.chat.id, 
                f, 
                caption="🔐 Your ULTRA SECURE encoded Python code!",
                visible_file_name="ultra_secure_script.py"
            )
        
        os.unlink(temp_path)
        
    except Exception as e:
        bot.reply_to(message, f"❌ Encryption error: {str(e)}")

# Run bot in a separate thread
def run_bot():
    print("🤖 ULTRA SECURE Bot started!")
    bot.infinity_polling()

# Main function
if __name__ == "__main__":
    bot_thread = Thread(target=run_bot)
    bot_thread.daemon = True
    bot_thread.start()
    
    port = int(os.environ.get('PORT', 5000))
    print(f"🌐 Starting server on port {port}")
    app.run(host='0.0.0.0', port=port)
