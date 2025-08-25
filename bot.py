# 🔐 Telegram Multi-Layer Encoder Bot
# Developer: @aayuxfr | @aayushpython

import os
import marshal
import zlib
import base64
import tempfile
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

BOT_TOKEN = "8241335689:AAHV4hZmiZrTxgVeidJw4QU5kuMM09irV24"

# ========== ENCODER ==========
def encode_layer(data: bytes, key: int) -> bytes:
    """Encode a single layer with XOR, compression, and base64"""
    xored = bytes([b ^ key for b in data])
    compressed = zlib.compress(xored)
    return base64.b64encode(compressed)

def multilayer_encode(source: str, layers: int = 4, key: int = 37) -> str:
    """Apply multi-layer encoding to Python source code"""
    try:
        # Compile the source code
        code = compile(source, "<encoded>", "exec")
        payload = marshal.dumps(code)

        # Apply multiple encoding layers
        for _ in range(layers):
            payload = encode_layer(payload, key)

        # Create the wrapper script
        wrapper = f"""# Auto-Generated Encrypted Script
# Multi-Layer Encoding: marshal + XOR + zlib + base64
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
"""
        return wrapper
    except SyntaxError as e:
        raise ValueError(f"Syntax error in provided code: {e}")
    except Exception as e:
        raise ValueError(f"Error encoding code: {e}")

# ========== HANDLERS ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    welcome_message = """🔐 **Multi-Layer Python Encoder Bot**

Welcome! This bot can encode your Python files using advanced multi-layer encryption.

**Features:**
• 4-layer encoding (Marshal + XOR + Zlib + Base64)
• Secure obfuscation of Python source code
• Easy to use - just send your .py file!

**How to use:**
1. Send me a Python (.py) file
2. I'll encode it with 4 layers of encryption
3. Download your encoded file

**Security layers:**
1. Marshal compilation
2. XOR encryption (key: 37)
3. Zlib compression
4. Base64 encoding

Ready to encode your Python files! 🚀"""

    await update.message.reply_text(welcome_message, parse_mode='Markdown')

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle document uploads"""
    try:
        document = update.message.document
        
        # Check if it's a Python file
        if not (document.file_name.endswith('.py') or document.mime_type == 'text/x-python'):
            await update.message.reply_text("❌ Please send a Python (.py) file only!")
            return

        await update.message.reply_text("📥 Received your file! Encoding in progress...")

        # Download the file
        file = await document.get_file()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.py', delete=False) as temp_file:
            temp_path = temp_file.name
        
        # Download to temporary file
        await file.download_to_drive(temp_path)
        
        # Read the content
        with open(temp_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Validate that it's not empty
        if not source_code.strip():
            await update.message.reply_text("❌ The file appears to be empty!")
            os.unlink(temp_path)
            return

        # Encode the code
        try:
            encoded_code = multilayer_encode(source_code, layers=4, key=37)
        except ValueError as e:
            await update.message.reply_text(f"❌ Error encoding your code: {str(e)}")
            os.unlink(temp_path)
            return

        # Create output file
        output_filename = f"encoded_{document.file_name}"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as encoded_file:
            encoded_path = encoded_file.name
            encoded_file.write(encoded_code)

        # Send the encoded file
        await update.message.reply_text("✅ Encoding complete! Here's your encoded file:")
        
        with open(encoded_path, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename=output_filename,
                caption="🔐 Your Python file has been encoded with 4-layer encryption!"
            )

        # Clean up temporary files
        os.unlink(temp_path)
        os.unlink(encoded_path)

    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        print(f"Error in handle_document: {e}")

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages (raw Python code)"""
    try:
        source_code = update.message.text
        
        # Check if it looks like Python code
        if not any(keyword in source_code.lower() for keyword in ['import', 'def ', 'class ', 'print(', 'if ', 'for ', 'while ']):
            await update.message.reply_text("""
📝 **Send me Python code to encode!**

You can either:
• Send a .py file (recommended)
• Paste Python code directly

Example:
```python
print("Hello World!")
x = 10
print(f"Value: {x}")
```
""", parse_mode='Markdown')
            return

        await update.message.reply_text("🔄 Encoding your Python code...")

        # Encode the code
        try:
            encoded_code = multilayer_encode(source_code, layers=4, key=37)
        except ValueError as e:
            await update.message.reply_text(f"❌ Error encoding your code: {str(e)}")
            return

        # Create temporary file for the encoded code
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(encoded_code)
            temp_path = temp_file.name

        # Send the encoded file
        await update.message.reply_text("✅ Encoding complete!")
        
        with open(temp_path, 'rb') as f:
            await update.message.reply_document(
                document=f,
                filename="encoded_script.py",
                caption="🔐 Your Python code has been encoded with 4-layer encryption!"
            )

        # Clean up
        os.unlink(temp_path)

    except Exception as e:
        await update.message.reply_text(f"❌ An error occurred: {str(e)}")
        print(f"Error in handle_text: {e}")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command"""
    help_text = """🔐 **Multi-Layer Python Encoder Bot Help**

**Commands:**
• /start - Welcome message and bot info
• /help - Show this help message

**How to use:**
1. **File Upload**: Send a .py file directly
2. **Text Input**: Paste Python code in the chat

**Encoding Process:**
1. Your Python code is compiled to bytecode
2. Applied 4 layers of encryption:
   - Marshal serialization
   - XOR encryption (key: 37)
   - Zlib compression  
   - Base64 encoding
3. Wrapped in a decoder script
4. Sent back as .py file

**Notes:**
• Only Python files (.py) are accepted
• Code must be syntactically valid
• Encoded files can be run like normal Python scripts
• The decoder is embedded in the output file

**Security:** Your code is processed locally and not stored permanently."""

    await update.message.reply_text(help_text, parse_mode='Markdown')

# ========== MAIN ==========
def main():
    """Start the bot"""
    print("🚀 Starting Multi-Layer Encoder Bot...")
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    print("✅ Bot is running! Press Ctrl+C to stop.")
    
    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()
