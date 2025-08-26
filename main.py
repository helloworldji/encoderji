# Ultra Secure Telegram Python Encoder Bot - Ultra Simplified for Hosting
# No emojis in strings, minimal decorative output.

import os
import marshal
import zlib
import base64
import tempfile
import random
import hashlib
import binascii
import struct
import sys
import time
import glob
import shutil
from threading import Thread
from flask import Flask
import telebot

# --- Configuration ---
# Read sensitive configuration from environment variables.
BOT_TOKEN = os.environ.get("BOT_TOKEN")
if not BOT_TOKEN:
    print("FATAL ERROR: BOT_TOKEN environment variable not set.")
    sys.exit(1) # Exit if no token is found.

# Flask app for health check endpoint.
app = Flask(__name__)

@app.route('/')
@app.route('/health')
def health_check():
    return "Bot is operational.", 200

# --- Core Obfuscation Engine ---

class ObfuscationEngine:
    """Handles code obfuscation, simplified for reliable hosting."""
    def __init__(self, layers=7, key_size=32):
        self.layers = layers
        self.key_size = key_size
        self.seed_salt = os.urandom(16) 
        self.temp_dir = tempfile.mkdtemp(prefix="obfuscator_")
        print(f"Obfuscation temp dir: {self.temp_dir}")

    def _generate_complex_seed(self, base_seed):
        timestamp = int(time.time() * 1000)
        random_val = random.random()
        seed_material = f"{base_seed.hex()}-{timestamp}-{random_val}-{os.getpid()}-{self.seed_salt.hex()}"
        return hashlib.sha256(seed_material.encode()).digest()

    def _derive_keys(self, seed):
        """Derives multiple keys from a seed."""
        keys = []
        prk = hashlib.sha256(seed).digest() 
        for i in range(self.layers):
            t = self.seed_salt + struct.pack('>I', i) + prk
            h = hashlib.sha256(t).digest()
            keys.append(h[:self.key_size])
            prk = h
        return keys

    def _poly_cipher(self, data, keys):
        """Simplified polymorphic cipher with basic operations and rotations."""
        processed_data = bytearray(data)
        for layer_idx, key in enumerate(keys):
            key_len = len(key)
            op_sequence_seed = hashlib.sha256(key).digest()
            random.seed(op_sequence_seed)

            op_funcs = [
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256,
                lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256,
            ]
            random.shuffle(op_funcs) 

            for i in range(len(processed_data)):
                rotation_amount = (i % 8) + 1 
                operation = op_funcs[i % len(op_funcs)]
                processed_data[i] = operation(processed_data, key, i, layer_idx, op_sequence_seed)
                if layer_idx % 2 == 0: # ROL
                    processed_data[i] = ((processed_data[i] << rotation_amount) | (processed_data[i] >> (8 - rotation_amount))) & 0xFF
                else: # ROR
                    processed_data[i] = ((processed_data[i] >> rotation_amount) | (processed_data[i] << (8 - rotation_amount))) & 0xFF
        return bytes(processed_data)

    def _multi_compress_obfuscated(self, data, level=9):
        """Simplified multi-stage compression."""
        if len(data) < 64: return data
        try:
            compressed_l1 = zlib.compress(data, level=level)
            header_l1 = b'\xDE\xC0' + struct.pack('>H', len(compressed_l1)) 
            data_l1 = header_l1 + compressed_l1
            
            compressed_l2 = zlib.compress(data_l1, level=level)
            stuff_size = random.randint(5, 10)
            stuff = os.urandom(stuff_size)
            header_l2 = b'\xCA\xFE' + struct.pack('>I', len(compressed_l2)) + stuff
            data_l2 = header_l2 + compressed_l2
            return data_l2
        except zlib.error: return data

    def _encode_stages(self, data):
        """Applies simplified encoding stages."""
        encoded_b85 = base64.b85encode(data)
        encoded_urlsafe = base64.urlsafe_b64encode(encoded_b85)
        encoded_hex = b'XX' + binascii.hexlify(encoded_urlsafe) + b'YY'
        
        scrambled_hex_bytearray = bytearray(encoded_hex)
        for i in range(len(scrambled_hex_bytearray)):
            scrambled_hex_bytearray[i] ^= (i % 128) # Simplified scrambling
        encoded_final = base64.b64encode(bytes(scrambled_hex_bytearray))
        return encoded_final

    def _decrypt_strings_for_stub(self, critical_strings_map, initial_key, seed_salt):
        """Encrypts critical strings for embedding in the stub."""
        encrypted_strings_dict = {}
        for name, value in critical_strings_map.items():
            val_bytes = value.encode('utf-8') if isinstance(value, str) else value
            encrypted_val = bytearray()
            name_offset = ord(name[0]) % len(initial_key) 
            for i in range(len(val_bytes)):
                encrypted_val.append(val_bytes[i] ^ initial_key[(i + name_offset) % len(initial_key)])
            encrypted_strings_dict[name] = bytes(encrypted_val)
        return encrypted_strings_dict

    def _generate_vm_stub_code(self, vm_args, encrypted_strings_map):
        """Generates the VM stub code, minimizing complexity."""
        embedded_encrypted_strings = "{\n"
        for name, enc_val in encrypted_strings_map.items():
            embedded_encrypted_strings += f"        '{name}': {repr(enc_val)},\n"
        embedded_encrypted_strings += "    }"
        
        stub_template = f"""
import marshal, zlib, base64, binascii, hashlib, time, struct, random, sys, os

# --- String Decryption Helper ---
def decrypt_strings(encrypted_map, initial_key_hex, seed_salt_hex):
    decrypted_map = {{}}
    initial_key = bytes.fromhex(initial_key_hex)
    seed_salt = bytes.fromhex(seed_salt_hex)
    for name, enc_val in encrypted_map.items():
        decrypted_bytes = bytearray()
        name_offset = ord(name[0]) % len(initial_key) 
        for i in range(len(enc_val)):
            decrypted_bytes.append(enc_val[i] ^ initial_key[(i + name_offset) % len(initial_key)])
        decrypted_map[name] = bytes(decrypted_bytes).decode('utf-8', errors='ignore')
    return decrypted_map

# --- VM Executor Class ---
class VM_Executor:
    def __init__(self, encrypted_payload, seeds_list, key_size, num_layers, seed_salt_hex, initial_key_hex, encrypted_strings_map):
        self.payload = encrypted_payload
        self.seeds = seeds_list
        self.key_size = key_size
        self.layers = num_layers
        self.seed_salt = bytes.fromhex(seed_salt_hex)
        self.initial_key = bytes.fromhex(initial_key_hex)
        self.s = decrypt_strings(encrypted_strings_map, initial_key_hex, seed_salt_hex)
        self._validate_environment()
        self.keys = self._derive_keys_for_decipher(self.seed_salt)

    def _get_callable(self, name_key):
        try:
            str_name = self.s[name_key]
            if '.' in str_name:
                module_name, attr_name = str_name.split('.', 1)
                module = None
                if module_name == 'zlib': module = __import__('zlib')
                elif module_name == 'base64': module = __import__('base64')
                elif module_name == 'binascii': module = __import__('binascii')
                elif module_name == 'marshal': module = __import__('marshal')
                elif module_name == 'hashlib': module = __import__('hashlib')
                elif module_name == 'struct': module = __import__('struct')
                elif module_name == 'random': module = __import__('random')
                elif module_name == 'sys': module = __import__('sys')
                elif module_name == 'os': module = __import__('os')
                elif module_name == 'time': module = __import__('time')
                elif module_name == 'exec': return lambda code: exec(code)
                else: raise ValueError("Unknown module")
                return getattr(module, attr_name)
            else: return str_name
        except Exception: os._exit(1)

    def _derive_keys_for_decipher(self, seed):
        keys = []
        prk = self.s['hashlib_sha256'](seed).digest()
        for i in range(self.layers):
            t = self.seed_salt + self.s['struct_pack']('>I', i) + prk
            h = self.s['hashlib_sha256'](t).digest()
            keys.append(h[:self.key_size])
            prk = h
        return keys

    def _validate_environment(self):
        try:
            if self.s.get('sys_gettrace') and self.s.get('sys_gettrace')() is not None: os._exit(1)
        except Exception: os._exit(1)
        if not self.s.get('zlib_decompress'): os._exit(1)

    def _decompress_multi_stage(self, data):
        try:
            for i in range(len(data)):
                try:
                    decompressed_l1 = self.s['zlib_decompress'](data[i:])
                    if decompressed_l1.startswith(self.s['header_l1_prefix']):
                        compressed_len_l1 = self.s['struct_unpack']('>H', decompressed_l1[3:5])[0]
                        inner_compressed_data = decompressed_l1[5 : 5 + compressed_len_l1]
                        decompressed_l0 = self.s['zlib_decompress'](inner_compressed_data)
                        return decompressed_l0
                except Exception: continue
            raise Exception("Invalid compressed data or header.")
        except Exception: os._exit(1)

    def _reverse_poly_cipher_layer(self, data, layer_index):
        key = self.keys[layer_index]
        key_len = len(key)
        processed_data = bytearray(data)
        
        op_sequence_seed = self.s['hashlib_sha256'](key).digest()
        self.s['random_seed'](op_sequence_seed)
        
        for i in range(len(processed_data) - 1, -1, -1):
            rotation_amount = (i % 8) + 1 
            if layer_index % 2 == 0: # ROL inverse is ROR
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
            else: # ROR inverse is ROL
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF
            
            processed_data[i] ^= key[(i + layer_index) % key_len] # Simplified inverse for XOR
            
        return bytes(processed_data)

    def execute_pipeline(self):
        current_data = self.payload
        
        # --- Phase 1: Reverse Encoding Stages ---
        try:
            decoded_final_b64 = self.s['base64_b64decode'](current_data)
            scrambled_hex_bytearray = bytearray(decoded_final_b64)
            for i in range(len(scrambled_hex_bytearray)): scrambled_hex_bytearray[i] ^= (i % 128) # Inverse scramble
            current_data = bytes(scrambled_hex_bytearray)

            if not current_data.startswith(self.s['header_l1_prefix']) or not current_data.endswith(self.s['header_l2_prefix']): raise ValueError("Invalid hex prefix/suffix.")
            current_data = current_data[2:-2]
            current_data = self.s['binascii_unhexlify'](current_data)

            current_data = self.s['base64_urlsafe_b64decode'](current_data)
            current_data = self.s['base64_b85decode'](current_data)
        except Exception: os._exit(1)

        # --- Phase 2: Interleaved Decompression and Cipher Decryption ---
        for i in range(self.layers - 1, -1, -1):
            if i % 3 == 0: 
                try: current_data = self._decompress_multi_stage(current_data)
                except Exception: os._exit(1)
            try: current_data = self._reverse_poly_cipher_layer(current_data, i)
            except Exception: os._exit(1)

        # --- Phase 3: Final Unmarshalling and Execution ---
        try:
            code_object = self.s['marshal_loads'](current_data)
            self.s['exec_call'](code_object)
        except Exception: os._exit(1)

# --- Bot Controller Class ---
class BotController:
    def __init__(self, bot_token):
        self.bot = telebot.TeleBot(bot_token)
        self.obfuscator = ObfuscationEngine(layers=7) 
        self.setup_handlers()

    def setup_handlers(self):
        """Sets up the message handlers for the Telegram bot."""
        @self.bot.message_handler(commands=['start', 'help'])
        def send_welcome(message):
            welcome_msg = """Hello! This is the Ultra Secure Python Obfuscator Bot.
Send me a .py file or Python code snippet, and I'll return an obfuscated version.
For more info on features, send /help."""
            self.bot.reply_to(message, welcome_msg)

        @self.bot.message_handler(content_types=['document'])
        def handle_document(message):
            try:
                file_info = self.bot.get_file(message.document.file_id)
                if not file_info.file_name.lower().endswith('.py'):
                    self.bot.reply_to(message, "❌ Please send a Python (.py) file only!")
                    return

                self.bot.reply_to(message, "🔒 Processing your file with advanced obfuscation...")
                
                downloaded_file = self.bot.download_file(file_info.file_path)
                source_code = downloaded_file.decode('utf-8', errors='ignore')

                if not source_code.strip():
                    self.bot.reply_to(message, "❌ The provided file is empty or contains no executable code.")
                    return
                
                encoded_code = self.obfuscate_code(source_code)
                
                temp_file_path = os.path.join(self.obfuscator.temp_dir, f"ultra_secure_{file_info.file_name}")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="Your ULTRA SECURE obfuscated Python script!",
                        visible_file_name=f"ultra_secure_{file_info.file_name}"
                    )
                
                os.unlink(temp_file_path)
                
            except telebot.apihelper.ApiTelegramException as e:
                self.handle_error(message, f"Telegram API Error: {e}")
            except Exception as e:
                self.handle_error(message, f"Error processing document: {str(e)}")

        @self.bot.message_handler(func=lambda message: True)
        def handle_text(message):
            text = message.text
            python_indicators = ['import ', 'def ', 'class ', 'print(', 'if ', 'for ', 'while ', '=', '{', '}']
            if not any(indicator in text for indicator in python_indicators) and len(text.splitlines()) < 2:
                welcome_msg = """Send me Python code or a .py file for obfuscation!
Example:
```python
print("Hello")
```"""
                self.bot.reply_to(message, welcome_msg)
                return
            
            self.bot.reply_to(message, "🔒 Applying obfuscation...")
            
            try:
                encoded_code = self.obfuscate_code(text)
                
                temp_file_path = os.path.join(self.obfuscator.temp_dir, "ultra_secure_script.py")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="Your ULTRA SECURE obfuscated Python code!",
                        visible_file_name="ultra_secure_script.py"
                    )
                
                os.unlink(temp_file_path)
                
            except telebot.apihelper.ApiTelegramException as e:
                self.handle_error(message, f"Telegram API Error: {e}")
            except Exception as e:
                self.handle_error(message, f"Error obfuscating code: {str(e)}")

    def obfuscate_code(self, source_code):
        """Orchestrates the obfuscation process for a given source code string."""
        try:
            code = compile(source_code, "<obfuscated_source>", "exec")
            payload = marshal.dumps(code)
            
            base_seed = os.urandom(16) 
            seeds = [self.obfuscator._generate_complex_seed(base_seed + struct.pack('>I', i)) for i in range(self.obfuscator.layers)]
            keys = self.obfuscator._derive_keys(base_seed) 

            transformed_data = payload
            for i in range(self.obfuscator.layers):
                transformed_data = self.obfuscator._poly_cipher(transformed_data, [keys[i]])
                if i % 3 == 0: 
                    transformed_data = self.obfuscator._multi_compress_obfuscated(transformed_data)
            
            final_encoded_payload = self.obfuscator._encode_stages(transformed_data)
            
            critical_strings_map = {
                "zlib_decompress": "zlib.decompress", "base64_b85decode": "base64.b85decode",
                "base64_urlsafe_b64decode": "base64.urlsafe_b64decode", "base64_b64decode": "base64.b64decode",
                "binascii_unhexlify": "binascii.unhexlify", "binascii_hexlify": "binascii.hexlify",
                "hashlib_sha256": "hashlib.sha256", "marshal_loads": "marshal.loads",
                "struct_pack": "struct.pack", "struct_unpack": "struct.unpack",
                "random_seed": "random.seed", "sys_gettrace": "sys.gettrace",
                "os_exit": "os._exit", "exec_call": "exec", "Exception": "Exception",
                "header_l1_prefix": b'\xDE\xC0', "header_l2_prefix": b'\xCA\xFE', 
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
            }
            encrypted_strings_dict = self.obfuscator._decrypt_strings_for_stub(critical_strings_map, keys[0], self.obfuscator.seed_salt)
            
            vm_args = {
                "encrypted_payload": final_encoded_payload,
                "seeds_list": seeds,
                "key_size": self.obfuscator.key_size,
                "num_layers": self.obfuscator.layers,
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
                "initial_key_hex": keys[0].hex() 
            }
            
            stub_code = self.obfuscator._generate_vm_stub_code(vm_args, encrypted_strings_dict)
            
            return stub_code
            
        except Exception as e:
            print(f"ERROR: Failed to obfuscate code: {e}", file=sys.stderr)
            raise ValueError("Obfuscation failed due to an internal error. Please try again.")

    def handle_error(self, message, error_msg):
        print(f"BOT ERROR: {error_msg}", file=sys.stderr)
        self.bot.reply_to(message, f"❌ An error occurred.")

    def start_polling(self):
        print("🤖 Starting Telegram Bot polling...")
        while True:
            try:
                self.bot.infinity_polling(timeout=10, long_polling_timeout=5)
            except telebot.apihelper.ApiTelegramException as e:
                print(f"Telegram API Exception: {e}. Retrying in 5 seconds...")
                time.sleep(5)
            except Exception as e:
                print(f"An unexpected error occurred in polling: {e}. Retrying in 10 seconds...")
                time.sleep(10)

    def start_webserver(self):
        port = int(os.environ.get('PORT', 5000))
        print(f"🌐 Starting Flask server on port {port}")
        try:
            server_thread = Thread(target=lambda: app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False))
            server_thread.daemon = True
            server_thread.start()
        except Exception as e:
            print(f"Error starting Flask server: {e}", file=sys.stderr)

# --- Main Execution Block ---
if __name__ == "__main__":
    if not BOT_TOKEN:
        print("ERROR: BOT_TOKEN is not configured. Please set the BOT_TOKEN environment variable.")
        sys.exit(1)

    # Cleanup old temp directories
    try:
        temp_dir_pattern = os.path.join(tempfile.gettempdir(), "obfuscator_*")
        for dir_path in glob.glob(temp_dir_pattern):
            if os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
                print(f"Cleaned up old temp dir: {dir_path}")
    except Exception as e:
        print(f"Error during initial temp directory cleanup: {e}", file=sys.stderr)

    bot_controller = BotController(BOT_TOKEN)
    bot_controller.start_webserver() 
    bot_controller.start_polling()
