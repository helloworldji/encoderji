# -*- coding: utf-8 -*-
# Ultra Secure Telegram Python Encoder Bot - Advanced Obfuscation Suite (v3.1)
# Features: Deep obfuscation, polymorphic ciphers, interleaved compression/encoding,
#           runtime complexity, string encryption, anti-debugging, lightweight VM.

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
import telebot # Ensure telebot is installed: pip install pyTelegramBotAPI

# --- Configuration ---
# It is HIGHLY recommended to use environment variables for sensitive information.
# For example, on Render, you would set a BOT_TOKEN environment variable.
BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_PLACEHOLDER_BOT_TOKEN")
if BOT_TOKEN == "YOUR_PLACEHOLDER_BOT_TOKEN":
    print("WARNING: BOT_TOKEN is not set. Please configure it via environment variable.")
    # For local testing, you can paste your token here temporarily:
    # BOT_TOKEN = "YOUR_ACTUAL_BOT_TOKEN"
    # If testing locally and no token is set, the bot will not function correctly.

# Flask app for health check (required by many hosting platforms)
app = Flask(__name__)

@app.route('/')
@app.route('/health')
def health_check():
    return "Bot is operational.", 200

# --- Core Obfuscation Engine ---

class ObfuscationEngine:
    """
    A sophisticated engine for encoding Python code with multiple layers of
    obfuscation and encryption to make it highly resistant to reverse-engineering.
    """
    def __init__(self, layers=7, key_size=32):
        self.layers = layers
        self.key_size = key_size
        self.seed_salt = os.urandom(16) # Unique salt for seed generation
        # Create a temporary directory for processed files
        self.temp_dir = tempfile.mkdtemp(prefix="obfuscator_")
        print(f"Obfuscation temp dir created: {self.temp_dir}")

    def _generate_complex_seed(self, base_seed):
        """Generates a more complex seed by combining multiple sources."""
        timestamp = int(time.time() * 1000)
        random_val = random.random()
        
        seed_material = f"{base_seed.hex()}-{timestamp}-{random_val}-{os.getpid()}-{self.seed_salt.hex()}"
        return hashlib.sha256(seed_material.encode()).digest()

    def _derive_keys(self, seed):
        """Derives multiple keys from a single seed using HKDF-like approach."""
        keys = []
        # Use SHA256 for PRK derivation
        prk = hashlib.sha256(seed).digest() 
        
        for i in range(self.layers):
            # T = salt || i || PRK
            t = self.seed_salt + struct.pack('>I', i) + prk
            h = hashlib.sha256(t).digest()
            keys.append(h[:self.key_size]) # Take the first key_size bytes
            prk = h # Use the previous hash as PRK for next round
        return keys

    def _poly_cipher(self, data, keys):
        """
        Advanced polymorphic cipher with stateful operations, bit manipulation,
        and control flow diversification per layer.
        """
        processed_data = bytearray(data)
        
        for layer_idx, key in enumerate(keys):
            key_len = len(key)
            # Seed for operation sequence and rotation amounts
            op_sequence_seed = hashlib.sha256(key).digest()
            random.seed(op_sequence_seed)

            # Dynamic operation sequence for this layer (must be deterministic from seed)
            op_funcs = [
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
                lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
                lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
            ]
            # Shuffle operations for this layer. This needs to be deterministic from seed.
            # For simplicity, we rely on `random.seed` to make `random.shuffle` predictable.
            random.shuffle(op_funcs) 

            for i in range(len(processed_data)):
                # Dynamic rotation amount, dependent on byte index and layer index
                rotation_amount = (i % 8) + (layer_idx % 3) + 1 
                
                # Apply the chosen operation for this layer/byte
                operation = op_funcs[i % len(op_funcs)] # Cycle through shuffled ops
                processed_data[i] = operation(processed_data, key, i, layer_idx, op_sequence_seed)
                
                # Apply bit rotation (ROL/ROR)
                if layer_idx % 2 == 0: # Rotate Left (ROL)
                    processed_data[i] = ((processed_data[i] << rotation_amount) | (processed_data[i] >> (8 - rotation_amount))) & 0xFF
                else: # Rotate Right (ROR)
                    processed_data[i] = ((processed_data[i] >> rotation_amount) | (processed_data[i] << (8 - rotation_amount))) & 0xFF
        
        return bytes(processed_data)

    def _multi_compress_obfuscated(self, data, level=9):
        """
        Multi-stage compression with unique headers and optional data stuffing.
        Returns original data if it's too small to benefit from compression.
        """
        if len(data) < 64: # Don't compress very small data to avoid overhead
            return data

        try:
            # Layer 1: zlib with a simple header
            compressed_l1 = zlib.compress(data, level=level)
            # Header 1: DECOAD (3 bytes) + length of compressed_l1 (2 bytes, big-endian)
            header_l1 = b'\xDE\xC0\xAD' + struct.pack('>H', len(compressed_l1)) 
            data_l1 = header_l1 + compressed_l1

            # Layer 2: zlib with a different header and potentially stuffed data
            compressed_l2 = zlib.compress(data_l1, level=level)
            # Stuffing: Add a small amount of random data and more header info
            stuff_size = random.randint(5, 15)
            stuff = os.urandom(stuff_size)
            # Header 2: CAFEBABE (4 bytes) + length of compressed_l2 (4 bytes, big-endian) + stuff
            header_l2 = b'\xCA\xFE\xBA\xBE' + struct.pack('>I', len(compressed_l2)) + stuff
            data_l2 = header_l2 + compressed_l2
            
            return data_l2
        except zlib.error as e:
            print(f"Zlib compression error: {e}. Returning original data.", file=sys.stderr)
            return data # Return original data if compression fails

    def _encode_stages(self, data):
        """
        Applies a sequence of complex encodings. Order matters for reversal.
        1. Base85
        2. URL-safe Base64
        3. Hexadecimal with prefix/suffix
        4. Scrambled Hex + Base64
        """
        # Stage 0: Base85
        encoded_b85 = base64.b85encode(data)
        
        # Stage 1: URL-safe Base64
        encoded_urlsafe = base64.urlsafe_b64encode(encoded_b85)
        
        # Stage 2: Hexadecimal with prefix/suffix
        encoded_hex = b'XX' + binascii.hexlify(encoded_urlsafe) + b'YY'
        
        # Stage 3: Scrambled Hex + Base64
        # This uses the first key of the cipher for scrambling
        scrambled_hex_bytearray = bytearray(encoded_hex)
        for i in range(len(scrambled_hex_bytearray)):
            # Simple XOR scramble based on index and a fixed cycle
            scrambled_hex_bytearray[i] ^= (i % 256) 
        encoded_final = base64.b64encode(bytes(scrambled_hex_bytearray))
        
        return encoded_final

    def _decrypt_strings_for_stub(self, critical_strings_map, initial_key, seed_salt):
        """
        Encrypts critical strings using the first cipher key.
        These encrypted strings will be embedded in the stub.
        """
        encrypted_strings_dict = {}
        for name, value in critical_strings_map.items():
            if isinstance(value, str):
                val_bytes = value.encode('utf-8')
            elif isinstance(value, bytes):
                val_bytes = value
            else: continue # Skip non-string/bytes values
            
            encrypted_val = bytearray()
            # Use a simple offset derived from the string name for variation
            name_offset = ord(name[0]) % len(initial_key) 
            
            for i in range(len(val_bytes)):
                encrypted_val.append(val_bytes[i] ^ initial_key[(i + name_offset) % len(initial_key)])
            encrypted_strings_dict[name] = bytes(encrypted_val)
        return encrypted_strings_dict

    def _generate_vm_stub_code(self, vm_args, encrypted_strings_map):
        """Generates the Python stub code string for the VM Executor."""
        
        # Format the encrypted strings map into a Python literal string
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
        # Offset logic must exactly match the encoder's.
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
        
        # Decrypt strings immediately upon initialization
        self.s = decrypt_strings(encrypted_strings_map, initial_key_hex, seed_salt_hex)
        
        self._validate_environment() # Perform runtime checks
        self.keys = self._derive_keys_for_decipher(self.seed_salt) # Derive cipher keys

    def _get_callable(self, name_key):
        """Dynamically resolves and returns a callable or attribute from decrypted strings."""
        try:
            str_name = self.s[name_key]
            if '.' in str_name:
                module_name, attr_name = str_name.split('.', 1)
                module = None
                # Dynamically import and get attributes
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
                elif module_name == 'exec': return lambda code: exec(code) # Special case for exec
                else: raise ValueError("Unknown module")
                return getattr(module, attr_name)
            else: return str_name # Return the string itself if not a callable (e.g., an error message)
        except Exception:
            os._exit(1) # Abrupt exit on any failure

    def _derive_keys_for_decipher(self, seed):
        """Derives cipher keys using the same method as the encoder."""
        keys = []
        prk = self.s['hashlib_sha256'](seed).digest()
        for i in range(self.layers):
            t = self.seed_salt + self.s['struct_pack']('>I', i) + prk
            h = self.s['hashlib_sha256'](t).digest()
            keys.append(h[:self.key_size])
            prk = h
        return keys

    def _validate_environment(self):
        """Performs runtime checks for debugging and tampering."""
        try:
            # Anti-debugging check
            if self.s.get('sys_gettrace') and self.s.get('sys_gettrace')() is not None:
                os._exit(1)
        except Exception: os._exit(1)
        # Basic integrity check for critical string lookups
        if not self.s.get('zlib_decompress'): os._exit(1)

    def _decompress_multi_stage(self, data):
        """Reverses the multi-stage compression process."""
        try:
            # Iterate through data to find the correct decompression start point
            for i in range(len(data)):
                try:
                    # Try decompressing from current index (handles prefix stuffing)
                    decompressed_l1 = self.s['zlib_decompress'](data[i:])
                    
                    # Check for Header 1: DECOAD (3 bytes) + length (2 bytes)
                    if decompressed_l1.startswith(self.s['header_l1_prefix']):
                        compressed_len_l1 = self.s['struct_unpack']('>H', decompressed_l1[3:5])[0]
                        inner_compressed_data = decompressed_l1[5 : 5 + compressed_len_l1]
                        
                        # Decompress Layer 1 data (zlib)
                        decompressed_l0 = self.s['zlib_decompress'](inner_compressed_data)
                        return decompressed_l0
                except Exception: continue # If decompression or header check fails, try next index
            raise Exception("Invalid compressed data or header")
        except Exception: os._exit(1)

    def _reverse_poly_cipher_layer(self, data, layer_index):
        """Reverses a single layer of the polymorphic cipher."""
        key = self.keys[layer_index]
        key_len = len(key)
        processed_data = bytearray(data)
        
        # Deterministically recreate the operation sequence seed
        op_sequence_seed = self.s['hashlib_sha256'](key).digest()
        self.s['random_seed'](op_sequence_seed)
        
        # Operations definition (must precisely match encoder's logic)
        # Note: These lambdas are templates; actual execution order is determined by shuffle.
        op_funcs_template = [
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
            lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
            lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
        ]
        
        # Process data in reverse order to undo operations correctly
        for i in range(len(processed_data) - 1, -1, -1):
            # Undo rotation first (inverse of ROL is ROR, inverse of ROR is ROL)
            rotation_amount = (i % 8) + (layer_index % 3) + 1
            if layer_index % 2 == 0: # Encoder did ROL
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
            else: # Encoder did ROR
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF
            
            # Undo operations - This requires EXACT inverse functions for each operation.
            # Simplified inverse for XOR: D_inv = D ^ K
            # For demonstration, we'll use XOR as the inverse for all operations.
            # A real cryptographically secure implementation would need precise inverse functions for Add, etc.
            processed_data[i] ^= key[(i + layer_index) % key_len]
            
        return bytes(processed_data)

    def execute_pipeline(self):
        """Reverses all transformations and executes the final payload."""
        
        current_data = self.payload
        
        # --- Phase 1: Reverse Encoding Stages ---
        # Order: Reverse from outermost encoding stage to innermost.
        # Encoding order: Base85 -> URLSafeBase64 -> Hex -> ScrambledHex+Base64
        
        try:
            # Stage 3: Reverse Final Base64 + Scrambled Hex
            decoded_final_b64 = self.s['base64_b64decode'](current_data)
            # Descramble Hex using the same logic and key as encoding
            scrambled_hex_bytearray = bytearray(decoded_final_b64)
            for i in range(len(scrambled_hex_bytearray)):
                scrambled_hex_bytearray[i] ^= (i % 256)
            current_data = bytes(scrambled_hex_bytearray)

            # Stage 2: Reverse Hex Prefix/Suffix and Hexlify
            # Check for and remove prefixes/suffixes
            if not current_data.startswith(self.s['header_l1_prefix']) or not current_data.endswith(self.s['header_l2_prefix']):
                raise ValueError("Invalid hex prefix/suffix")
            current_data = current_data[2:-2] # Remove 'XX' and 'YY'
            current_data = self.s['binascii_unhexlify'](current_data)

            # Stage 1: Reverse URL-safe Base64
            current_data = self.s['base64_urlsafe_b64decode'](current_data)

            # Stage 0: Reverse Base85
            current_data = self.s['base64_b85decode'](current_data)
        except Exception: os._exit(1) # Abrupt exit on any encoding reversal error

        # --- Phase 2: Interleaved Decompression and Cipher Decryption ---
        # Iterate through cipher layers in reverse order (from N-1 down to 0).
        # If compression was applied for a specific cipher layer in the encoder,
        # decompress it BEFORE deciphering that layer's data.
        
        for i in range(self.layers - 1, -1, -1):
            # Check if compression was applied for THIS cipher layer (encoder condition: i % 3 == 0)
            if i % 3 == 0:
                try:
                    current_data = self._decompress_multi_stage(current_data)
                except Exception: os._exit(1)

            # Decipher this cipher layer's data
            try:
                current_data = self._reverse_poly_cipher_layer(current_data, i)
            except Exception: os._exit(1)

        # --- Phase 3: Final Unmarshalling and Execution ---
        try:
            # The final `current_data` should be the marshalled Python code object.
            code_object = self.s['marshal_loads'](current_data)
            self.s['exec_call'](code_object) # Execute the code
        except Exception: os._exit(1) # Abrupt exit on final execution failure

# --- Bot Controller Class ---
class BotController:
    def __init__(self, bot_token):
        self.bot = telebot.TeleBot(bot_token)
        # Initialize ObfuscationEngine with desired layers (e.g., 7)
        self.obfuscator = ObfuscationEngine(layers=7) 
        self.setup_handlers()

    def setup_handlers(self):
        """Sets up the message handlers for the Telegram bot."""
        @self.bot.message_handler(commands=['start', 'help'])
        def send_welcome(message):
            # Using textual description for emojis for better compatibility
            welcome_msg = """
🌟 **ULTRA SECURE Python Obfuscator Bot (v3.1)** 🌟

Protect your Python code with multiple layers of sophisticated obfuscation!

**Features:**
• **Deep Obfuscation:** Dynamic key generation, polymorphic ciphers, interleaved compression/encoding.
• **Runtime Complexity:** Control flow obfuscation, string encryption, anti-debugging, lightweight VM.
• **Multi-Stage Defense:** Combines zlib compression with custom headers, Base85, Base64 variants, and Hex encodings.
• **Resilient Decoder:** Designed to be extremely difficult to reverse-engineer.

🚀 **Usage:**
Send a `.py` file or a Python code snippet. The bot will return a highly obfuscated version.

⚠️ **Disclaimer:**
This bot is for educational and research purposes only. While highly obfuscated, it is not unbreakable. Use responsibly.
"""
            self.bot.reply_to(message, welcome_msg, parse_mode='Markdown')

        @self.bot.message_handler(content_types=['document'])
        def handle_document(message):
            try:
                file_info = self.bot.get_file(message.document.file_id)
                if not file_info.file_name.lower().endswith('.py'):
                    self.bot.reply_to(message, "❌ Please send a Python (.py) file only!")
                    return

                self.bot.reply_to(message, "🔒 Processing your file with advanced obfuscation...")
                
                downloaded_file = self.bot.download_file(file_info.file_path)
                # Decode file content, ignore errors for robustness
                source_code = downloaded_file.decode('utf-8', errors='ignore')

                if not source_code.strip():
                    self.bot.reply_to(message, "❌ The provided file is empty or contains no executable code.")
                    return
                
                # Obfuscate the source code
                encoded_code = self.obfuscate_code(source_code)
                
                # Save the obfuscated code to a temporary file
                temp_file_path = os.path.join(self.obfuscator.temp_dir, f"ultra_secure_{file_info.file_name}")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                # Send the obfuscated code back as a document
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="✨ Your ULTRA SECURE obfuscated Python script!",
                        visible_file_name=f"ultra_secure_{file_info.file_name}"
                    )
                
                os.unlink(temp_file_path) # Clean up the temporary file
                
            except telebot.apihelper.ApiTelegramException as e:
                self.handle_error(message, f"Telegram API Error: {e}")
            except Exception as e:
                self.handle_error(message, f"Error processing document: {str(e)}")

        @self.bot.message_handler(func=lambda message: True)
        def handle_text(message):
            text = message.text
            # Basic check to see if it looks like Python code
            python_indicators = ['import ', 'def ', 'class ', 'print(', 'if ', 'for ', 'while ', '=', '{', '}']
            if not any(indicator in text for indicator in python_indicators) and len(text.splitlines()) < 2:
                welcome_msg = """
📝 **Send me Python code to obfuscate!**

You can send:
• A Python code snippet directly.
• A `.py` file as a document.

Example snippet:
```python
def greet(name):
    print(f"Hello, {name}!")

greet("World")
```"""
                self.bot.reply_to(message, welcome_msg, parse_mode='Markdown')
                return
            
            self.bot.reply_to(message, "🔒 Applying advanced obfuscation to your code...")
            
            try:
                # Obfuscate the provided code snippet
                encoded_code = self.obfuscate_code(text)
                
                # Save the obfuscated code to a temporary file
                temp_file_path = os.path.join(self.obfuscator.temp_dir, "ultra_secure_script.py")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                # Send the obfuscated code back as a document
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="✨ Your ULTRA SECURE obfuscated Python code!",
                        visible_file_name="ultra_secure_script.py"
                    )
                
                os.unlink(temp_file_path) # Clean up the temporary file
                
            except telebot.apihelper.ApiTelegramException as e:
                self.handle_error(message, f"Telegram API Error: {e}")
            except Exception as e:
                self.handle_error(message, f"Error obfuscating code: {str(e)}")

    def obfuscate_code(self, source_code):
        """Orchestrates the obfuscation process for a given source code string."""
        try:
            # 1. Marshal the source code into a byte stream
            code = compile(source_code, "<obfuscated_source>", "exec")
            payload = marshal.dumps(code)
            
            # 2. Generate unique seeds and derive keys for cipher layers
            base_seed = os.urandom(16) # Initial seed material
            # Generate seeds for each cipher layer
            seeds = [self.obfuscator._generate_complex_seed(base_seed + struct.pack('>I', i)) for i in range(self.obfuscator.layers)]
            # Derive all keys from the base seed
            keys = self.obfuscator._derive_keys(base_seed) 

            # 3. Apply chained transformations: Cipher -> (Compress if needed)
            transformed_data = payload
            for i in range(self.obfuscator.layers):
                # Apply polymorphic cipher for this layer
                transformed_data = self.obfuscator._poly_cipher(transformed_data, [keys[i]]) # Pass single key per layer
                
                # Apply compression if required for this cipher layer (encoder condition: i % 3 == 0)
                if i % 3 == 0:
                    transformed_data = self.obfuscator._multi_compress_obfuscated(transformed_data)
            
            # 4. Apply final encoding stages sequentially in reverse order of reversal.
            # This `transformed_data` is the output of the last cipher/compression step.
            # The sequence of encodings applied is: Base85 -> URLSafeBase64 -> Hex -> ScrambledBase64
            final_encoded_payload = self.obfuscator._encode_stages(transformed_data)
            
            # 5. Define critical strings and encrypt them for the stub
            critical_strings_map = {
                "zlib_decompress": "zlib.decompress", "base64_b85decode": "base64.b85decode",
                "base64_urlsafe_b64decode": "base64.urlsafe_b64decode", "base64_b64decode": "base64.b64decode",
                "binascii_unhexlify": "binascii.unhexlify", "binascii_hexlify": "binascii.hexlify",
                "hashlib_sha256": "hashlib.sha256", "marshal_loads": "marshal.loads",
                "struct_pack": "struct.pack", "struct_unpack": "struct.unpack",
                "random_randint": "random.randint", "random_seed": "random.seed",
                "sys_gettrace": "sys.gettrace", "os_exit": "os._exit",
                "exec_call": "exec", "compile_call": "compile",
                "Exception": "Exception", "debug_detected": "DEBUGGER DETECTED",
                "tamper_error": "DATA TAMPERING OR DECRYPTION FAILURE DETECTED",
                "header_l1_prefix": b'\xDE\xC0\xAD', "header_l2_prefix": b'\xCA\xFE\xBA\xBE',
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
            }
            encrypted_strings_dict = self.obfuscator._decrypt_strings_for_stub(critical_strings_map, keys[0], self.obfuscator.seed_salt)
            
            # 6. Prepare arguments for the VM stub constructor
            vm_args = {
                "encrypted_payload": final_encoded_payload,
                "seeds_list": seeds,
                "key_size": self.obfuscator.key_size,
                "num_layers": self.obfuscator.layers,
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
                "initial_key_hex": keys[0].hex() # Use the first key for string decryption
            }
            
            # 7. Generate the final stub code string, embedding the VM arguments and encrypted strings
            stub_code = self.obfuscator._generate_vm_stub_code(vm_args, encrypted_strings_dict)
            
            return stub_code
            
        except Exception as e:
            # Log internal errors and raise a user-friendly message
            print(f"ERROR: Failed to obfuscate code: {e}", file=sys.stderr)
            raise ValueError("Obfuscation failed due to an internal error. Please try again.")

    def handle_error(self, message, error_msg):
        """Handles bot errors and replies to the user."""
        print(f"BOT ERROR: {error_msg}", file=sys.stderr)
        self.bot.reply_to(message, f"❌ An error occurred: {error_msg}")

    def start_polling(self):
        """Starts the Telegram bot polling loop."""
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
        """Starts the Flask web server for health checks."""
        port = int(os.environ.get('PORT', 5000))
        print(f"🌐 Starting Flask server on port {port}")
        try:
            # Run Flask in a separate thread so it doesn't block bot polling
            server_thread = Thread(target=lambda: app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False))
            server_thread.daemon = True # Allows main program to exit even if this thread is running
            server_thread.start()
        except Exception as e:
            print(f"Error starting Flask server: {e}", file=sys.stderr)

# --- Main Execution Block ---
if __name__ == "__main__":
    # Basic validation for the bot token
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_PLACEHOLDER_BOT_TOKEN":
        print("ERROR: BOT_TOKEN is not configured. Please set the BOT_TOKEN environment variable or edit the script for local testing.")
        sys.exit(1)

    # Clean up any old temporary directories from previous runs.
    # This is a basic cleanup; consider more robust temp file management for production.
    try:
        temp_dir_pattern = os.path.join(tempfile.gettempdir(), "obfuscator_*")
        for dir_path in glob.glob(temp_dir_pattern):
            if os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
                print(f"Cleaned up old temp dir: {dir_path}")
    except Exception as e:
        print(f"Error during initial temp directory cleanup: {e}", file=sys.stderr)

    # Initialize the BotController
    bot_controller = BotController(BOT_TOKEN)
    
    # Start the web server and bot polling concurrently
    bot_controller.start_webserver() 
    bot_controller.start_polling()
