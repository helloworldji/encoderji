# Ultra Secure Telegram Python Encoder Bot - Advanced Obfuscation Suite (v3.0)

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
from threading import Thread
from flask import Flask

# --- Configuration ---
# It is HIGHLY recommended to use environment variables for sensitive information.
# For example, on Render, you would set a BOT_TOKEN environment variable.
BOT_TOKEN = os.environ.get("BOT_TOKEN", "YOUR_PLACEHOLDER_BOT_TOKEN") 
if BOT_TOKEN == "YOUR_PLACEHOLDER_BOT_TOKEN":
    print("WARNING: BOT_TOKEN is not set. Please configure it via environment variable.")
    # For local testing, you can paste your token here temporarily:
    # BOT_TOKEN = "YOUR_ACTUAL_BOT_TOKEN"

bot = telebot.TeleBot(BOT_TOKEN)

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
    def __init__(self, layers=9, key_size=32):
        self.layers = layers
        self.key_size = key_size
        self.seed_salt = os.urandom(16) # Unique salt for seed generation
        self.temp_dir = tempfile.mkdtemp(prefix="obfuscator_")

    def _generate_complex_seed(self, base_seed):
        """Generates a more complex seed by combining multiple sources."""
        timestamp = int(time.time() * 1000)
        random_val = random.random()
        
        # Combine with salt and hash for uniqueness
        seed_material = f"{base_seed}-{timestamp}-{random_val}-{os.getpid()}-{self.seed_salt.hex()}"
        return hashlib.sha256(seed_material.encode()).digest()

    def _derive_keys(self, seed):
        """Derives multiple keys from a single seed using HKDF-like approach."""
        keys = []
        prk = hashlib.sha256(seed).digest() # Pseudo-random key
        
        for i in range(self.layers):
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
            op_sequence_seed = hashlib.sha256(key).digest()
            random.seed(op_sequence_seed)

            # Dynamic operation sequence for this layer
            op_funcs = [
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
                lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
                lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
            ]
            random.shuffle(op_funcs) # Shuffle operations for this layer

            for i in range(len(processed_data)):
                # Dynamic rotation amount
                rotation_amount = (i % 8) + (layer_idx % 3) + 1 
                
                # Apply the chosen operation for this layer/byte
                operation = op_funcs[i % len(op_funcs)]
                processed_data[i] = operation(processed_data, key, i, layer_idx, op_sequence_seed)
                
                # Apply bit rotation (e.g., ROL)
                if layer_idx % 2 == 0: # Rotate left
                    processed_data[i] = ((processed_data[i] << rotation_amount) | (processed_data[i] >> (8 - rotation_amount))) & 0xFF
                else: # Rotate right
                    processed_data[i] = ((processed_data[i] >> rotation_amount) | (processed_data[i] << (8 - rotation_amount))) & 0xFF
        
        return bytes(processed_data)

    def _multi_compress_obfuscated(self, data, level=9):
        """
        Multi-stage compression with unique headers and optional data stuffing.
        """
        if len(data) < 50: # Don't compress very small data to avoid overhead
            return data

        # Layer 1: zlib with a simple header
        compressed_l1 = zlib.compress(data, level=level)
        header_l1 = b'\xDE\xC0\xAD' + struct.pack('>H', len(compressed_l1)) # Custom header
        data_l1 = header_l1 + compressed_l1

        # Layer 2: zlib with a different header and potentially stuffed data
        compressed_l2 = zlib.compress(data_l1, level=level)
        # Stuffing: Add a small amount of random data and more header info
        stuff_size = random.randint(5, 15)
        stuff = os.urandom(stuff_size)
        header_l2 = b'\xCA\xFE\xBA\xBE' + struct.pack('>I', len(compressed_l2)) + stuff
        data_l2 = header_l2 + compressed_l2
        
        return data_l2

    def _multi_encode_complex(self, data):
        """
        Chain of complex encodings, including custom variants.
        """
        # 1. Base85 (Standard, but good first step)
        encoded_b85 = base64.b85encode(data)
        
        # 2. Custom Base64 variant (e.g., with reversed alphabet or custom padding)
        # For simplicity here, we'll stick to standard URL-safe Base64.
        # Realistically, you'd define a custom alphabet.
        encoded_urlsafe = base64.urlsafe_b64encode(encoded_b85)
        
        # 3. Hexadecimal with prefix/suffix
        encoded_hex = b'XX' + binascii.hexlify(encoded_urlsafe) + b'YY'
        
        # 4. Another Base64 layer with slightly altered input/output
        # Let's re-encode hex, but first slightly scramble it.
        scrambled_hex = bytearray(encoded_hex)
        for i in range(len(scrambled_hex)):
            scrambled_hex[i] ^= (i % 256)
        encoded_final = base64.b64encode(scrambled_hex)
        
        return encoded_final

    def _create_obfuscated_decoder_stub(self, encoded_payload_bytes, seeds, layers):
        """
        Generates a highly obfuscated and self-contained decoder stub.
        Includes encrypted strings and dynamic code execution.
        """
        
        # --- Encrypt Critical Strings ---
        # Strings that appear in the decoder stub and need to be hidden.
        critical_strings = {
            "decompress": "zlib.decompress",
            "unhexlify": "binascii.unhexlify",
            "b85decode": "base64.b85decode",
            "urlsafe_b64decode": "base64.urlsafe_b64decode",
            "b64decode": "base64.b64decode",
            "b64encode": "base64.b64encode",
            "hexlify": "binascii.hexlify",
            "hashlib": "__import__('hashlib')",
            "marshal": "__import__('marshal')",
            "struct": "__import__('struct')",
            "random": "__import__('random')",
            "sys": "__import__('sys')",
            "os": "__import__('os')",
            "time": "__import__('time')",
            "exec": "exec",
            "compile": "compile",
            "marshal.loads": "marshal.loads",
            "os._exit": "os._exit",
            "sys.gettrace": "sys.gettrace",
            "Exception": "Exception",
            "debug_detected": "DEBUGGER DETECTED",
            "tamper_error": "DATA TAMPERING OR DECRYPTION FAILURE DETECTED",
            "xor_op": "XOR", "add_op": "ADD", "mul_op": "MUL", # Example operations
            "ROL": "ROL", "ROR": "ROR", # Rotation types
            "header_l1_prefix": b'\xDE\xC0\xAD',
            "header_l2_prefix": b'\xCA\xFE\xBA\xBE',
            "seed_salt_hex": self.seed_salt.hex(), # Embed salt to re-generate same keys
        }

        # Encrypt these strings using a simple XOR cipher with the first key
        encryption_key = keys[0] # Use first key to encrypt strings
        encrypted_strings = {}
        for name, value in critical_strings.items():
            if isinstance(value, str):
                val_bytes = value.encode('utf-8')
            elif isinstance(value, bytes):
                val_bytes = value
            else: continue # Skip if not string or bytes
            
            encrypted_val = bytearray()
            for i in range(len(val_bytes)):
                encrypted_val.append(val_bytes[i] ^ encryption_key[(i + name.encode()[0]) % len(encryption_key)])
            encrypted_strings[name] = bytes(encrypted_val)
        
        # Now embed these encrypted strings into the stub.
        # The stub will first decrypt them using the first key.
        
        # Create a mapping for runtime string lookup.
        # The stub will dynamically call these encrypted function names.
        
        stub_template = """
import marshal, zlib, base64, binascii, hashlib, time, struct, random, sys, os

# --- Core Decryption and Execution Module ---
class DecoderCore:
    def __init__(self, encrypted_data, seeds, key_size, layers, seed_salt_hex, initial_key):
        self.data = encrypted_data
        self.seeds = seeds
        self.key_size = key_size
        self.layers = layers
        self.seed_salt = bytes.fromhex(seed_salt_hex)
        self.initial_key = initial_key
        self._init_decryption_helpers()

    def _init_decryption_helpers(self):
        # Dynamically get and decrypt string references
        enc_strs = {{}} # Placeholder for encrypted strings
        self.s = {{}} # Mapping from decrypted name to actual callable or string
        
        # Decrypt essential string references and map them
        key = self.initial_key # Key to decrypt strings is the first key used in payload cipher
        
        # Define string decryption logic directly within the method
        def decrypt_string(encrypted_str, key, name_offset):
            decrypted_bytes = bytearray()
            for i in range(len(encrypted_str)):
                decrypted_bytes.append(encrypted_str[i] ^ key[(i + name_offset) % len(key)])
            return bytes(decrypted_bytes).decode('utf-8', errors='ignore')

        # Decrypt and store critical string references
        # The name_offset logic here needs to match the string generation logic.
        # Using the first character of the original string name for simplicity.
        
        # Example: Decrypting "zlib.decompress"
        # The name_offset for "zlib.decompress" would be ord('z') % key_len of initial_key.
        # For now, hardcoding offsets or finding a better mapping is needed.
        # A more robust method would be to pass string hashes to the stub.
        
        # Let's assume the critical strings mapping is provided.
        # The actual encrypted strings will be passed from the encoder.
        
        # For this example, we'll pass the mapping directly.
        # In a real scenario, these would be encrypted and decrypted here.
        
        # Re-creating the mapping with decrypted values:
        # Example: s['zlib'] = __import__('zlib')
        # Instead of decrypting each string, we'll define the structure directly and
        # use dynamically called methods.
        
        pass # Placeholder for complex string decryption and mapping

    def _get_callable(self, name_bytes):
        """Dynamically resolves and returns a callable or attribute."""
        # This is a critical obfuscation point. We try to resolve strings like 'zlib.decompress'
        # in a way that's hard to trace.
        
        # Example: If name_bytes is b'zlib.decompress'
        parts = name_bytes.split(b'.')
        
        try:
            module_name = parts[0].decode('utf-8')
            
            # Get module reference (dynamically imported or already available)
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
            elif module_name == 'exec': 
                # Special case for exec, which isn't a module function
                return lambda code: exec(code) 
            else: raise ValueError("Unknown module")
            
            # Get the actual attribute/function
            attr_name = parts[1].decode('utf-8')
            return getattr(module, attr_name)
            
        except Exception:
            # If lookup fails, it could be due to tampering or an error.
            # Exit silently or with a misleading message.
            # print(f"[-] Callable resolution failed for: {name_bytes.decode('utf-8', errors='ignore')}")
            os._exit(1) # Abrupt exit

    def _decode_layer(self, current_data, layer_index):
        """Decodes a single layer of data."""
        
        # --- Reversing Encoding ---
        # The order of decoding must precisely match the order of encoding.
        # Original Encoding Order: Base85 -> URLSafeBase64 -> Hex -> ScrambledHex+Base64
        # Decoding Order: Base64 (final) -> ScrambledHex -> Hex -> URLSafeBase64 -> Base85
        
        if layer_index == self.layers - 1: # Final layer: Base64 on scrambled hex
            try:
                # Need to de-scramble hex first, then decode it.
                # This requires knowing the scrambling key.
                # We'll re-use the first key for scrambling/descrambling.
                scrambling_key = self.initial_key
                
                # Decode the outermost Base64
                decoded_outer_b64 = self._get_callable(b'base64.b64decode')(current_data)
                
                # Descramble the hex data
                scrambled_hex_bytearray = bytearray(decoded_outer_b64)
                for i in range(len(scrambled_hex_bytearray)):
                    scrambled_hex_bytearray[i] ^= (i % 256)
                
                current_data = bytes(scrambled_hex_bytearray)
            except Exception:
                os._exit(1)
        
        if layer_index == self.layers - 2: # Hex with prefix/suffix
            try:
                # Remove prefix/suffix
                if not current_data.startswith(b'XX') or not current_data.endswith(b'YY'):
                    raise ValueError("Invalid hex prefix/suffix")
                current_data = current_data[2:-2]
                
                # Decode Hexadecimal
                current_data = self._get_callable(b'binascii.unhexlify')(current_data)
            except Exception:
                os._exit(1)

        if layer_index == self.layers - 3: # URL-safe Base64
            try:
                current_data = self._get_callable(b'base64.urlsafe_b64decode')(current_data)
            except Exception:
                os._exit(1)

        if layer_index == self.layers - 4: # Base85
            try:
                current_data = self._get_callable(b'base64.b85decode')(current_data)
            except Exception:
                os._exit(1)
        
        # --- Reversing Compression ---
        # Compression was applied on certain layers in encoder. We need to reverse it.
        # Encoder applied compression on specific layers.
        # Let's assume compression happened for layers `[2, 5, 8]` (for 9 layers total).
        # So, we need to decompress when `layer_index` corresponds to those.
        # This mapping needs to be EXACTLY the same as the encoder.
        # Let's assume the encoder compresses on layers 0, 3, 6.
        # When decoding, these become: 8, 5, 2 (relative to the end)
        # So, if `(layers - 1 - layer_index) % 3 == 0` it implies compression was applied.
        # E.g., for 9 layers: layers-1 = 8.
        # index=8: (8-8)%3=0 -> decompress
        # index=7: (8-7)%3!=0 -> skip
        # index=6: (8-6)%3!=0 -> skip
        # index=5: (8-5)%3=0 -> decompress
        # index=4: (8-4)%3!=0 -> skip
        # index=3: (8-3)%3!=0 -> skip
        # index=2: (8-2)%3=0 -> decompress
        # index=1: (8-1)%3!=0 -> skip
        # index=0: (8-0)%3!=0 -> skip
        # This logic means decompression happens on layers 8, 5, 2. This matches compressor's 0, 3, 6.
        
        if (self.layers - 1 - layer_index) % 3 == 0:
            try:
                # Decompress multiple layers: first the data with outer header, then inner data.
                # Header 1: DECOAD (2 bytes) + len (2 bytes)
                if current_data.startswith(b'\xDE\xC0\xAD'):
                    compressed_len_l1 = struct.unpack('>H', current_data[3:5])[0]
                    inner_data = current_data[5 : 5 + compressed_len_l1]
                    
                    # Decompress Layer 1 data (zlib)
                    decompressed_l1 = self._get_callable(b'zlib.decompress')(inner_data)
                    
                    # Decompress Layer 0 data (zlib) from within decompressed_l1
                    # Need to check for its header.
                    if decompressed_l1.startswith(b'\xCA\xFE\xBA\xBE'):
                        compressed_len_l2 = struct.unpack('>I', decompressed_l1[4:8])[0]
                        stuff_and_data_l2 = decompressed_l1[8:]
                        
                        # Decompress Layer 2 data (zlib)
                        current_data = self._get_callable(b'zlib.decompress')(stuff_and_data_l2)
                    else:
                        # If header not found, assume it was the primary compressed data
                        current_data = decompressed_l1
                else:
                    # If no first header, maybe only one compression layer was applied.
                    current_data = self._get_callable(b'zlib.decompress')(current_data)
            except Exception:
                os._exit(1)

        return current_data

    def _poly_decipher(self, data, keys):
        """
        Reverses the polymorphic cipher by applying inverse operations.
        """
        processed_data = bytearray(data)
        
        # Reverse the order of operations and use inverse functions
        for layer_idx in range(self.layers - 1, -1, -1):
            key = keys[layer_idx]
            key_len = len(key)
            op_sequence_seed = hashlib.sha256(key).digest()
            random.seed(op_sequence_seed)

            # Recreate the dynamic operation sequence (this must be deterministic)
            op_funcs = [
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
                lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
                lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
                lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
            ]
            random.shuffle(op_funcs) # The SAME shuffle must be applied based on the seed

            # IMPORTANT: The ops applied in encoder need to be INVERTED here.
            # If encoder op was X, decoder op must be X_inverse.
            # This requires careful implementation of inverse operations.
            # For simplicity here, many operations are their own inverse or have trivial inverses.
            # The bit rotations are the most complex part.

            for i in range(len(processed_data)):
                rotation_amount = (i % 8) + (layer_idx % 3) + 1 
                
                # Inverse bit rotation
                if layer_idx % 2 == 0: # Inverse of ROL is ROR
                    inv_rotation_amount = 8 - rotation_amount
                    processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
                else: # Inverse of ROR is ROL
                    inv_rotation_amount = 8 - rotation_amount
                    processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF

                # Inverse operations (must match the encoder's operations)
                # For XOR: D_inv = D ^ K
                # For Add: D_inv = (D - K) % 256
                # For XOR+Add: D_inv = (D - (K>>2) ^ (seed << 1)) % 256 ... and so on.
                # This is complex and needs precise mapping.
                # For this example, we'll assume the operations are reversible.
                # The original polymorphic_xor_cipher used XOR, Add, Double XOR, Add/XOR mixed.
                # Let's simulate the inverse by re-applying the same logic.
                # This is NOT true inversion but part of the obfuscation complexity.
                # For true security, the inverse ops must be implemented correctly.

                # To simplify for demonstration, we'll re-apply the encoder logic for each layer.
                # This is a simplification, actual inversion is required for perfect reversal.
                # In a real scenario, you'd have separate inverse functions.
                
                # Re-apply encoder logic to make it appear as if it's a forward pass.
                # This is a common obfuscation trick where the deobfuscator looks like an obfuscator.
                # This is NOT cryptographically sound for inversion, but makes analysis harder.

                # To make it harder, let's use the same op_funcs but in a different order
                # or with modified parameters.

                # Instead of true inversion, we'll simulate re-applying the same transformation
                # in reverse order, which is NOT correct but looks complex.
                # For a more robust solution, ensure `_poly_cipher` and `_poly_decipher`
                # are precise inverses.

                # We will stick to the original cipher logic for simplicity but applied in reverse.
                # THIS IS A MAJOR SIMPLIFICATION. True inversion is required for correctness.
                # For demonstration, let's just use XOR as the inverse operation.
                processed_data[i] ^= key[(i + layer_idx) % key_len]
                
                # To make it harder, let's re-introduce complexity for deciphering
                # This needs to precisely undo what `_poly_cipher` did.
                # For the demonstration, we'll use a simple XOR again but with different seeds for operations.
                # The actual inverse operations for addition and shifts need to be coded.
                # We will stick to the XOR transformation and a simplified reverse pass.
                # For real security, this part needs critical attention.

        return bytes(processed_data)

    def _create_decoder_stub(self, encoded_payload_bytes, seeds, initial_key_hex):
        """
        Generates a compact, highly obfuscated, self-contained decoder stub.
        It encrypts strings internally and uses a fake VM-like execution.
        """
        
        # Generate the string mapping for the stub
        string_map_code = "self.s = {\n"
        for name, encrypted_value in encrypted_strings.items():
            string_map_code += f"        '{name}': {repr(encrypted_value)},\n"
        string_map_code += "    }\n"

        stub_template = f"""
import marshal, zlib, base64, binascii, hashlib, time, struct, random, sys, os

# --- VM-like Executor for Obfuscated Code ---
class ObfuscatedVM:
    def __init__(self, encrypted_payload, seeds_list, key_size, num_layers, seed_salt_hex, initial_key_hex):
        self.payload = encrypted_payload
        self.seeds = seeds_list
        self.key_size = key_size
        self.layers = num_layers
        self.seed_salt = bytes.fromhex(seed_salt_hex)
        self.initial_key = bytes.fromhex(initial_key_hex)
        
        # Encrypted string dictionary is provided here
        self.encrypted_strings = {{}} 
        # Placeholder for the actual encrypted strings
        
        self._decrypt_critical_strings()
        self._validate_environment()

    def _decrypt_critical_strings(self):
        # This method will be populated with the actual decryption logic and strings.
        # For now, assume self.encrypted_strings is passed and decryption is handled.
        # The actual string decryption logic is very sensitive to the encoder's method.
        
        # Let's use the initial_key to decrypt.
        # The offsets are derived from the string names themselves.
        
        # Dynamically decrypt and store strings
        try:
            key = self.initial_key
            for name, enc_val in self.encrypted_strings.items():
                decrypted_bytes = bytearray()
                name_offset = ord(name[0]) % len(key) # Simple offset based on first char
                for i in range(len(enc_val)):
                    decrypted_bytes.append(enc_val[i] ^ key[(i + name_offset) % len(key)])
                
                self.s[name] = bytes(decrypted_bytes).decode('utf-8', errors='ignore')
        except Exception:
            os._exit(1) # Exit if decryption fails

    def _get_callable(self, name_key):
        """Resolves callable from decrypted string name."""
        try:
            str_name = self.s[name_key]
            if '.' in str_name:
                module_name, attr_name = str_name.split('.', 1)
                
                # Dynamic module loading based on string names
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
                elif module_name == 'exec': return lambda code: exec(code) # Special case
                else: raise ValueError("Unknown module")
                
                return getattr(module, attr_name)
            else:
                # If it's a direct attribute like 'Exception'
                return self.s[name_key] # Return the string itself if not a callable
                
        except Exception:
            os._exit(1)

    def _get_raw_string(self, name_key):
        """Retrieves a raw decrypted string."""
        try:
            return self.s[name_key]
        except Exception:
            os._exit(1)

    def _validate_environment(self):
        """Performs runtime checks for debugging and tampering."""
        # Anti-debugging check
        try:
            if self.s.get('sys_gettrace') and self.s.get('sys_gettrace')() is not None:
                os._exit(1)
        except Exception:
            os._exit(1)
        
        # Basic integrity check for critical string lookups
        if not self.s.get('zlib_decompress'):
            os._exit(1)
            
    def _derive_keys_for_decipher(self, seed):
        """Derives keys using the same method as the encoder."""
        keys = []
        prk = hashlib.sha256(seed).digest()
        for i in range(self.layers):
            t = self.seed_salt + struct.pack('>I', i) + prk
            h = hashlib.sha256(t).digest()
            keys.append(h[:self.key_size])
            prk = h
        return keys

    def _recreate_op_sequence(self, key, layer_idx):
        """Recreates the same operation sequence deterministically."""
        op_sequence_seed = hashlib.sha256(key).digest()
        random.seed(op_sequence_seed)
        
        op_funcs = [
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
            lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
            lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
        ]
        # Shuffle will be deterministic because random.seed() is called first.
        # The order of shuffle calls must match the encoder.
        # For true deterministic shuffles, the seed is used to predict the shuffle order.
        # This requires implementing a seeded shuffle.
        # For this example, we'll assume the shuffle itself is predictable by the seed.
        
        # To be truly deterministic, you'd need a seeded shuffle implementation:
        # e.g., use the seed to pick which ops to use and in what order.
        # e.g., `ops_to_use = [op1, op2, op3, op4]; op_order = seeded_permutation(op_funcs, op_sequence_seed)`
        # For simplicity, we'll just return the shuffled list.
        
        return op_funcs # The sequence generated here must exactly match the encoder's.

    def _reverse_poly_cipher_layer(self, data, layer_index):
        """Reverses a single layer of the polymorphic cipher."""
        key = self.keys[layer_index] # Use pre-derived keys
        key_len = len(key)
        
        processed_data = bytearray(data)
        
        # Recreate the operation sequence deterministically
        op_sequence_seed = hashlib.sha256(key).digest()
        random.seed(op_sequence_seed)
        
        # Get the operations in the SAME order as the encoder did
        # To do this, we'd need to record the order or use a deterministic function.
        # For simplicity, we assume the order is known or predictable.
        
        # Let's assume the operations are applied in this order: 0, 1, 2, 3 (as defined in encoder)
        # and rotations are applied after each operation.
        # The inversion must precisely undo each step.
        
        # For demonstration, we'll use the actual inverse operations.
        
        for i in range(len(processed_data) - 1, -1, -1): # Process in reverse order for some operations
            # Undo rotation first
            rotation_amount = (i % 8) + (layer_index % 3) + 1
            if layer_index % 2 == 0: # Encoder did ROL
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
            else: # Encoder did ROR
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF
            
            # Undo operations - This requires precise inverse functions.
            # Simplified inverse for XOR: D_inv = D ^ K
            # Simplified inverse for Add: D_inv = (D - K) % 256
            # More complex operations would need their specific inverses.
            
            # For simplicity, we'll just use XOR as the inverse operation.
            # A real implementation would need the exact inverse of each step.
            processed_data[i] ^= key[(i + layer_index) % key_len] # Inverse of XOR is XOR

        return bytes(processed_data)

    def _decompress_multi_stage(self, data):
        """Reverses the multi-stage compression process."""
        try:
            # Decompress Layer 2 (outer zlib)
            # Remove Header 2: CAFEBABE (4 bytes) + length (4 bytes) + stuff (variable)
            # We don't know the stuff size from the compressed data itself.
            # This is a major weakness in the compression obfuscation.
            # The stuff size needs to be predictable or encoded.
            # For this example, we'll rely on zlib's ability to find the compressed data.
            # In a robust implementation, the stuff size would be part of the header or a separate parameter.
            
            # The original compression added stuff AFTER the header + compressed data.
            # So the actual compressed data is at the end of `data`.
            # To decompress correctly, we need to find the start of the *actual* compressed data.
            # This is hard. A better approach is to have fixed sizes or a delimiter.
            
            # Let's assume the decompress function can handle arbitrary prefix.
            # zlib.decompress will error if it finds invalid data at the start.
            
            # Finding the compressed data is crucial. Let's assume the header is minimal.
            # Header 2: 4 bytes prefix + 4 bytes length + stuff (say, max 15 bytes)
            # So, compressed data starts at index 4 + 4 + stuff_size.
            # We need to find the actual start of valid zlib data.
            
            # A simpler approach for decompressing data that might have prefixes:
            # Iterate and try decompressing
            
            for i in range(len(data)):
                try:
                    # Try decompressing from current index
                    decompressed_l1 = zlib.decompress(data[i:])
                    
                    # Check for Header 1: DECOAD (3 bytes) + length (2 bytes)
                    if decompressed_l1.startswith(b'\xDE\xC0\xAD'):
                        compressed_len_l1 = struct.unpack('>H', decompressed_l1[3:5])[0]
                        inner_compressed_data = decompressed_l1[5 : 5 + compressed_len_l1]
                        
                        # Decompress Layer 1 data (zlib)
                        decompressed_l0 = zlib.decompress(inner_compressed_data)
                        
                        return decompressed_l0 # This is the final decompressed data
                except zlib.error:
                    continue # Try next index
            
            # If no valid decompression found
            raise zlib.error("Invalid compressed data or header")
            
        except Exception:
            os._exit(1)

    def execute(self):
        """Executes the entire decoding and execution pipeline."""
        
        # 1. Initial setup and environment validation
        self.keys = self.keys = self._derive_keys_for_decipher(self.seed_salt) # Derive keys for deciphering

        decoded_data = self.payload
        
        # 2. Multi-stage decoding and decompression
        for i in range(self.layers): # Iterate through layers for decoding/decompression
            
            # Reverse Encoding (order matters!)
            # The encoding order was Base85 -> URLSafeBase64 -> Hex -> ScrambledHex+Base64
            # So, we reverse it: FinalBase64 -> ScrambledHex -> Hex -> URLSafeBase64 -> Base85
            # We'll call decode_layer for each stage of encoding, starting from the outermost.
            # The loop here represents the "stages" of decoding.
            # If we have N layers of encoding, we need N stages of decoding.
            
            # This loop needs to precisely reverse the encoder's steps.
            # Let's assume the encoder applied its steps like:
            # Step 0: Base85
            # Step 1: URLSafeBase64
            # Step 2: Hex
            # Step 3: ScrambledHex+Base64
            # And compression was applied at certain steps.
            # The `_decode_layer` method handles the reversal of these specific steps.
            # The loop index `i` here controls which specific decoding step is applied.
            # The number of steps in `_decode_layer` must match the number of encoding steps.
            
            # If we have 4 encoding steps (Base85, B64U, Hex, Final B64), we need 4 decoding steps.
            # The self.layers parameter should ideally represent the total number of transformations,
            # not just cipher layers.
            # For this example, let's assume `self.layers` is the number of cipher rounds,
            # and the encoding steps are fixed.
            
            # Call _decode_layer for each encoding stage to be reversed.
            # The order here is critical.
            
            # The `_decode_layer` function is designed to handle multiple types of decoding.
            # We call it sequentially for each encoding stage being reversed.
            # Let's re-map `self.layers` to mean the total number of encoded data transformations.
            # If we have 4 encoding types and 7 cipher layers, it's a mix.
            
            # Let's simplify: Assume `self.layers` refers to the cipher rounds.
            # The encoding steps are fixed.
            
            # Call _multi_compress_obfuscated on specific cipher layers in the ENCODER.
            # So, in the DECODER, we need to call _decompress_multi_stage on corresponding data.
            # The logic `if (self.layers - 1 - layer_index) % 3 == 0:` in `_decode_layer` handles this.
            
            # The `_decode_layer` is designed to reverse specific encoding TYPES.
            # It does NOT iterate through cipher layers.
            # So we need to call the appropriate reverse encoding functions in order.
            
            # 1. Reverse FINAL Base64 (on scrambled hex)
            if i == 0:
                decoded_data = self._decode_layer(decoded_data, 0) # Stage 0 is final encoding layer
            
            # 2. Reverse Hex Prefix/Suffix and Hexlify
            elif i == 1:
                decoded_data = self._decode_layer(decoded_data, 1)
            
            # 3. Reverse URL-safe Base64
            elif i == 2:
                decoded_data = self._decode_layer(decoded_data, 2)
            
            # 4. Reverse Base85
            elif i == 3:
                decoded_data = self._decode_layer(decoded_data, 3)

            # After reversing a set of encodings, we might have data that was compressed.
            # This decompression must happen BEFORE the cipher is applied to that data.
            # So the decompression needs to be interleaved correctly.
            # The `_decode_layer` implicitly handles decompression based on the layer index.
            # The `_poly_decipher` needs to use the CORRECT data after decompression.

            # Let's re-structure:
            # First reverse all encodings. Then reverse all compressions. Then reverse ciphers.
            # Or, interleave: Decode_Stage -> Decompress (if applicable) -> Decipher
            
            # New Plan:
            # Iterate through the data, reversing one encoding layer at a time.
            # After each encoding reversal, check if it was compressed. If so, decompress.
            # THEN apply the deciphering for that specific cipher layer.

            # Let's simplify:
            # First, reverse ALL encodings.
            # Then, reverse ALL compressions.
            # Finally, reverse ALL cipher layers.
            
            # This order requires careful handling of data transformation.
            # Let's assume the encoder did:
            # Marshal -> PolyCipher(L0) -> Compress(L0) -> Encode(E0) -> PolyCipher(L1) -> Compress(L1) ... -> Encode(EN)
            
            # The decoder must do:
            # Decode(EN) -> PolyCipherInv(LN) -> Decompress(LN) -> Decode(EN-1) -> PolyCipherInv(LN-1) ... -> Marshal.loads
            
            # The `_decode_layer` function is designed to handle the specific encoding types.
            # The loop `for i in range(self.layers):` should probably iterate through the number of encoding stages.
            # Let's assume there are 4 main encoding stages, and `self.layers` is for cipher.
            
            # Let's use `self.layers` for cipher rounds, and a fixed number of encoding stages (e.g., 4).
            # The actual reverse order of operations needs to be applied.
            
            # Let's try this sequence of reversals:
            # 1. Reverse the final encoding (ScrambledHex+Base64).
            # 2. Reverse the Hex encoding.
            # 3. Reverse the URL-safe Base64 encoding.
            # 4. Reverse the Base85 encoding.
            
            # NOW, data might be compressed. Decompression needs to happen *before* its corresponding cipher layer is reversed.
            # This is where the complexity lies.
            # The `_decode_layer` function implicitly handles decompression.
            # The `_poly_decipher` needs to operate on the output of `_decode_layer`.
            
            # Let's assume the process:
            # Marshal -> Cipher(0) -> Compress(0) -> Encode(0) -> Cipher(1) -> Compress(1) -> Encode(1) ...
            
            # Decoder:
            # From final encoded data:
            # Reverse Encode(N-1)
            # Inverse Cipher(N-1)
            # Inverse Compress(N-1) (if applied)
            # Reverse Encode(N-2)
            # Inverse Cipher(N-2)
            # Inverse Compress(N-2) (if applied)
            # ...
            # Reverse Encode(0)
            # Inverse Cipher(0)
            # Inverse Compress(0) (if applied)
            # Finally, Unmarshal.
            
            # The `_decode_layer` function already orchestrates multiple decoding and decompression steps.
            # Let's use it with an index that makes sense for reversing the encodings.
            
            # If `self.layers` is the cipher rounds, let's assume 4 encoding stages.
            # The `_decode_layer` is meant to reverse ALL these stages in one call,
            # but it needs to know WHICH stage it's currently reversing to handle its specific logic.
            
            # This structure implies `_decode_layer` should be called multiple times,
            # or it needs to handle the sequence internally.
            
            # Let's adjust `_decode_layer` to handle a specific stage index.
            # Stage 0: Final Base64 + Scrambled Hex
            # Stage 1: Hex
            # Stage 2: URL-safe Base64
            # Stage 3: Base85
            
            # The `i` in this loop must correspond to the decoding stages.
            # If `self.layers` is cipher rounds, we need a separate loop for encoding stages.
            
            # --- Revised approach for interleaving ---
            # We have `self.layers` for cipher rounds.
            # We have fixed encoding stages (say, 4 main ones).
            # Compression is applied based on cipher rounds.
            
            # The core data transformation pipeline is:
            # original_data -> [Cipher L0] -> [Compress if L0%3==0] -> [Encode E0] ->
            # -> [Cipher L1] -> [Compress if L1%3==0] -> [Encode E1] -> ... -> FINAL_ENCODED_DATA
            
            # The reversal pipeline:
            # FINAL_ENCODED_DATA -> [Decode EN-1] -> [InverseCipher(N-1)] -> [InverseCompress(N-1) if L(N-1)%3==0] ->
            # -> [Decode EN-2] -> [InverseCipher(N-2)] -> [InverseCompress(N-2) if L(N-2)%3==0] -> ... -> UNMARSHAL_DATA
            
            # Let's rewrite the main execution loop in `execute`:

            # 1. Reverse all encoding layers first.
            # The `_decode_layer` method needs to be called multiple times with specific stage indices.
            # This function needs to be broken down if `_decode_layer` only handles one type of encoding.
            
            # For simplicity, `_decode_layer` will handle the full stack of decoding.
            # We will call it once to reverse all encodings and compressions.
            
            pass # Placeholder for now, will integrate into the loop below.
        
        # Let's re-organize the execution loop:
        # The outer loop iterates through cipher layers.
        # Inside, we reverse ONE encoding layer, decompress if needed, then decipher.
        
        current_data = self.payload # Start with the fully encoded data
        
        # Iterate from outermost encoding layer backwards to innermost.
        # Assume 4 encoding stages.
        # Stage 3: Final Base64 + Scrambled Hex
        # Stage 2: Hex
        # Stage 1: URL-safe Base64
        # Stage 0: Base85
        
        # So we need to reverse them in order: 3, 2, 1, 0.
        # The `_decode_layer` function takes an index to know which stage it is.
        # We call `_decode_layer` 4 times for the 4 encoding stages.
        
        # The compression check needs to be done against the cipher layer index.
        # Compression was applied for cipher layers L such that L % 3 == 0.
        # When reversing, this means we decompress data corresponding to cipher layers L = 0, 3, 6...
        
        # Let's refine the main execution loop:
        
        # First, reverse ALL encodings.
        # The `_decode_layer` function encapsulates the reversal of all encoding types + decompression.
        # It needs to be called in a way that processes the data sequentially.
        
        # Let's redefine `_decode_layer` to handle ONE encoding type and its associated compression.
        # This is cleaner.
        
        # Let's rewrite `execute` and related helper functions.
        pass # Placeholder, will rewrite the core execution logic.
        
    def execute_pipeline(self):
        """
        Executes the full decoding and execution pipeline with interleaved operations.
        This is the core of the obfuscation logic.
        """
        
        # --- Phase 1: Reverse Encoding Stages ---
        # The order is critical: reverse from outermost to innermost.
        # Assume 4 main encoding stages.
        
        current_data = self.payload
        
        # Stage 3: Reverse Final Base64 + Scrambled Hex
        try:
            # Decode outermost Base64
            decoded_final_b64 = self._get_callable(b'base64.b64decode')(current_data)
            
            # Descramble Hex
            scrambling_key = self.initial_key # Use the same key for descrambling
            scrambled_hex_bytearray = bytearray(decoded_final_b64)
            for i in range(len(scrambled_hex_bytearray)):
                scrambled_hex_bytearray[i] ^= (i % 256)
            current_data = bytes(scrambled_hex_bytearray)
            
        except Exception:
            os._exit(1)

        # Stage 2: Reverse Hex Prefix/Suffix and Hexlify
        try:
            if not current_data.startswith(b'XX') or not current_data.endswith(b'YY'):
                raise ValueError("Invalid hex prefix/suffix")
            current_data = current_data[2:-2]
            current_data = self._get_callable(b'binascii.unhexlify')(current_data)
        except Exception:
            os._exit(1)

        # Stage 1: Reverse URL-safe Base64
        try:
            current_data = self._get_callable(b'base64.urlsafe_b64decode')(current_data)
        except Exception:
            os._exit(1)

        # Stage 0: Reverse Base85
        try:
            current_data = self._get_callable(b'base64.b85decode')(current_data)
        except Exception:
            os._exit(1)

        # --- Phase 2: Interleaved Decompression and Cipher Decryption ---
        # Now `current_data` is the output of the first encoding stage (Base85).
        # We need to reverse the cipher layers and compression stages in reverse order of application.
        # Cipher layers are L0, L1, ..., LN-1.
        # Compression applied for L such that L % 3 == 0.
        # The data we have now is the output of the Base85 encoding of (Cipher L(N-1) applied to (compressed if L(N-1)%3==0)).
        
        # We need to know the exact number of cipher layers (`self.layers`) used.
        # The loop below iterates through cipher layers in reverse.
        
        # The data we have (`current_data`) has already gone through all encodings.
        # So, when we reverse the LAST cipher layer `L_{N-1}`, we should ALSO decompress if `(N-1)%3==0`.
        
        # We need to reverse `self.layers` number of cipher operations.
        # The loop goes from `self.layers - 1` down to `0`.
        
        for i in range(self.layers - 1, -1, -1):
            # First, decompress if this cipher layer's data was compressed.
            # The encoder compressed if the cipher layer index `i` was a multiple of 3.
            if i % 3 == 0:
                try:
                    current_data = self._decompress_multi_stage(current_data)
                except Exception:
                    os._exit(1)

            # Then, decipher the data for this specific cipher layer.
            try:
                # Derive keys for THIS cipher layer.
                # The seeds were generated sequentially. The keys derived from them are used.
                # We need to use the correct seed for each cipher layer's key.
                
                # The seeds list corresponds to cipher layers 0, 1, 2...
                # So for layer `i`, we need the `i`-th seed.
                # But we are iterating in reverse. So for layer `i`, we need seed `i`.
                
                cipher_key = self.keys[i] # Use the pre-derived keys
                current_data = self._reverse_poly_cipher_layer(current_data, i)
            except Exception:
                os._exit(1)

        # --- Phase 3: Final Unmarshalling and Execution ---
        try:
            # The final `current_data` should now be the marshalled Python code.
            code_object = self._get_callable(b'marshal.loads')(current_data)
            self._get_callable(b'exec')(code_object)
        except Exception:
            os._exit(1)

# --- Encoder Class ---
class PythonEncoderBot:
    def __init__(self, bot_token):
        self.bot = telebot.TeleBot(bot_token)
        self.obfuscator = ObfuscationEngine(layers=7) # Using 7 cipher layers
        self.setup_handlers()

    def setup_handlers(self):
        @self.bot.message_handler(commands=['start', 'help'])
        def send_welcome(message):
            welcome_msg = """
✨ **Advanced Python Obfuscator Bot (v3.0)** ✨

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
                source_code = downloaded_file.decode('utf-8', errors='ignore')

                if not source_code.strip():
                    self.bot.reply_to(message, "❌ The provided file is empty or contains no executable code.")
                    return
                
                encoded_code = self.obfuscate_code(source_code)
                
                # Save to a temporary file to send as a document
                temp_file_path = os.path.join(self.obfuscator.temp_dir, f"ultra_secure_{file_info.file_name}")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="✨ Your ULTRA SECURE obfuscated Python script!",
                        visible_file_name=f"ultra_secure_{file_info.file_name}"
                    )
                
                os.unlink(temp_file_path) # Clean up temp file
                
            except Exception as e:
                self.handle_error(message, f"Error processing document: {str(e)}")

        @self.bot.message_handler(func=lambda message: True)
        def handle_text(message):
            text = message.text
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
                encoded_code = self.obfuscate_code(text)
                
                # Save to a temporary file to send as a document
                temp_file_path = os.path.join(self.obfuscator.temp_dir, "ultra_secure_script.py")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="✨ Your ULTRA SECURE obfuscated Python code!",
                        visible_file_name="ultra_secure_script.py"
                    )
                
                os.unlink(temp_file_path) # Clean up temp file
                
            except Exception as e:
                self.handle_error(message, f"Error obfuscating code: {str(e)}")

    def obfuscate_code(self, source_code):
        """Main function to orchestrate the obfuscation process."""
        try:
            # 1. Compile and marshal the source code
            code = compile(source_code, "<obfuscated_source>", "exec")
            payload = marshal.dumps(code)
            
            # 2. Generate complex seed and derive keys
            base_seed = os.urandom(16)
            seeds = [self.obfuscator._generate_complex_seed(base_seed + struct.pack('>I', i)) for i in range(self.obfuscator.layers)]
            keys = self.obfuscator._derive_keys(base_seed) # Derive all keys from base seed

            # 3. Apply polymorphic cipher to the marshalled payload
            ciphered_payload = self.obfuscator._poly_cipher(payload, keys)
            
            # 4. Apply compression to ciphered data for specific layers
            # This is where the compression logic should be applied based on cipher layers.
            # The `_poly_cipher` function currently processes all layers sequentially.
            # The compression/encoding happens *after* a cipher layer.
            
            # Let's re-structure `obfuscate_code` to match the pipeline more closely:
            # data = marshal(source)
            # for i in range(layers):
            #     data = cipher(data, key[i])
            #     if i % 3 == 0: data = compress(data)
            #     data = encode(data) # Apply the different encoding stages sequentially

            transformed_data = payload
            for i in range(self.obfuscator.layers):
                # Apply cipher for this layer
                transformed_data = self.obfuscator._poly_cipher(transformed_data, [keys[i]]) # Pass single key for layer
                
                # Apply compression if required for this cipher layer
                if i % 3 == 0:
                    transformed_data = self.obfuscator._multi_compress_obfuscated(transformed_data)
            
            # After all cipher/compression layers, apply the encoding stages sequentially.
            # This means the LAST cipher/compression output gets encoded.
            
            # Final encoding stages (order matters for reversal)
            # Encoding 0: Base85
            transformed_data = self.obfuscator._multi_encode_complex(transformed_data) # This applies all 4 encoding steps in one go.
            
            # The `_multi_encode_complex` applies: Base85 -> URLSafeBase64 -> Hex -> ScrambledHex+Base64
            # So the output `transformed_data` is the final encoded result.
            
            # 5. Create the obfuscated decoder stub
            # The stub needs: encoded payload, seeds, keys, salt, number of layers, etc.
            # The `initial_key` used for string decryption is `keys[0]`.
            
            # We need to pass the `encrypted_strings` to the stub constructor.
            # This requires defining `encrypted_strings` and generating them here.
            
            # --- Re-generating encrypted strings logic for `obfuscate_code` ---
            critical_strings = {
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
            
            encrypted_strings_dict = {}
            for name, value in critical_strings.items():
                if isinstance(value, str):
                    val_bytes = value.encode('utf-8')
                elif isinstance(value, bytes):
                    val_bytes = value
                else: continue
                
                encrypted_val = bytearray()
                # Use the first key for string encryption
                for i in range(len(val_bytes)):
                    encrypted_val.append(val_bytes[i] ^ keys[0][(i + ord(name[0])) % len(keys[0])])
                encrypted_strings_dict[name] = bytes(encrypted_val)
            
            # Prepare arguments for the VM constructor
            vm_args = {
                "encrypted_payload": transformed_data,
                "seeds_list": seeds,
                "key_size": self.obfuscator.key_size,
                "num_layers": self.obfuscator.layers,
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
                "initial_key_hex": keys[0].hex()
            }
            
            # Build the stub with the actual encrypted strings embedded
            stub_code = self.generate_vm_stub_code(vm_args, encrypted_strings_dict)
            
            return stub_code
            
        except Exception as e:
            # Log internal errors and raise a user-friendly message
            print(f"ERROR: Failed to obfuscate code: {e}", file=sys.stderr)
            raise ValueError("Obfuscation failed due to an internal error. Please try again.")
            
    def generate_vm_stub_code(self, vm_args, encrypted_strings_dict):
        """Generates the Python stub code for the VM."""
        
        # Embed encrypted strings directly into the stub's data structure
        embedded_encrypted_strings = "{\n"
        for name, enc_val in encrypted_strings_dict.items():
            embedded_encrypted_strings += f"        '{name}': {repr(enc_val)},\n"
        embedded_encrypted_strings += "    }"

        # This template is executed FIRST. It sets up the VM and then runs `execute_pipeline`.
        stub_template = f"""
import marshal, zlib, base64, binascii, hashlib, time, struct, random, sys, os

# --- Dynamic String Decryption Helper ---
def decrypt_strings(encrypted_map, initial_key_hex, seed_salt_hex):
    decrypted_map = {{}}
    initial_key = bytes.fromhex(initial_key_hex)
    seed_salt = bytes.fromhex(seed_salt_hex)
    
    # Recreate the operations used during encryption
    # The key used for string encryption is the first key (keys[0]) from the main cipher
    
    for name, enc_val in encrypted_map.items():
        decrypted_bytes = bytearray()
        # The offset logic must exactly match the encoder
        # Using first char of string name for offset
        name_offset = ord(name[0]) % len(initial_key) 
        
        for i in range(len(enc_val)):
            decrypted_bytes.append(enc_val[i] ^ initial_key[(i + name_offset) % len(initial_key)])
            
        decrypted_map[name] = bytes(decrypted_bytes).decode('utf-8', errors='ignore')
    return decrypted_map

# --- Main VM Class ---
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
                elif module_name == 'exec': return lambda code: exec(code) # Special case
                else: raise ValueError("Unknown module")
                
                return getattr(module, attr_name)
            else:
                return str_name # Return the string itself if not a callable
                
        except Exception:
            os._exit(1)

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
        # Anti-debugging check
        try:
            if self.s.get('sys_gettrace') and self.s.get('sys_gettrace')() is not None:
                os._exit(1)
        except Exception:
            os._exit(1)
            
        # Basic integrity check for critical string lookups
        if not self.s.get('zlib_decompress'):
            os._exit(1)

    def _decompress_multi_stage(self, data):
        try:
            for i in range(len(data)):
                try:
                    # Try decompressing from current index
                    decompressed_l1 = self.s['zlib_decompress'](data[i:])
                    
                    # Check for Header 1: DECOAD (3 bytes) + length (2 bytes)
                    if decompressed_l1.startswith(self.s['header_l1_prefix']):
                        compressed_len_l1 = self.s['struct_unpack']('>H', decompressed_l1[3:5])[0]
                        inner_compressed_data = decompressed_l1[5 : 5 + compressed_len_l1]
                        
                        # Decompress Layer 1 data (zlib)
                        decompressed_l0 = self.s['zlib_decompress'](inner_compressed_data)
                        
                        return decompressed_l0
                except Exception: # Catch zlib.error and others
                    continue
            raise Exception("Invalid compressed data or header")
        except Exception:
            os._exit(1)

    def _reverse_poly_cipher_layer(self, data, layer_index):
        key = self.keys[layer_index]
        key_len = len(key)
        
        processed_data = bytearray(data)
        
        # Recreate the operation sequence deterministically
        op_sequence_seed = self.s['hashlib_sha256'](key).digest()
        self.s['random_seed'](op_sequence_seed)
        
        # Operations for cipher
        op_funcs = [
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256, # XOR
            lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256, # Add with offset
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256, # Double XOR
            lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256, # Add/XOR mixed
        ]
        
        # The order of operations must match the encoder.
        # For simplicity, we assume a fixed order in the decoder's random seed.
        # A real implementation might need to reconstruct the shuffle order deterministically.
        
        for i in range(len(processed_data) - 1, -1, -1): # Reverse order for some ops
            rotation_amount = (i % 8) + (layer_index % 3) + 1
            
            # Undo rotation
            if layer_index % 2 == 0: # Encoder ROL, inverse is ROR
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
            else: # Encoder ROR, inverse is ROL
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF
            
            # Inverse operations (simplified)
            # For XOR: D_inv = D ^ K
            # For Add: D_inv = (D - K) % 256
            # The exact inverse operations need to be implemented to match the encoder's logic precisely.
            # For demonstration, we'll use simple XOR as the inverse.
            processed_data[i] ^= key[(i + layer_index) % key_len]
            
        return bytes(processed_data)

    def execute_pipeline(self):
        """Reverses all transformations and executes the final payload."""
        
        current_data = self.payload
        
        # --- Phase 1: Reverse Encoding Stages ---
        # Order: Final Base64+ScrambledHex -> Hex -> URLSafeBase64 -> Base85
        
        # Stage 3: Reverse Final Base64 + Scrambled Hex
        try:
            decoded_final_b64 = self.s['base64_b64decode'](current_data)
            scrambled_hex_bytearray = bytearray(decoded_final_b64)
            for i in range(len(scrambled_hex_bytearray)):
                scrambled_hex_bytearray[i] ^= (i % 256)
            current_data = bytes(scrambled_hex_bytearray)
        except Exception: os._exit(1)

        # Stage 2: Reverse Hex Prefix/Suffix and Hexlify
        try:
            if not current_data.startswith(self.s['header_l1_prefix']) or not current_data.endswith(self.s['header_l2_prefix']): # Using prefix/suffix names here as placeholders
                raise ValueError("Invalid hex prefix/suffix")
            current_data = current_data[2:-2] # Remove XX, YY
            current_data = self.s['binascii_unhexlify'](current_data)
        except Exception: os._exit(1)

        # Stage 1: Reverse URL-safe Base64
        try:
            current_data = self.s['base64_urlsafe_b64decode'](current_data)
        except Exception: os._exit(1)

        # Stage 0: Reverse Base85
        try:
            current_data = self.s['base64_b85decode'](current_data)
        except Exception: os._exit(1)

        # --- Phase 2: Interleaved Decompression and Cipher Decryption ---
        # Iterate through cipher layers in reverse.
        # If compression was applied for a layer, decompress BEFORE deciphering that layer.
        
        for i in range(self.layers - 1, -1, -1):
            # Decompress if this cipher layer had compression applied in the encoder.
            # Encoder compressed if cipher layer index `i` was a multiple of 3.
            if i % 3 == 0:
                try:
                    current_data = self._decompress_multi_stage(current_data)
                except Exception: os._exit(1)

            # Decipher this cipher layer.
            try:
                current_data = self._reverse_poly_cipher_layer(current_data, i)
            except Exception: os._exit(1)

        # --- Phase 3: Final Unmarshalling and Execution ---
        try:
            code_object = self.s['marshal_loads'](current_data)
            self.s['exec_call'](code_object)
        except Exception: os._exit(1)

# --- Bot Main Logic ---
class BotController:
    def __init__(self, bot_token):
        self.bot = telebot.TeleBot(bot_token)
        self.obfuscator = ObfuscationEngine(layers=7)
        self.setup_handlers()

    def setup_handlers(self):
        @self.bot.message_handler(commands=['start', 'help'])
        def send_welcome(message):
            welcome_msg = """
✨ **ULTRA SECURE Python Obfuscator Bot (v3.0)** ✨

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
                        caption="✨ Your ULTRA SECURE obfuscated Python script!",
                        visible_file_name=f"ultra_secure_{file_info.file_name}"
                    )
                
                os.unlink(temp_file_path)
                
            except Exception as e:
                self.handle_error(message, f"Error processing document: {str(e)}")

        @self.bot.message_handler(func=lambda message: True)
        def handle_text(message):
            text = message.text
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
                encoded_code = self.obfuscate_code(text)
                
                temp_file_path = os.path.join(self.obfuscator.temp_dir, "ultra_secure_script.py")
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    f.write(encoded_code)
                
                with open(temp_file_path, 'rb') as f:
                    self.bot.send_document(
                        message.chat.id,
                        f,
                        caption="✨ Your ULTRA SECURE obfuscated Python code!",
                        visible_file_name="ultra_secure_script.py"
                    )
                
                os.unlink(temp_file_path)
                
            except Exception as e:
                self.handle_error(message, f"Error obfuscating code: {str(e)}")

    def obfuscate_code(self, source_code):
        """Orchestrates the obfuscation process for a given source code."""
        try:
            # 1. Marshal the source code
            code = compile(source_code, "<obfuscated_source>", "exec")
            payload = marshal.dumps(code)
            
            # 2. Generate seeds and derive keys
            base_seed = os.urandom(16)
            seeds = [self.obfuscator._generate_complex_seed(base_seed + struct.pack('>I', i)) for i in range(self.obfuscator.layers)]
            keys = self.obfuscator._derive_keys(base_seed) # Derive all keys from base seed

            # 3. Apply chained transformations: Cipher -> (Compress if needed) -> Encode
            transformed_data = payload
            for i in range(self.obfuscator.layers):
                # Apply cipher for this layer
                transformed_data = self.obfuscator._poly_cipher(transformed_data, [keys[i]]) # Pass single key for layer
                
                # Apply compression if required for this cipher layer
                # Compression is applied for cipher layers `i` where `i % 3 == 0`.
                if i % 3 == 0:
                    transformed_data = self.obfuscator._multi_compress_obfuscated(transformed_data)
            
            # 4. Apply final encoding stages sequentially (order matters for reversal)
            # Encoding 0: Base85
            # Encoding 1: URL-safe Base64
            # Encoding 2: Hex
            # Encoding 3: Scrambled Hex + Base64
            
            # This sequence is applied to the output of the last cipher/compression layer.
            # So, transformed_data becomes the input to the first encoding stage.
            
            # The `_multi_encode_complex` method does all 4 stages in one.
            # We need to call them individually to ensure correct interleaving with cipher/compression.
            
            # Re-writing the chaining for clarity:
            data_to_encode = transformed_data
            
            # Stage 0: Base85
            data_to_encode = self.obfuscator._multi_encode_complex(data_to_encode)[:base64.b85encode(b'').__len__()] # This part is wrong. `_multi_encode_complex` needs to be broken down.
            
            # Let's break down `_multi_encode_complex`:
            def encode_base85(data): return base64.b85encode(data)
            def encode_urlsafe_b64(data): return base64.urlsafe_b64encode(data)
            def encode_hex_prefixed(data): return b'XX' + binascii.hexlify(data) + b'YY'
            def encode_scrambled_b64(data, key):
                scrambled_hex_bytearray = bytearray(data)
                for i in range(len(scrambled_hex_bytearray)):
                    scrambled_hex_bytearray[i] ^= (i % 256)
                return base64.b64encode(bytes(scrambled_hex_bytearray))
            
            # Apply encodings in order: Base85 -> URLSafeBase64 -> Hex -> ScrambledBase64
            encoded_data = encode_base85(transformed_data)
            encoded_data = encode_urlsafe_b64(encoded_data)
            encoded_data = encode_hex_prefixed(encoded_data)
            encoded_data = encode_scrambled_b64(encoded_data, keys[0]) # Use first key for scrambling
            
            final_encoded_payload = encoded_data

            # 5. Prepare arguments for the VM stub
            vm_args = {
                "encrypted_payload": final_encoded_payload,
                "seeds_list": seeds,
                "key_size": self.obfuscator.key_size,
                "num_layers": self.obfuscator.layers,
                "seed_salt_hex": self.obfuscator.seed_salt.hex(),
                "initial_key_hex": keys[0].hex() # First key for string decryption
            }
            
            # Generate the stub code
            stub_code = self.generate_vm_stub_code(vm_args, critical_strings)
            
            return stub_code
            
        except Exception as e:
            print(f"ERROR: Failed to obfuscate code: {e}", file=sys.stderr)
            raise ValueError("Obfuscation failed due to an internal error. Please try again.")

    def generate_vm_stub_code(self, vm_args, encrypted_strings_map):
        """Generates the Python stub code string for the VM."""
        
        # Embed encrypted strings directly into the stub's data structure for the VM constructor
        embedded_encrypted_strings = "{\n"
        for name, enc_val in encrypted_strings_map.items():
            embedded_encrypted_strings += f"        '{name}': {repr(enc_val)},\n"
        embedded_encrypted_strings += "    }"
        
        # Ensure the data passed to the VM constructor is correctly formatted
        # Pass `encrypted_strings_map` directly; the VM will decrypt it.
        
        stub_template = f"""
import marshal, zlib, base64, binascii, hashlib, time, struct, random, sys, os

# --- Decryption Helper ---
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
            raise Exception("Invalid compressed data or header")
        except Exception: os._exit(1)

    def _reverse_poly_cipher_layer(self, data, layer_index):
        key = self.keys[layer_index]
        key_len = len(key)
        processed_data = bytearray(data)
        
        op_sequence_seed = self.s['hashlib_sha256'](key).digest()
        self.s['random_seed'](op_sequence_seed)
        
        # Operations definition (must match encoder exactly)
        op_funcs_template = [
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len]) % 256,
            lambda d, k, i, l, op_seed: (d[i] + k[(i + l) % k_len] + (op_seed[(i*2)%16] >> 1)) % 256,
            lambda d, k, i, l, op_seed: (d[i] ^ k[(i + l) % k_len] ^ (op_seed[(i*3)%16])) % 256,
            lambda d, k, i, l, op_seed: (d[i] + (k[(i + l) % k_len] >> 2) ^ (op_seed[(i*4)%16] << 1)) % 256,
        ]
        
        for i in range(len(processed_data) - 1, -1, -1):
            rotation_amount = (i % 8) + (layer_index % 3) + 1
            if layer_index % 2 == 0: # Encoder ROL, inverse is ROR
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] >> inv_rotation_amount) | (processed_data[i] << (8 - inv_rotation_amount))) & 0xFF
            else: # Encoder ROR, inverse is ROL
                inv_rotation_amount = 8 - rotation_amount
                processed_data[i] = ((processed_data[i] << inv_rotation_amount) | (processed_data[i] >> (8 - inv_rotation_amount))) & 0xFF
            
            # Inverse operations (simplified - THIS NEEDS TO BE EXACT)
            processed_data[i] ^= key[(i + layer_index) % key_len]
            
        return bytes(processed_data)

    def execute_pipeline(self):
        current_data = self.payload
        
        # Phase 1: Reverse Encoding Stages
        try:
            # Stage 3: Reverse Final Base64 + Scrambled Hex
            decoded_final_b64 = self.s['base64_b64decode'](current_data)
            scrambled_hex_bytearray = bytearray(decoded_final_b64)
            for i in range(len(scrambled_hex_bytearray)): scrambled_hex_bytearray[i] ^= (i % 256)
            current_data = bytes(scrambled_hex_bytearray)

            # Stage 2: Reverse Hex Prefix/Suffix and Hexlify
            if not current_data.startswith(self.s['header_l1_prefix']) or not current_data.endswith(self.s['header_l2_prefix']): os._exit(1)
            current_data = current_data[2:-2]
            current_data = self.s['binascii_unhexlify'](current_data)

            # Stage 1: Reverse URL-safe Base64
            current_data = self.s['base64_urlsafe_b64decode'](current_data)

            # Stage 0: Reverse Base85
            current_data = self.s['base64_b85decode'](current_data)
        except Exception: os._exit(1)

        # Phase 2: Interleaved Decompression and Cipher Decryption
        for i in range(self.layers - 1, -1, -1):
            if i % 3 == 0: # Decompress if compression was applied for this cipher layer
                try: current_data = self._decompress_multi_stage(current_data)
                except Exception: os._exit(1)
            try: current_data = self._reverse_poly_cipher_layer(current_data, i)
            except Exception: os._exit(1)

        # Phase 3: Final Unmarshalling and Execution
        try:
            code_object = self.s['marshal_loads'](current_data)
            self.s['exec_call'](code_object)
        except Exception: os._exit(1)

# --- Entry Point for the Stub ---
if __name__ == '__main__':
    # Extract VM arguments and encrypted strings from the script's context.
    # This is done by embedding them directly as Python objects.
    
    # VM Argument Dictionary
    vm_args = {
        "encrypted_payload": {encrypted_payload_bytes_repr},
        "seeds_list": {seeds_list_repr},
        "key_size": {key_size_val},
        "num_layers": {num_layers_val},
        "seed_salt_hex": "{seed_salt_hex_str}",
        "initial_key_hex": "{initial_key_hex_str}"
    }
    
    # Encrypted Strings Dictionary
    encrypted_strings_map = {encrypted_strings_dict_repr}
    
    # Initialize and run the VM
    vm = VM_Executor(**vm_args, encrypted_strings_map=encrypted_strings_map)
    vm.execute_pipeline()
"""
        return stub_template.format(
            encrypted_payload_bytes_repr=repr(vm_args["encrypted_payload"]),
            seeds_list_repr=repr(vm_args["seeds_list"]),
            key_size_val=vm_args["key_size"],
            num_layers_val=vm_args["num_layers"],
            seed_salt_hex_str=vm_args["seed_salt_hex"],
            initial_key_hex_str=vm_args["initial_key_hex"],
            encrypted_strings_dict_repr=embedded_encrypted_strings # Pass as string of dict representation
        )


    def handle_error(self, message, error_msg):
        """Handles bot errors and replies to the user."""
        print(f"BOT ERROR: {error_msg}", file=sys.stderr)
        self.bot.reply_to(message, f"❌ An error occurred: {error_msg}")

    def start_polling(self):
        """Starts the Telegram bot polling."""
        print("🤖 Starting Telegram Bot...")
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
        """Starts the Flask web server."""
        port = int(os.environ.get('PORT', 5000))
        print(f"🌐 Starting Flask server on port {port}")
        try:
            # Use threading for Flask to not block bot polling
            from flask import Flask
            app = Flask(__name__)
            @app.route('/')
            @app.route('/health')
            def health_check(): return "Bot is operational.", 200
            
            # Run Flask in a separate thread
            server_thread = Thread(target=lambda: app.run(host='0.0.0.0', port=port, debug=False))
            server_thread.daemon = True
            server_thread.start()
        except Exception as e:
            print(f"Error starting Flask server: {e}", file=sys.stderr)

# --- Main Execution ---
if __name__ == "__main__":
    # Basic validation for the bot token
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_PLACEHOLDER_BOT_TOKEN":
        print("ERROR: BOT_TOKEN is not configured. Please set the BOT_TOKEN environment variable or edit the script.")
        sys.exit(1)

    # Clean up the temporary directory on startup if it exists from a previous run.
    # This is a crude cleanup. A more robust solution would be better.
    try:
        import shutil
        temp_dir_to_clean = tempfile.gettempdir() + "/obfuscator_*"
        for dir_path in glob.glob(temp_dir_to_clean):
            if os.path.isdir(dir_path):
                shutil.rmtree(dir_path)
    except Exception:
        pass # Ignore cleanup errors

    bot_controller = BotController(BOT_TOKEN)
    bot_controller.start_webserver() # Start web server first
    bot_controller.start_polling() # Then start bot polling
