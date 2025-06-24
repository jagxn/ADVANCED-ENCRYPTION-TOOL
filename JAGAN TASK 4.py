import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys

class SecureFileCrypto:
    def __init__(self, passphrase):
        self.passphrase = passphrase.encode('utf-8')
        self.salt_len = 16
        self.key_len = 32
        self.n = 2**14
        self.r = 8
        self.p = 1
        self.iv_len = AES.block_size
        self.mac_len = 32
        self.buf_size = 65536

    def _get_keys(self, salt):
        derived = scrypt(
            password=self.passphrase,
            salt=salt,
            key_len=self.key_len*2,
            N=self.n,
            r=self.r,
            p=self.p
        )
        return derived[:self.key_len], derived[self.key_len:]

    def lock(self, src, dst):
        if not os.path.exists(src):
            raise FileNotFoundError(f"Input file not found: {src}")

        salt = get_random_bytes(self.salt_len)
        key_enc, key_auth = self._get_keys(salt)
        iv = get_random_bytes(self.iv_len)
        aes = AES.new(key_enc, AES.MODE_CBC, iv)
        h = hmac.new(key_auth, digestmod=hashlib.sha256)

        try:
            with open(src, 'rb') as in_file, open(dst, 'wb') as out_file:
                out_file.write(salt + iv)
                while True:
                    data = in_file.read(self.buf_size)
                    if not data:
                        break
                    if len(data) % AES.block_size != 0:
                        data = pad(data, AES.block_size)
                    enc_data = aes.encrypt(data)
                    out_file.write(enc_data)
                    h.update(enc_data)
                out_file.write(h.digest())
        except Exception as e:
            if os.path.exists(dst):
                os.remove(dst)
            raise Exception(f"Encryption failed: {str(e)}")

    def unlock(self, src, dst):
        if not os.path.exists(src):
            raise FileNotFoundError(f"Input file not found: {src}")

        try:
            with open(src, 'rb') as in_file:
                salt = in_file.read(self.salt_len)
                iv = in_file.read(self.iv_len)
                key_enc, key_auth = self._get_keys(salt)
                h = hmac.new(key_auth, digestmod=hashlib.sha256)
                file_size = os.path.getsize(src)
                data_size = file_size - self.salt_len - self.iv_len - self.mac_len
                aes = AES.new(key_enc, AES.MODE_CBC, iv)

                with open(dst, 'wb') as out_file:
                    remaining = data_size
                    while remaining > 0:
                        read_size = min(self.buf_size, remaining)
                        data = in_file.read(read_size)
                        if not data:
                            break
                        h.update(data)
                        remaining -= len(data)
                        dec_data = aes.decrypt(data)
                        if remaining <= 0:
                            dec_data = unpad(dec_data, AES.block_size)
                        out_file.write(dec_data)
                    stored_mac = in_file.read(self.mac_len)
                    if not hmac.compare_digest(h.digest(), stored_mac):
                        raise ValueError("Integrity check failed - file may be corrupted or tampered with")
        except Exception as e:
            if os.path.exists(dst):
                os.remove(dst)
            raise Exception(f"Decryption failed: {str(e)}")

def execute():
    if len(sys.argv) < 4:
        print("Usage: python script.py <encrypt|decrypt> <input> <output> [password]")
        print("Example:")
        print("  python script.py encrypt input.txt encrypted.bin")
        print("  python script.py decrypt encrypted.bin output.txt")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    input_path = sys.argv[2]
    output_path = sys.argv[3]
    
    try:
        secret = sys.argv[4] if len(sys.argv) > 4 else input("Enter password: ")
        if not secret:
            raise ValueError("Password cannot be empty")

        crypto = SecureFileCrypto(secret)

        if mode == 'encrypt':
            crypto.lock(input_path, output_path)
            print(f"File encrypted successfully: {output_path}")
        elif mode == 'decrypt':
            crypto.unlock(input_path, output_path)
            print(f"File decrypted successfully: {output_path}")
        else:
            raise ValueError("Invalid mode - use 'encrypt' or 'decrypt'")
            
    except Exception as e:
        print(f"\nError: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    execute()