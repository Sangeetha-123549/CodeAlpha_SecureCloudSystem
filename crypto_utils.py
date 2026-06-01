from Crypto.Cipher import AES
import base64

KEY = b'12345678901234567890123456789012'  # 32 bytes

def encrypt(text):
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())

    data = cipher.nonce + tag + ciphertext
    return base64.b64encode(data).decode()

def decrypt(enc_text):
    raw = base64.b64decode(enc_text)

    nonce = raw[:16]
    tag = raw[16:32]
    ciphertext = raw[32:]

    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()