"""
Encryption utilities for sensitive data
Uses Fernet symmetric encryption (AES-128 in CBC mode with HMAC)
"""
import os
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_encryption_key():
    """Get encryption key from environment or derive it from an explicit password"""
    key = os.getenv('ENCRYPTION_KEY')

    if key:
        return key.encode() if isinstance(key, str) else key

    password = os.getenv('ENCRYPTION_PASSWORD')
    salt = os.getenv('ENCRYPTION_SALT')
    if not password:
        raise RuntimeError('ENCRYPTION_KEY or ENCRYPTION_PASSWORD must be set')
    if not salt:
        raise RuntimeError('ENCRYPTION_SALT must be set when using ENCRYPTION_PASSWORD')
    if password == 'default-password-change-me' or salt == 'default-salt-change-me':
        raise RuntimeError('Default encryption password/salt placeholders are not allowed')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


# Initialize Fernet cipher
try:
    _fernet_key = get_encryption_key()
    _fernet = Fernet(_fernet_key)
    ENCRYPTION_ENABLED = True
except Exception as e:
    print(f"⚠ Encryption disabled: {e}")
    _fernet = None
    ENCRYPTION_ENABLED = False


def encrypt_value(value):
    """
    Encrypt a string value
    Returns: encrypted string with 'ENC:' prefix, or original if encryption disabled
    """
    if not ENCRYPTION_ENABLED or not value:
        return value

    try:
        if isinstance(value, str):
            value = value.encode('utf-8')
        encrypted = _fernet.encrypt(value)
        return 'ENC:' + encrypted.decode('utf-8')
    except Exception as e:
        print(f"⚠ Encryption failed: {e}")
        return value


def decrypt_value(value):
    """
    Decrypt a string value
    Handles both encrypted (ENC: prefix) and plain text values
    """
    if not value:
        return value

    # Check if value is encrypted
    if isinstance(value, str) and value.startswith('ENC:'):
        if not ENCRYPTION_ENABLED:
            print("⚠ Cannot decrypt: encryption disabled")
            return value

        try:
            encrypted_data = value[4:]  # Remove 'ENC:' prefix
            decrypted = _fernet.decrypt(encrypted_data.encode('utf-8'))
            return decrypted.decode('utf-8')
        except InvalidToken:
            print("⚠ Decryption failed: invalid token or wrong key")
            return value
        except Exception as e:
            print(f"⚠ Decryption failed: {e}")
            return value

    # Plain text value
    return value


def encrypt_env_file(env_path='.env'):
    """
    Encrypt sensitive values in .env file
    Adds 'ENC:' prefix to encrypted values
    """
    sensitive_keys = ['ADMIN_PASS', 'FLASK_SECRET_KEY', 'ENCRYPTION_KEY']

    if not os.path.exists(env_path):
        print(f"⚠ {env_path} not found")
        return False

    with open(env_path, 'r') as f:
        lines = f.readlines()

    updated_lines = []
    for line in lines:
        line = line.rstrip('\n')

        # Skip comments and empty lines
        if not line or line.strip().startswith('#'):
            updated_lines.append(line)
            continue

        # Parse KEY=VALUE
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()

            # Encrypt sensitive keys if not already encrypted
            if key in sensitive_keys and value and not value.startswith('ENC:'):
                encrypted = encrypt_value(value)
                updated_lines.append(f"{key}={encrypted}")
                print(f"🔒 Encrypted: {key}")
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)

    # Write back
    with open(env_path, 'w') as f:
        f.write('\n'.join(updated_lines) + '\n')

    print(f"✓ {env_path} updated")
    return True


def generate_encryption_key():
    """Generate a new Fernet encryption key"""
    return Fernet.generate_key().decode('utf-8')


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == 'encrypt-env':
            encrypt_env_file()
        elif command == 'generate-key':
            key = generate_encryption_key()
            print(f"Generated key: {key}")
            print(f"\nAdd to .env:")
            print(f"ENCRYPTION_KEY={key}")
        else:
            print("Usage:")
            print("  python encryption.py encrypt-env    - Encrypt .env file")
            print("  python encryption.py generate-key   - Generate new key")
    else:
        print("Encryption module")
        print(f"Status: {'Enabled' if ENCRYPTION_ENABLED else 'Disabled'}")
        print("\nUsage:")
        print("  python encryption.py encrypt-env    - Encrypt .env file")
        print("  python encryption.py generate-key   - Generate new key")
