import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_api_data_dir = tempfile.TemporaryDirectory()

os.environ["API_DATA_DIR"] = _api_data_dir.name
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["FLASK_SECRET_KEY"] = "test-secret-key"
os.environ["FLASK_ENV"] = "development"

import app
from encryption import decrypt_value, encrypt_value


class AccountEncryptionTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.accounts_file = Path(self.temp_dir.name) / "accounts.txt"
        self.original_accounts_file = app.ACCOUNTS_FILE
        app.ACCOUNTS_FILE = str(self.accounts_file)
        app.invalidate_accounts_cache()

    def tearDown(self):
        app.ACCOUNTS_FILE = self.original_accounts_file
        app.invalidate_accounts_cache()
        self.temp_dir.cleanup()

    def test_load_accounts_unwraps_nested_encrypted_fields(self):
        account = {
            "email": "alice@example.com",
            "password": "password",
            "client_id": "client-id",
            "refresh_token": "refresh-token",
        }
        fields = [encrypt_value(encrypt_value(account[key])) for key in account]
        self.accounts_file.write_text("----".join(fields) + "\n")

        loaded = app.load_accounts()

        self.assertEqual(loaded, [account])

    def test_load_accounts_unwraps_deeply_nested_encrypted_fields(self):
        value = "alice@example.com"
        for _ in range(12):
            value = encrypt_value(value)
        fields = [value, encrypt_value("password"), encrypt_value("client-id"), encrypt_value("refresh-token")]
        self.accounts_file.write_text("----".join(fields) + "\n")

        loaded = app.load_accounts()

        self.assertEqual(loaded[0]["email"], "alice@example.com")

    def test_save_accounts_writes_single_encryption_layer(self):
        account = {
            "email": encrypt_value("alice@example.com"),
            "password": encrypt_value("password"),
            "client_id": encrypt_value("client-id"),
            "refresh_token": encrypt_value("refresh-token"),
        }

        app.save_accounts([account], already_deduplicated=True)

        line = next(
            line
            for line in self.accounts_file.read_text().splitlines()
            if line and not line.startswith("#")
        )
        saved_email = line.split("----", 1)[0]
        decrypted_email = decrypt_value(saved_email)
        self.assertEqual(decrypted_email, "alice@example.com")
        self.assertFalse(decrypted_email.startswith("ENC:"))

    def test_load_accounts_skips_unreadable_encrypted_rows(self):
        bad_row = "ENC:not-a-valid-token----password----client-id----refresh-token"
        good_fields = [
            encrypt_value(value)
            for value in ["alice@example.com", "password", "client-id", "refresh-token"]
        ]
        self.accounts_file.write_text(bad_row + "\n" + "----".join(good_fields) + "\n")

        loaded = app.load_accounts()

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["email"], "alice@example.com")

    def test_save_accounts_preserves_unreadable_encrypted_rows(self):
        bad_row = "ENC:not-a-valid-token----password----client-id----refresh-token"
        good_fields = [
            encrypt_value(value)
            for value in ["alice@example.com", "password", "client-id", "refresh-token"]
        ]
        self.accounts_file.write_text(bad_row + "\n" + "----".join(good_fields) + "\n")
        loaded = app.load_accounts()

        app.save_accounts(loaded, already_deduplicated=True)

        self.assertIn(bad_row, self.accounts_file.read_text().splitlines())

    def test_save_accounts_rejects_unreadable_encrypted_fields_without_truncating(self):
        original = "plain@example.com----password----client-id----refresh-token\n"
        self.accounts_file.write_text(original)
        account = {
            "email": "safe@example.com",
            "password": "password",
            "client_id": "ENC:not-a-valid-token",
            "refresh_token": "refresh-token",
        }

        with self.assertRaises(ValueError):
            app.save_accounts([account], already_deduplicated=True)

        self.assertEqual(self.accounts_file.read_text(), original)

    def _authenticated_client(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["authenticated"] = True
            session["expires_at"] = 9999999999
        return client

    def test_check_duplicates_skips_unreadable_encrypted_rows(self):
        bad_row = "ENC:not-a-valid-token----password----client-id----refresh-token"
        duplicate_fields = [
            encrypt_value(value)
            for value in ["alice@example.com", "password", "client-id", "refresh-token"]
        ]
        self.accounts_file.write_text(
            bad_row + "\n" + "----".join(duplicate_fields) + "\n" + "----".join(duplicate_fields) + "\n"
        )

        response = self._authenticated_client().get("/api/check-duplicates")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["duplicate_count"], 1)

    def test_clean_duplicates_preserves_unreadable_encrypted_rows(self):
        bad_row = "ENC:not-a-valid-token----password----client-id----refresh-token"
        duplicate_fields = [
            encrypt_value(value)
            for value in ["alice@example.com", "password", "client-id", "refresh-token"]
        ]
        self.accounts_file.write_text(
            bad_row + "\n" + "----".join(duplicate_fields) + "\n" + "----".join(duplicate_fields) + "\n"
        )

        response = self._authenticated_client().post("/api/clean-duplicates")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["removed"], 1)
        lines = [line for line in self.accounts_file.read_text().splitlines() if line and not line.startswith("#")]
        self.assertIn(bad_row, lines)
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
