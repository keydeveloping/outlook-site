# Data Directory

Folder ini berisi data runtime aplikasi yang **TIDAK** di-commit ke Git.

## File yang ada:
- `accounts.txt` - Data akun Outlook (encrypted)
- `api_keys.json` - API keys yang terdaftar
- `api_usage.json` - Log penggunaan API

## Catatan:
- File-file di folder ini akan di-create otomatis saat aplikasi pertama kali jalan
- Jangan commit file sensitive ke repository
- Untuk backup, copy seluruh folder `data/` ke lokasi aman
