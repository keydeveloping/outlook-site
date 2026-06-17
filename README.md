# Outlook Web Inbox

Web-based Outlook email client with multi-account support, encryption, API key management, and AI agent integration.

## Features

- 🔐 **Full Encryption** - All sensitive data encrypted at rest (accounts, credentials, API keys)
- 👥 **Multi-Account** - Manage multiple Outlook accounts in one interface
- 🔑 **API Key System** - Rate-limited API access for AI agents and automation
- 🚀 **Production Ready** - Docker support, security hardening, health checks
- 📧 **Email Management** - Read, search, and manage emails via web interface
- 🤖 **Agent API** - RESTful API for AI agent integration with permission controls

## Quick Start (Docker)

### 1. Clone and Configure

```bash
cd outlook-web-inbox

# Create data directory
mkdir -p data

# Generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Set Environment Variables

Create a `.env` file or set variables:

```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="your-secure-password-here"
export ENCRYPTION_KEY="your-generated-fernet-key-here"
```

### 3. Deploy

```bash
docker-compose up -d
```

Access the application at: `http://localhost:5000`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_SECRET_KEY` | Random | Flask session encryption key |
| `ADMIN_USERNAME` | `admin` | Admin login username |
| `ADMIN_PASSWORD` | `admin123` | Admin login password (change this!) |
| `ENCRYPTION_KEY` | None | Fernet key for data encryption |
| `RATE_LIMIT_ENABLED` | `true` | Enable login rate limiting |
| `RATE_LIMIT_ATTEMPTS` | `5` | Max login attempts before lockout |
| `RATE_LIMIT_WINDOW` | `900` | Lockout duration in seconds (15 min) |
| `MAX_UPLOAD_SIZE` | `10` | Max file upload size in MB |
| `FLASK_ENV` | `production` | Flask environment |

## API Key Management

### Generate API Key

Access the API Keys page at `/api-keys` or use the API:

```bash
curl -X POST http://localhost:5000/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My AI Agent",
    "permission": "read-only",
    "rate_limit": "60/min",
    "expires_days": 30
  }'
```

### Rate Limit Options

- `unlimited` - No rate limit
- `10/min`, `30/min`, `60/min`, `100/min`, `300/min`, `600/min` - Per minute
- `1000/hour`, `5000/hour`, `10000/hour` - Per hour

### Permission Levels

- `read-only` - GET requests only
- `read-write` - GET, POST, PATCH
- `admin` - Full access including DELETE

### Using API Keys

Include the API key in the `X-API-Key` header:

```bash
curl http://localhost:5000/api/v1/agent/accounts \
  -H "X-API-Key: owb_your-api-key-here"
```

## Agent API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agent/accounts` | List all email accounts |
| GET | `/api/v1/agent/inbox/<email>` | Get inbox messages |
| GET | `/api/v1/agent/message/<email>/<id>` | Get specific message |
| GET | `/api/v1/agent/search/<email>?q=query` | Search messages |

## Security Features

✅ **Non-root Docker user** - Runs as unprivileged user  
✅ **Multi-stage build** - Minimal attack surface  
✅ **Encryption at rest** - All sensitive data encrypted  
✅ **Rate limiting** - Protection against brute force  
✅ **API key controls** - Fine-grained access control  
✅ **Health checks** - Automatic monitoring  
✅ **Security headers** - HTTP security enabled  
✅ **Resource limits** - Docker resource constraints  

## Production Deployment

### 1. Generate Secure Keys

```bash
# Flask secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Create `.env` File

```env
FLASK_SECRET_KEY=your-generated-secret-key
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-strong-password
ENCRYPTION_KEY=your-fernet-key
RATE_LIMIT_ENABLED=true
RATE_LIMIT_ATTEMPTS=5
RATE_LIMIT_WINDOW=900
```

### 3. Deploy with Docker Compose

```bash
docker-compose up -d
```

### 4. Set Up Reverse Proxy (Optional)

Example nginx configuration:

```nginx
server {
    listen 80;
    server_name outlook.yourdomain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 5. Enable HTTPS (Recommended)

Use Let's Encrypt with certbot:

```bash
sudo certbot --nginx -d outlook.yourdomain.com
```

## Adding Email Accounts

### Via Web Interface

1. Log in as admin
2. Click "Upload Accounts"
3. Select a text file with format:

```
email1@outlook.com----password1----client_id1----refresh_token1
email2@outlook.com----password2----client_id2----refresh_token2
```

### Via API

```bash
curl -X POST http://localhost:5000/api/upload-accounts \
  -F "file=@accounts.txt"
```

## Getting Outlook Refresh Tokens

1. Register app at [Azure Portal](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Get `client_id` from app registration
3. Use OAuth2 flow to get `refresh_token`

See [Microsoft Graph API documentation](https://docs.microsoft.com/en-us/graph/auth-v2-user) for details.

## Data Storage

All data is stored in the `./data` directory (mounted as volume):

- `accounts.txt` - Encrypted email accounts
- `api_keys.json` - Encrypted API keys
- `api_usage.json` - API usage logs

## Backup

```bash
# Backup data directory
tar -czf outlook-backup-$(date +%Y%m%d).tar.gz ./data

# Restore
tar -xzf outlook-backup-20260617.tar.gz
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker-compose logs outlook-web

# Check if port 5000 is in use
sudo lsof -i :5000
```

### Can't log in

- Verify `ADMIN_USERNAME` and `ADMIN_PASSWORD` are set correctly
- Check if you're locked out due to rate limiting (wait 15 minutes)

### Encryption errors

- Ensure `ENCRYPTION_KEY` is a valid Fernet key
- Generate new key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

### API rate limited

- Check your API key's rate limit in the UI
- Generate a new key with higher limit if needed

## Development

### Run without Docker

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export FLASK_ENV=development
export FLASK_DEBUG=1

# Run
python app.py
```

### Run tests

```bash
./test_api_keys.sh
```

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or PR.

## Support

For issues and questions, please open a GitHub issue.
