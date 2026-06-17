"""
API Key Management Module
Handles generation, storage, verification, revocation, and usage tracking
"""
import json
import time
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List
import threading

# Files to store API key metadata, usage logs, and persistent rate-limit windows.
# Raw API keys are never stored; data/api_keys.json is keyed by SHA-256 hashes.
DATA_DIR = Path(__file__).parent / 'data'
API_KEYS_FILE = DATA_DIR / 'api_keys.json'
API_USAGE_FILE = DATA_DIR / 'api_usage.json'
API_RATE_LIMIT_FILE = DATA_DIR / 'api_rate_limits.json'

# Re-entrant lock for atomic load/update/save sequences.
_lock = threading.RLock()


class APIKeyManager:
    """Manages API keys with encryption, permissions, rate limiting, and usage tracking"""

    PERMISSIONS = {
        'read-only': ['GET'],
        'read-write': ['GET', 'POST', 'PATCH'],
        'admin': ['GET', 'POST', 'PATCH', 'DELETE']
    }

    # Rate limit presets (requests per window)
    RATE_LIMITS = {
        'unlimited': 0,       # No limit
        '10/min': 10,
        '30/min': 30,
        '60/min': 60,
        '100/min': 100,
        '300/min': 300,
        '600/min': 600,
        '1000/hour': 1000,
        '5000/hour': 5000,
        '10000/hour': 10000,
    }

    def __init__(self):
        self.keys_file = API_KEYS_FILE
        self.usage_file = API_USAGE_FILE
        self.rate_file = API_RATE_LIMIT_FILE
        self._ensure_files_exist()
        self._rate_tracker = self._load_rate_tracker()
        self._rate_lock = threading.Lock()

    def _ensure_files_exist(self):
        """Create storage files if they don't exist"""
        DATA_DIR.mkdir(exist_ok=True)
        for path in (self.keys_file, self.usage_file, self.rate_file):
            if not path.exists():
                path.write_text(json.dumps({}, indent=2))

    def _load_keys(self) -> Dict:
        """Load API keys from storage"""
        with _lock:
            try:
                return json.loads(self.keys_file.read_text())
            except (json.JSONDecodeError, OSError):
                return {}

    def _save_keys(self, keys: Dict):
        """Save API keys to storage"""
        with _lock:
            self.keys_file.write_text(json.dumps(keys, indent=2))

    def _load_usage(self) -> Dict:
        """Load usage logs"""
        with _lock:
            try:
                return json.loads(self.usage_file.read_text())
            except (json.JSONDecodeError, OSError):
                return {}

    def _save_usage(self, usage: Dict):
        """Save usage logs"""
        with _lock:
            self.usage_file.write_text(json.dumps(usage, indent=2))

    def _load_rate_tracker(self) -> Dict:
        """Load persisted rate-limit request timestamps"""
        with _lock:
            try:
                return json.loads(self.rate_file.read_text())
            except (json.JSONDecodeError, OSError):
                return {}

    def _save_rate_tracker(self):
        """Persist rate-limit request timestamps"""
        with _lock:
            self.rate_file.write_text(json.dumps(self._rate_tracker, indent=2))

    def _hash_key(self, raw_key: str) -> str:
        """Hash API key for secure storage"""
        return hashlib.sha256(raw_key.encode()).hexdigest()

    def generate_key(self, name: str, permission: str = 'read-only',
                    expires_days: Optional[int] = None,
                    rate_limit: str = '60/min') -> Dict:
        """
        Generate a new API key

        Args:
            name: Descriptive name for the key (e.g., "Email Bot Agent")
            permission: 'read-only', 'read-write', or 'admin'
            expires_days: Days until expiration (None = never expires)
            rate_limit: Rate limit preset (e.g., '60/min', '1000/hour', 'unlimited')

        Returns:
            Dict with raw key (show once!) and metadata
        """
        if permission not in self.PERMISSIONS:
            raise ValueError(f"Invalid permission. Choose from: {list(self.PERMISSIONS.keys())}")

        if rate_limit not in self.RATE_LIMITS:
            raise ValueError(f"Invalid rate limit. Choose from: {list(self.RATE_LIMITS.keys())}")

        # Generate secure random key
        raw_key = f"owb_{secrets.token_urlsafe(32)}"
        key_hash = self._hash_key(raw_key)

        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()

        # Parse rate limit
        rate_limit_count = self.RATE_LIMITS[rate_limit]
        rate_limit_window = 60 if '/min' in rate_limit else 3600 if '/hour' in rate_limit else 0

        # Create key metadata
        key_data = {
            'name': name,
            'permission': permission,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at,
            'revoked': False,
            'last_used': None,
            'usage_count': 0,
            'rate_limit': rate_limit,
            'rate_limit_count': rate_limit_count,
            'rate_limit_window': rate_limit_window
        }

        # Store metadata under the SHA-256 key hash; the raw key is returned once and never saved.
        with _lock:
            keys = self._load_keys()
            keys[key_hash] = key_data
            self._save_keys(keys)

        return {
            'key': raw_key,  # Show this to user ONCE
            'name': name,
            'permission': permission,
            'expires_at': expires_at,
            'rate_limit': rate_limit
        }

    def verify_key(self, raw_key: str, method: str = 'GET') -> Dict:
        """
        Verify API key, check permissions, and enforce rate limits

        Args:
            raw_key: The API key from request header
            method: HTTP method (GET, POST, etc.)

        Returns:
            Dict with 'valid' (bool), 'error' (str), and 'key_data' (dict if valid)
        """
        if not raw_key:
            return {'valid': False, 'error': 'Missing API key', 'key_data': None}

        key_hash = self._hash_key(raw_key)
        with _lock:
            keys = self._load_keys()

            if key_hash not in keys:
                return {'valid': False, 'error': 'Invalid API key', 'key_data': None}

            key_data = keys[key_hash]

            # Backward compatibility for older data that marked keys revoked instead of deleting them.
            if key_data.get('revoked'):
                return {'valid': False, 'error': 'API key has been revoked', 'key_data': None}

            if key_data.get('expires_at'):
                expires = datetime.fromisoformat(key_data['expires_at'])
                if datetime.now() > expires:
                    return {'valid': False, 'error': 'API key has expired', 'key_data': None}

            allowed_methods = self.PERMISSIONS.get(key_data['permission'], [])
            if method not in allowed_methods:
                return {'valid': False, 'error': 'Method not allowed for this API key', 'key_data': None}

            rate_limit = key_data.get('rate_limit')
            if rate_limit and not self._check_rate_limit(key_hash, key_data):
                return {
                    'valid': False,
                    'error': f'Rate limit exceeded: {rate_limit}',
                    'key_data': None,
                    'rate_limited': True
                }

            key_data['last_used'] = datetime.now().isoformat()
            key_data['usage_count'] = key_data.get('usage_count', 0) + 1
            self._save_keys(keys)
            self._log_usage(key_hash, method)

        return {'valid': True, 'error': None, 'key_data': key_data}

    def _check_rate_limit(self, key_hash: str, key_data: Dict) -> bool:
        """
        Check if the API key has exceeded its rate limit

        Returns:
            True if within limit, False if rate limited
        """
        rate_limit_count = key_data.get('rate_limit_count', 0)
        rate_limit_window = key_data.get('rate_limit_window', 0)

        # Unlimited or not configured
        if rate_limit_count == 0 or rate_limit_window == 0:
            return True

        now = time.time()
        window_start = now - rate_limit_window

        with self._rate_lock:
            # Initialize tracker for this key
            if key_hash not in self._rate_tracker:
                self._rate_tracker[key_hash] = []

            # Remove old timestamps outside the window
            self._rate_tracker[key_hash] = [
                ts for ts in self._rate_tracker[key_hash]
                if ts > window_start
            ]

            # Check if limit exceeded
            if len(self._rate_tracker[key_hash]) >= rate_limit_count:
                return False

            # Add current request and persist the sliding window so restarts do not reset limits.
            self._rate_tracker[key_hash].append(now)
            self._save_rate_tracker()

        return True

    def _log_usage(self, key_hash: str, method: str):
        """Log API usage for analytics"""
        usage = self._load_usage()

        if key_hash not in usage:
            usage[key_hash] = []

        # Keep only last 100 logs per key
        usage[key_hash].append({
            'timestamp': datetime.now().isoformat(),
            'method': method
        })
        usage[key_hash] = usage[key_hash][-100:]

        self._save_usage(usage)

    def revoke_key(self, key_prefix: str) -> bool:
        """Revoke (delete) an API key by its hash prefix (or full hash)"""
        keys = self._load_keys()
        # Try matching by prefix
        for key_hash in list(keys.keys()):
            if key_hash.startswith(key_prefix.rstrip('.')) or key_hash == key_prefix:
                del keys[key_hash]
                self._save_keys(keys)
                return True
        return False

    def list_keys(self) -> List[Dict]:
        """List all active API keys (without exposing the actual keys, excludes revoked)"""
        keys = self._load_keys()
        result = []

        for key_hash, data in keys.items():
            # Skip revoked keys
            if data.get('revoked', False):
                continue

            result.append({
                'id': key_hash[:8] + '...',  # Short ID for display
                'name': data['name'],
                'permission': data['permission'],
                'created_at': data['created_at'],
                'expires_at': data['expires_at'],
                'revoked': data.get('revoked', False),
                'last_used': data.get('last_used'),
                'usage_count': data.get('usage_count', 0),
                'rate_limit': data.get('rate_limit', '60/min')
            })

        return sorted(result, key=lambda x: x['created_at'], reverse=True)

    def get_key_stats(self, key_prefix: str) -> Optional[Dict]:
        """Get detailed usage stats for a key by hash prefix"""
        usage = self._load_usage()
        keys = self._load_keys()

        key_hash = None
        for h in keys:
            if h.startswith(key_prefix.rstrip('.')) or h == key_prefix:
                key_hash = h
                break

        if not key_hash or key_hash not in keys:
            return None

        key_data = keys[key_hash]
        logs = usage.get(key_hash, [])

        # Calculate stats
        total_requests = len(logs)
        methods_count = {}
        for log in logs:
            method = log['method']
            methods_count[method] = methods_count.get(method, 0) + 1

        # Last 24 hours
        yesterday = datetime.now() - timedelta(days=1)
        recent_requests = [
            log for log in logs
            if datetime.fromisoformat(log['timestamp']) > yesterday
        ]

        return {
            'name': key_data['name'],
            'total_requests': total_requests,
            'recent_24h': len(recent_requests),
            'methods': methods_count,
            'last_used': key_data.get('last_used'),
            'logs': logs[-20:]  # Last 20 logs
        }


# Singleton instance
api_manager = APIKeyManager()
