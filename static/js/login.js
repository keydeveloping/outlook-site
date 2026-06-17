// Initialize E2E encryption
let e2eEncryption = null;

// Load existing encryption key from localStorage
const existingKey = localStorage.getItem('e2eEncryptionKey');
const existingKeyId = localStorage.getItem('e2eEncryptionKeyId');

if (existingKey && E2EEncryption.isSupported()) {
    e2eEncryption = new E2EEncryption();
    e2eEncryption.init(existingKey, existingKeyId).catch(err => {
        console.error('Failed to load encryption key:', err);
        e2eEncryption = null;
    });
}

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const encryptionKey = document.getElementById('encryptionKey').value;
    const errorMessage = document.getElementById('errorMessage');
    const loginBtn = document.getElementById('loginBtn');

    // Reset error
    errorMessage.textContent = '';
    errorMessage.style.display = 'none';

    // Show loading state
    loginBtn.disabled = true;
    loginBtn.textContent = 'Signing in...';

    try {
        // Initialize E2E encryption if not already done
        if (!e2eEncryption && E2EEncryption.isSupported()) {
            e2eEncryption = new E2EEncryption();

            if (encryptionKey) {
                // User provided existing key
                await e2eEncryption.init(encryptionKey);
                localStorage.setItem('e2eEncryptionKey', encryptionKey);
                localStorage.setItem('e2eEncryptionKeyId', 'user-provided');
            } else {
                // Generate new key
                const keyInfo = await e2eEncryption.init();
                localStorage.setItem('e2eEncryptionKey', keyInfo.key);
                localStorage.setItem('e2eEncryptionKeyId', keyInfo.keyId);

                // Show generated key to user
                document.getElementById('generatedKey').textContent = keyInfo.key;
                document.getElementById('keyDisplay').style.display = 'block';

                // Wait for user to acknowledge
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            // Store token
            localStorage.setItem('authToken', data.token);

            // Make encryption available globally
            window.e2eEncryption = e2eEncryption;

            // Redirect to home page
            window.location.href = '/';
        } else {
            errorMessage.textContent = data.error || 'Login failed';
            errorMessage.style.display = 'block';
        }
    } catch (error) {
        console.error('Login error:', error);
        errorMessage.textContent = 'Network error. Please try again.';
        errorMessage.style.display = 'block';
    } finally {
        loginBtn.disabled = false;
        loginBtn.textContent = 'Sign In';
    }
});

// Copy key to clipboard
window.copyKey = function() {
    const key = document.getElementById('generatedKey').textContent;
    navigator.clipboard.writeText(key).then(() => {
        const btn = event.target;
        const originalText = btn.textContent;
        btn.textContent = '✓ Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    });
};
