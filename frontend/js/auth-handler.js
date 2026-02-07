/**
 * Authentication Handler for PhishGuard AI
 * Handles login/signup modal and authentication checks
 */

// ------------------------------------------------------------------
// AUTH MODAL MANAGEMENT
// ------------------------------------------------------------------

let authModalCallback = null;

/**
 * Show auth modal with a callback for successful auth
 * @param {string} action - 'download', 'share', or 'export'
 * @param {function} callback - Function to call after successful login
 */
function showAuthModal(action, callback) {
    const modal = document.getElementById('authModal');
    const title = document.getElementById('authModalTitle');
    const subtitle = document.getElementById('authModalSubtitle');
    
    // Set modal text based on action
    const actionTexts = {
        'download': {
            title: 'Login to Download',
            subtitle: 'Please login or create an account to download scan reports'
        },
        'share': {
            title: 'Login to Share',
            subtitle: 'Please login or create an account to share scan results'
        },
        'export': {
            title: 'Login to Export',
            subtitle: 'Please login or create an account to export scan reports'
        }
    };
    
    const text = actionTexts[action] || actionTexts['download'];
    title.textContent = text.title;
    subtitle.textContent = text.subtitle;
    
    // Store callback
    authModalCallback = callback;
    
    // Show modal
    modal.classList.remove('hidden');
    
    // Focus on email input
    setTimeout(() => {
        document.getElementById('loginEmail').focus();
    }, 300);
}

/**
 * Close auth modal
 */
function closeAuthModal() {
    const modal = document.getElementById('authModal');
    modal.classList.add('hidden');
    authModalCallback = null;
    
    // Clear forms
    document.getElementById('loginForm').reset();
    document.getElementById('signupForm').reset();
    hideError('loginError');
    hideError('signupError');
}

/**
 * Switch between login and signup tabs
 */
function switchAuthTab(tab) {
    // Update tabs
    document.querySelectorAll('.auth-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    
    // Update forms
    document.querySelectorAll('.auth-form').forEach(form => {
        form.classList.toggle('active', form.id === `${tab}Form`);
    });
    
    // Clear errors
    hideError('loginError');
    hideError('signupError');
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const btn = input.parentElement.querySelector('.toggle-password i');
    
    if (input.type === 'password') {
        input.type = 'text';
        btn.classList.remove('fa-eye');
        btn.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        btn.classList.remove('fa-eye-slash');
        btn.classList.add('fa-eye');
    }
}

/**
 * Show error message
 */
function showError(elementId, message) {
    const errorEl = document.getElementById(elementId);
    errorEl.textContent = message;
    errorEl.classList.add('show');
}

/**
 * Hide error message
 */
function hideError(elementId) {
    const errorEl = document.getElementById(elementId);
    errorEl.classList.remove('show');
}

// ------------------------------------------------------------------
// FORM HANDLERS
// ------------------------------------------------------------------

/**
 * Handle login form submission
 */
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const btn = document.getElementById('loginBtn');
    
    // Validation
    if (!email || !password) {
        showError('loginError', 'Please fill in all fields');
        return;
    }
    
    // Show loading
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Logging in...</span>';
    hideError('loginError');
    
    try {
        const response = await fetch('http://localhost:5000/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }
        
        // Save token and user
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        // Update UI
        updateUserDisplay(data.user.username);
        
        // Show success
        showToast('Login successful!', 'success');
        
        // Close modal
        closeAuthModal();
        
        // Execute callback if exists
        if (authModalCallback) {
            authModalCallback();
            authModalCallback = null;
        }
        
        // Reload stats
        if (typeof loadUserStats === 'function') {
            loadUserStats();
        }
        
    } catch (error) {
        console.error('Login error:', error);
        showError('loginError', error.message || 'Login failed. Please try again.');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> <span>Login</span>';
    }
}

/**
 * Handle signup form submission
 */
async function handleSignup(e) {
    e.preventDefault();
    
    const username = document.getElementById('signupUsername').value.trim();
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;
    const confirmPassword = document.getElementById('signupPasswordConfirm').value;
    const btn = document.getElementById('signupBtn');
    
    // Validation
    if (!username || !email || !password || !confirmPassword) {
        showError('signupError', 'Please fill in all fields');
        return;
    }
    
    if (password !== confirmPassword) {
        showError('signupError', 'Passwords do not match');
        return;
    }
    
    if (password.length < 8) {
        showError('signupError', 'Password must be at least 8 characters');
        return;
    }
    
    if (username.length < 3 || username.length > 20) {
        showError('signupError', 'Username must be 3-20 characters');
        return;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        showError('signupError', 'Username can only contain letters, numbers, and underscore');
        return;
    }
    
    // Show loading
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span>Creating account...</span>';
    hideError('signupError');
    
    try {
        const response = await fetch('http://localhost:5000/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }
        
        // Save token and user
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        // Update UI
        updateUserDisplay(data.user.username);
        
        // Show success
        showToast('Account created successfully!', 'success');
        
        // Close modal
        closeAuthModal();
        
        // Execute callback if exists
        if (authModalCallback) {
            authModalCallback();
            authModalCallback = null;
        }
        
    } catch (error) {
        console.error('Signup error:', error);
        showError('signupError', error.message || 'Registration failed. Please try again.');
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-user-plus"></i> <span>Create Account</span>';
    }
}

/**
 * Update user display in header
 */
function updateUserDisplay(username) {
    const usernameEl = document.getElementById('username');
    if (usernameEl) {
        usernameEl.textContent = username;
    }
}

/**
 * Check if user is authenticated
 */
function isAuthenticated() {
    const token = localStorage.getItem('token');
    return !!token;
}

/**
 * Get auth headers for API requests
 */
function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Content-Type': 'application/json',
        'Authorization': token ? `Bearer ${token}` : ''
    };
}

// ------------------------------------------------------------------
// EVENT LISTENERS
// ------------------------------------------------------------------

// Attach form handlers when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    // Signup form
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', handleSignup);
    }
    
    // Close modal on escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const modal = document.getElementById('authModal');
            if (modal && !modal.classList.contains('hidden')) {
                closeAuthModal();
            }
        }
    });
});