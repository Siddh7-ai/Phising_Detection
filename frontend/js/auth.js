/**
 * Authentication helper functions
 * Handles auth state management across pages
 */

/**
 * Check if user is authenticated
 * Redirects to login if not authenticated
 */
async function requireAuth() {
    if (!API.isAuthenticated()) {
        window.location.href = 'login.html';
        return false;
    }
    
    // Validate token with backend
    const isValid = await API.validateToken();
    
    if (!isValid) {
        window.location.href = 'login.html';
        return false;
    }
    
    return true;
}

/*
 * Initialize authentication state on page load
 * For protected pages (index.html)
 */
async function initAuth() {
    const isAuth = await requireAuth();
    
    if (isAuth) {
        try {
            // Load user profile
            const profile = await API.getProfile();
            
            // Update UI with user info
            if (document.getElementById('username')) {
                document.getElementById('username').textContent = profile.user.username;
            }
            
            return profile.user;
        } catch (error) {
            console.error('Failed to load profile:', error);
            API.logout();
        }
    }
}

/**
 * Logout handler
 */
function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        API.logout();
    }
}