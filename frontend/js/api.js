/**
 * PhishGuard AI - API Client
 * Handles all backend communication
 * FIXED: Correct endpoint paths to match backend routes
 */

class APIClient {
    constructor() {
        // FIXED: Remove /api prefix since backend routes include it
        this.baseURL = window.location.hostname === 'localhost'
        ? 'http://localhost:5000'
        : 'https://phising-detection-onik.onrender.com';
        
        console.log('✅ APIClient initialized with baseURL:', this.baseURL);
    }

    /**
     * Get auth token from localStorage
     */
    getToken() {
        return localStorage.getItem('token');
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.getToken();
    }

    /**
     * Validate token with backend
     */
    async validateToken() {
        const token = this.getToken();
        if (!token) return false;

        try {
            const response = await fetch(`${this.baseURL}/auth/validate`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            return response.ok;
        } catch (error) {
            console.error('Token validation error:', error);
            return false;
        }
    }

    /**
     * Register new user
     */
    async register(username, email, password) {
        const response = await fetch(`${this.baseURL}/auth/register`, {
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

        // Save token
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));

        return data;
    }

    /**
     * Login user
     */
    async login(email, password) {
        const response = await fetch(`${this.baseURL}/auth/login`, {
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

        // Save token
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));

        return data;
    }

    /**
     * Logout user
     */
    logout() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        window.location.href = 'login.html';
    }

    /**
     * Get user profile
     */
    async getProfile() {
        const token = this.getToken();
        if (!token) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseURL}/auth/profile`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get profile');
        }

        return data;
    }

    /**
     * Scan URL (public endpoint - no auth required)
     * FIXED: Uses /api/scan endpoint
     */
    async scanURL(url) {
        console.log('🔍 Scanning URL:', url);

        const response = await fetch(`${this.baseURL}/api/scan-enhanced`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        console.log('📦 Raw API response:', data);

        if (!response.ok) {
            throw new Error(data.error || 'Scan failed');
        }

        // ✅ Return the data AS-IS - backend already formats it correctly
        console.log('✅ Final response:', data);
        return data;
    }

    /**
     * Scan URL (authenticated endpoint - saves to history)
     * FIXED: Uses /api/predict endpoint
     */
    async scanURLAuthenticated(url) {
        const token = this.getToken();
        
        console.log('🔍 Scanning URL (authenticated):', url);

        const response = await fetch(`${this.baseURL}/api/predict`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': token ? `Bearer ${token}` : ''
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        console.log('📦 Raw API response (auth):', data);

        if (!response.ok) {
            throw new Error(data.error || 'Scan failed');
        }

        // ✅ Return the data AS-IS - backend already formats it correctly
        console.log('✅ Final response (auth):', data);
        return data;
    }

    /**
     * Alias methods for compatibility
     */
    async predictURL(url) {
        return this.scanURL(url);
    }

    async predictURLAuthenticated(url) {
        return this.scanURLAuthenticated(url);
    }

    /**
     * Get scan history (authenticated)
     */
    async getScanHistory(limit = 50) {
        const token = this.getToken();
        if (!token) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseURL}/api/history?limit=${limit}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get history');
        }

        return data;
    }

    /**
     * Get user statistics (authenticated)
     */
    async getStats() {
        const token = this.getToken();
        if (!token) {
            throw new Error('Not authenticated');
        }

        const response = await fetch(`${this.baseURL}/api/stats`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to get stats');
        }

        return data;
    }
}

// Create and expose global API instance
window.API = new APIClient();
console.log('✅ Global API instance created');