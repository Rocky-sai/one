// Configuration
const API_BASE_URL = 'http://localhost:8000';

// Check authentication
function checkAuth() {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    
    if (!token || role !== 'Admin') {
        alert('Please log in as an admin to access this page.');
        window.location.href = '../index.html';
        return null;
    }
    
    return { token, role };
}

// Initialize dashboard
function initializeDashboard() {
    const auth = checkAuth();
    if (!auth) return;
    
    // Verify token is still valid
    verifyToken(auth.token);
}

// Verify token validity
async function verifyToken(token) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/activities`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Token invalid');
        }
    } catch (error) {
        console.error('Token verification failed:', error);
        localStorage.clear();
        alert('Your session has expired. Please log in again.');
        window.location.href = '../index.html';
    }
}

// Setup logout functionality
function setupLogout() {
    const logoutBtn = document.getElementById('logout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to logout?')) {
                localStorage.clear();
                window.location.href = '../index.html';
            }
        });
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
    setupLogout();
});