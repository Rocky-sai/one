// Configuration
const API_BASE_URL = 'http://localhost:8000';

// Check authentication and get user info
function checkAuth() {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    const username = localStorage.getItem('username');
    
    if (!token || role !== 'Candidate') {
        alert('Please log in as a candidate to access this page.');
        window.location.href = '../index.html';
        return null;
    }
    
    return { token, role, username };
}

// Initialize dashboard
function initializeDashboard() {
    const auth = checkAuth();
    if (!auth) return;
    
    // Display welcome message with username
    const welcomeSpan = document.querySelector('.welcome-message span');
    if (welcomeSpan && auth.username) {
        welcomeSpan.textContent = auth.username;
    }
    
    // Verify token is still valid
    verifyToken(auth.token);
}

// Verify token validity
async function verifyToken(token) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/jobs`, {
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

// Logout functionality
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

// Add loading states to navigation links
function setupNavigation() {
    const navLinks = document.querySelectorAll('nav a');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Add loading state
            const originalText = this.textContent;
            this.innerHTML = '<span class="loading"></span>' + originalText;
            this.style.pointerEvents = 'none';
            
            // Reset after a short delay (in case navigation fails)
            setTimeout(() => {
                this.textContent = originalText;
                this.style.pointerEvents = 'auto';
            }, 3000);
        });
    });
}

// Check for notifications or updates
async function checkNotifications() {
    const auth = checkAuth();
    if (!auth) return;
    
    try {
        // Check for new messages, test assignments, etc.
        const response = await fetch(`${API_BASE_URL}/api/chat-messages`, {
            headers: {
                'Authorization': `Bearer ${auth.token}`
            }
        });
        
        if (response.ok) {
            const messages = await response.json();
            // Add notification badges if there are new messages
            // This is a placeholder for notification logic
        }
    } catch (error) {
        console.error('Error checking notifications:', error);
    }
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
    setupLogout();
    setupNavigation();
    checkNotifications();
    
    // Periodically check token validity
    setInterval(() => {
        const auth = checkAuth();
        if (auth) {
            verifyToken(auth.token);
        }
    }, 300000); // Check every 5 minutes
});

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
        // Page became visible, check for updates
        checkNotifications();
    }
});

// Global error handler
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});