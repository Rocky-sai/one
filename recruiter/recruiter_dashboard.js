// Ensure the jwt-decode library is loaded
if (typeof jwt_decode === 'undefined') {
    console.error('jwt-decode library is not loaded. Please ensure the script is included in recruiter_dashboard.html.');
    alert('An error occurred while loading the page. Please try again.');
    window.location.href = '../../index.html';
    throw new Error('jwt-decode not loaded');
}

// Ensure Chart.js is loaded
if (typeof Chart === 'undefined') {
    console.error('Chart.js library is not loaded. Please ensure the script is included in recruiter_dashboard.html.');
    alert('An error occurred while loading the page. Please try again.');
    window.location.href = '../../index.html';
    throw new Error('Chart.js not loaded');
}

// Base URL for API requests
const API_BASE_URL = 'http://localhost:3000';

// Retrieve the token from localStorage
const token = localStorage.getItem('token');

// Debug: Log the token to inspect its value
console.log('Token retrieved from localStorage:', token);

// Check if the token exists and is a non-empty string
if (!token || typeof token !== 'string' || token.trim() === '') {
    console.warn('No valid token found in localStorage.');
    alert('Please log in to access the dashboard.');
    localStorage.removeItem('token');
    window.location.href = '../../index.html';
    return;
}

let username = '';
let suitabilityChartInstance = null;
let testScoreChartInstance = null;

// Utility function to show a loading state on a button
function showLoading(button, originalText) {
    button.disabled = true;
    button.innerHTML = `${originalText} <span class="spinner"></span>`;
}

// Utility function to hide the loading state on a button
function hideLoading(button, originalText) {
    button.disabled = false;
    button.innerHTML = originalText;
}

// Initialize the dashboard
async function initializeDashboard() {
    try {
        // Decode the JWT token
        const decoded = jwt_decode(token);
        console.log('Decoded token:', decoded);

        // Extract username and role
        username = decoded.username;
        const role = decoded.role;

        // Verify the user is a recruiter
        if (role !== 'Recruiter') {
            console.warn('User role is not Recruiter:', role);
            alert('Unauthorized access. Recruiters only.');
            localStorage.removeItem('token');
            window.location.href = '../../index.html';
            return;
        }

        // Check if the token is expired
        const currentTime = Math.floor(Date.now() / 1000);
        if (decoded.exp && decoded.exp < currentTime) {
            console.warn('Token has expired:', decoded.exp);
            alert('Your session has expired. Please log in again.');
            localStorage.removeItem('token');
            window.location.href = '../../index.html';
            return;
        }

        // Display the username on the dashboard
        const usernameElement = document.getElementById('username');
        if (usernameElement) {
            usernameElement.textContent = username;
        } else {
            console.error('Username element not found in the DOM.');
            alert('Failed to load dashboard. Please try again.');
        }
    } catch (error) {
        console.error('Error decoding token:', error.message, error.stack);
        alert('Invalid token. Please log in again.');
        localStorage.removeItem('token');
        window.location.href = '../../index.html';
    }
}

// Add logout functionality
function setupLogout() {
    const logoutButton = document.getElementById('logout');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            console.log('Logging out user:', username);
            localStorage.removeItem('token');
            window.location.href = '../../index.html';
        });
    } else {
        console.error('Logout button not found in the DOM.');
        alert('Logout functionality is unavailable. Please refresh the page.');
    }
}

// Handle resume analysis form submission
function setupResumeAnalysis() {
    const resumeAnalysisForm = document.getElementById('resumeAnalysisForm');
    const analyzeButton = resumeAnalysisForm?.querySelector('button[type="submit"]');
    const originalButtonText = analyzeButton?.textContent || 'Analyze Resume';

    if (!resumeAnalysisForm || !analyzeButton) {
        console.error('Resume analysis form or submit button not found in the DOM.');
        return;
    }

    resumeAnalysisForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Show loading state
        showLoading(analyzeButton, originalButtonText);

        const formData = new FormData();
        const candidateInput = document.getElementById('candidate');
        const jobDescriptionInput = document.getElementById('jobDescription');
        const resumeInput = document.getElementById('resume');

        if (!candidateInput.value || !jobDescriptionInput.value || !resumeInput.files[0]) {
            alert('Please fill in all fields and upload a resume.');
            hideLoading(analyzeButton, originalButtonText);
            return;
        }

        formData.append('candidate', candidateInput.value);
        formData.append('jobDescription', jobDescriptionInput.value);
        formData.append('resume', resumeInput.files[0]);

        try {
            const response = await fetch(`${API_BASE_URL}/api/recruiter/analyze-resume`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
                body: formData,
            });

            const result = await response.json();
            hideLoading(analyzeButton, originalButtonText);

            if (result.success) {
                const { suitabilityScore, missingSkills, capabilityAnalysis } = result.analysis;
                const analysisDetails = document.getElementById('analysisDetails');
                analysisDetails.innerHTML = `
                    <h3>Analysis Results</h3>
                    <p><strong>Suitability Score:</strong> ${suitabilityScore}%</p>
                    <p><strong>Missing Skills:</strong> ${missingSkills.length > 0 ? missingSkills.join(', ') : 'None'}</p>
                    <p><strong>Capability Analysis:</strong> ${capabilityAnalysis}</p>
                `;

                // Destroy previous chart instance if it exists
                if (suitabilityChartInstance) {
                    suitabilityChartInstance.destroy();
                }

                // Visualize the suitability score using Chart.js
                const ctx = document.getElementById('suitabilityChart').getContext('2d');
                suitabilityChartInstance = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['Suitability Score'],
                        datasets: [{
                            label: 'Score (%)',
                            data: [suitabilityScore],
                            backgroundColor: 'rgba(59, 130, 246, 0.2)',
                            borderColor: 'rgba(59, 130, 246, 1)',
                            borderWidth: 1,
                        }],
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100,
                                title: {
                                    display: true,
                                    text: 'Score (%)',
                                    font: { size: 14 },
                                },
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Metric',
                                    font: { size: 14 },
                                },
                            },
                        },
                        plugins: {
                            legend: {
                                display: false,
                            },
                        },
                    },
                });

                // Scroll to results
                document.getElementById('analysisResults').scrollIntoView({ behavior: 'smooth' });
            } else {
                console.error('Resume analysis failed:', result.message);
                alert(`Failed to analyze resume: ${result.message}`);
            }
        } catch (error) {
            console.error('Error analyzing resume:', error.message, error.stack);
            alert('An error occurred while analyzing the resume. Please try again.');
            hideLoading(analyzeButton, originalButtonText);
        }
    });
}

// Handle mock test assignment form submission
function setupMockTestAssignment() {
    const mockTestForm = document.getElementById('mockTestForm');
    const assignButton = mockTestForm?.querySelector('button[type="submit"]');
    const originalButtonText = assignButton?.textContent || 'Assign Test';

    if (!mockTestForm || !assignButton) {
        console.error('Mock test form or submit button not found in the DOM.');
        return;
    }

    mockTestForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        // Show loading state
        showLoading(assignButton, originalButtonText);

        try {
            const candidate = document.getElementById('mockCandidate').value;
            const testType = document.getElementById('testType').value;
            const duration = parseInt(document.getElementById('duration').value);
            const questionsInput = document.getElementById('questions').value;

            if (!candidate || !testType || !duration || !questionsInput) {
                alert('Please fill in all fields.');
                hideLoading(assignButton, originalButtonText);
                return;
            }

            if (isNaN(duration) || duration <= 0) {
                alert('Duration must be a positive number.');
                hideLoading(assignButton, originalButtonText);
                return;
            }

            let questions;
            try {
                questions = JSON.parse(questionsInput);
                if (!Array.isArray(questions) || questions.length === 0) {
                    throw new Error('Questions must be a non-empty array.');
                }
                for (const q of questions) {
                    if (!q.question || !q.correctAnswer) {
                        throw new Error('Each question must have a "question" and "correctAnswer" field.');
                    }
                }
            } catch (parseError) {
                console.error('Invalid questions JSON:', parseError.message);
                alert('Invalid questions format. Please provide a valid JSON array with "question" and "correctAnswer" fields.');
                hideLoading(assignButton, originalButtonText);
                return;
            }

            const data = {
                candidate,
                testType,
                duration,
                questions,
            };

            const response = await fetch(`${API_BASE_URL}/api/recruiter/assign-mock-test`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            const result = await response.json();
            hideLoading(assignButton, originalButtonText);

            if (result.success) {
                alert('Mock test assigned successfully!');
                mockTestForm.reset();
            } else {
                console.error('Mock test assignment failed:', result.message);
                alert(`Failed to assign mock test: ${result.message}`);
            }
        } catch (error) {
            console.error('Error assigning mock test:', error.message, error.stack);
            alert('An error occurred while assigning the mock test. Please try again.');
            hideLoading(assignButton, originalButtonText);
        }
    });
}

// Handle fetching and displaying mock test results
function setupMockTestResults() {
    const fetchResultsButton = document.getElementById('fetchResults');
    const originalButtonText = fetchResultsButton?.textContent || 'Fetch Results';

    if (!fetchResultsButton) {
        console.error('Fetch results button not found in the DOM.');
        return;
    }

    fetchResultsButton.addEventListener('click', async () => {
        // Show loading state
        showLoading(fetchResultsButton, originalButtonText);

        const candidate = document.getElementById('resultsCandidate').value;
        if (!candidate) {
            alert('Please enter a candidate username.');
            hideLoading(fetchResultsButton, originalButtonText);
            return;
        }

        try {
            const response = await fetch(`${API_BASE_URL}/api/recruiter/mock-test-results/${candidate}`, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });

            const result = await response.json();
            hideLoading(fetchResultsButton, originalButtonText);

            if (result.success) {
                const tests = result.tests;
                const testDetails = document.getElementById('testDetails');

                if (tests.length === 0) {
                    testDetails.innerHTML = '<p>No completed tests found for this candidate.</p>';
                    return;
                }

                // Display the latest test result
                const latestTest = tests[0];
                testDetails.innerHTML = `
                    <h3>Test Results</h3>
                    <p><strong>Test Type:</strong> ${latestTest.testType}</p>
                    <p><strong>Score:</strong> ${latestTest.score}%</p>
                    <p><strong>Evaluation:</strong> ${latestTest.evaluation}</p>
                    <p><strong>Submitted At:</strong> ${new Date(latestTest.submittedAt).toLocaleString()}</p>
                `;

                // Destroy previous chart instance if it exists
                if (testScoreChartInstance) {
                    testScoreChartInstance.destroy();
                }

                // Visualize the test score using Chart.js
                const ctx = document.getElementById('testScoreChart').getContext('2d');
                testScoreChartInstance = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: ['Test Score'],
                        datasets: [{
                            label: 'Score (%)',
                            data: [latestTest.score],
                            backgroundColor: 'rgba(16, 185, 129, 0.2)',
                            borderColor: 'rgba(16, 185, 129, 1)',
                            borderWidth: 1,
                        }],
                    },
                    options: {
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100,
                                title: {
                                    display: true,
                                    text: 'Score (%)',
                                    font: { size: 14 },
                                },
                            },
                            x: {
                                title: {
                                    display: true,
                                    text: 'Metric',
                                    font: { size: 14 },
                                },
                            },
                        },
                        plugins: {
                            legend: {
                                display: false,
                            },
                        },
                    },
                });

                // Scroll to results
                document.getElementById('testResults').scrollIntoView({ behavior: 'smooth' });
            } else {
                console.error('Failed to fetch mock test results:', result.message);
                alert(`Failed to fetch mock test results: ${result.message}`);
            }
        } catch (error) {
            console.error('Error fetching mock test results:', error.message, error.stack);
            alert('An error occurred while fetching mock test results. Please try again.');
            hideLoading(fetchResultsButton, originalButtonText);
        }
    });
}

// Initialize the dashboard and setup event listeners
document.addEventListener('DOMContentLoaded', () => {
    initializeDashboard();
    setupLogout();
    setupResumeAnalysis();
    setupMockTestAssignment();
    setupMockTestResults();
});
