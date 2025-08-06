document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

const token = localStorage.getItem('token');
const username = jwt_decode(token).username;

document.getElementById('mockTestForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const testName = document.getElementById('testName').value;
    const score = document.getElementById('score').value;

    const response = await fetch('http://localhost:3000/api/mock-tests', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ user: username, testName, score }),
    });
    if (response.ok) {
        document.getElementById('testResults').style.display = 'block';
    } else {
        alert('Failed to submit test');
    }
});