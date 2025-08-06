document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

const token = localStorage.getItem('token');
const username = jwt_decode(token).username;

document.getElementById('codingForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const problem = document.getElementById('problem').value;
    const code = document.getElementById('code').value;

    const response = await fetch('http://localhost:3000/api/coding-practice', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ user: username, problem, code, output: 'Simulated output' }),
    });
    if (response.ok) {
        document.getElementById('codingResult').style.display = 'block';
    } else {
        alert('Failed to submit code');
    }
});