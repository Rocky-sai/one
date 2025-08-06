document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'recruiter_dashboard.html';
});

const token = localStorage.getItem('token');

const updateApplicationList = (applications) => {
    const list = document.querySelector('#applicationList ul');
    list.innerHTML = applications.map(app => `
        <li>
            ${app.candidate} applied for ${app.job} (Status: ${app.status})
            <button onclick="showUpdateForm('${app._id}', '${app.candidate}', '${app.job}', '${app.status}', '${app.feedback || ''}')">Update</button>
        </li>
    `).join('');
};

const fetchApplications = async () => {
    const response = await fetch('http://localhost:3000/api/applications', {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const applications = await response.json();
        updateApplicationList(applications);
    } else {
        alert('Failed to fetch applications');
    }
};

window.showUpdateForm = (id, candidate, job, status, feedback) => {
    const form = document.getElementById('updateApplicationForm');
    form.style.display = 'block';
    document.getElementById('appCandidate').textContent = candidate;
    document.getElementById('appJob').textContent = job;
    document.getElementById('appStatus').value = status;
    document.getElementById('appFeedback').value = feedback;
    form.dataset.appId = id;
};

document.getElementById('updateApplicationForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const appId = e.target.dataset.appId;
    const status = document.getElementById('appStatus').value;
    const feedback = document.getElementById('appFeedback').value;

    await fetch(`http://localhost:3000/api/applications/${appId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ status, feedback }),
    });
    fetchApplications();
    document.getElementById('updateApplicationForm').style.display = 'none';
});

fetchApplications();