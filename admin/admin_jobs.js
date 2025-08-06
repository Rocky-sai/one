document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'admin_dashboard.html';
});

const token = localStorage.getItem('token');

const updateJobList = (jobs) => {
    const list = document.querySelector('#jobList ul');
    list.innerHTML = jobs.map(job => `<li>${job.title} - ${job.company}, ${job.location} (ID: ${job._id})</li>`).join('');
};

const fetchJobs = async () => {
    const response = await fetch('http://localhost:3000/api/jobs', {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const jobs = await response.json();
        updateJobList(jobs);
    } else {
        alert('Failed to fetch jobs');
    }
};

document.getElementById('searchJobForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const jobId = document.getElementById('jobId').value;
    const response = await fetch(`http://localhost:3000/api/jobs/${jobId}`, {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const job = await response.json();
        document.getElementById('jobDetails').style.display = 'block';
        document.getElementById('jobTitle').textContent = job.title;
        document.getElementById('jobCompany').textContent = job.company;
        document.getElementById('jobLocation').textContent = job.location;
        document.getElementById('updateTitle').value = job.title;
        document.getElementById('updateCompany').value = job.company;
        document.getElementById('updateLocation').value = job.location;
        document.getElementById('updateJobForm').dataset.jobId = job._id;
    } else {
        alert('Job not found');
    }
});

document.getElementById('updateJobForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const jobId = e.target.dataset.jobId;
    const title = document.getElementById('updateTitle').value;
    const company = document.getElementById('updateCompany').value;
    const location = document.getElementById('updateLocation').value;

    await fetch(`http://localhost:3000/api/jobs/${jobId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ title, company, location }),
    });
    fetchJobs();
    document.getElementById('jobDetails').style.display = 'none';
});

document.getElementById('deleteJob').addEventListener('click', async () => {
    const jobId = document.getElementById('updateJobForm').dataset.jobId;
    await fetch(`http://localhost:3000/api/jobs/${jobId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` },
    });
    fetchJobs();
    document.getElementById('jobDetails').style.display = 'none';
});

fetchJobs();