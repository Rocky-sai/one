document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'recruiter_dashboard.html';
});

const token = localStorage.getItem('token');

const updateJobList = (jobs) => {
    const list = document.querySelector('#jobList ul');
    list.innerHTML = jobs.map(job => `<li>${job.title} - ${job.company}, ${job.location}</li>`).join('');
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

document.getElementById('postJobForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = document.getElementById('jobTitle').value;
    const company = document.getElementById('jobCompany').value;
    const location = document.getElementById('jobLocation').value;

    await fetch('http://localhost:3000/api/jobs', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ title, company, location }),
    });
    fetchJobs();
});

fetchJobs();