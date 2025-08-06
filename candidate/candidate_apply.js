document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
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

document.getElementById('applyJobForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const job = document.getElementById('jobApply').value;
    const coverLetter = document.getElementById('coverLetter').value;

    const response = await fetch('http://localhost:3000/api/applications', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ job, resume: coverLetter, status: 'Pending' }),
    });
    if (response.ok) {
        alert('Application submitted successfully!');
    } else {
        alert('Failed to submit application');
    }
});

fetchJobs();