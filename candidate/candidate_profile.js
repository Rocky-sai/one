document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

const token = localStorage.getItem('token');
const username = jwt_decode(token).username;

const fetchProfile = async () => {
    const response = await fetch(`http://localhost:3000/api/users/${username}`, {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    const user = await response.json();
    document.getElementById('username').textContent = user.username;
    document.getElementById('skills').textContent = user.skills || 'Not set';
    document.getElementById('experience').textContent = user.experience || 'Not set';
    document.getElementById('education').textContent = user.education || 'Not set';
    document.getElementById('projects').textContent = user.projects || 'Not set';
};

document.getElementById('updateProfileForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const skills = document.getElementById('updateSkills').value;
    const experience = document.getElementById('updateExperience').value;
    const education = document.getElementById('updateEducation').value;
    const projects = document.getElementById('updateProjects').value;

    await fetch(`http://localhost:3000/api/users/${username}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ skills, experience, education, projects }),
    });
    fetchProfile();
});

fetchProfile();