document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

let interns = JSON.parse(localStorage.getItem('internships')) || [];

const updateInternshipList = () => {
    const list = document.querySelector('#internshipList ul');
    list.innerHTML = interns.map(intern => `<li>${intern.name} - ${intern.project}</li>`).join('');
    localStorage.setItem('internships', JSON.stringify(interns));
};

document.getElementById('internshipForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = document.getElementById('internName').value;
    const project = document.getElementById('project').value;
    interns.push({ name, project });
    updateInternshipList();
    document.getElementById('internName').value = '';
    document.getElementById('project').value = '';
});

updateInternshipList();