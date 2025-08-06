document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

let progressItems = JSON.parse(localStorage.getItem('progressItems')) || [];

const updateProgressList = () => {
    const list = document.querySelector('#progressList ul');
    list.innerHTML = progressItems.map(item => `<li>${item}</li>`).join('');
    localStorage.setItem('progressItems', JSON.stringify(progressItems));
};

document.getElementById('progressForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const item = document.getElementById('progressItem').value;
    progressItems.push(item);
    updateProgressList();
    document.getElementById('progressItem').value = '';
});

updateProgressList();