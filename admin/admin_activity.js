document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'admin_dashboard.html';
});

const token = localStorage.getItem('token');

const updateActivityList = (activities) => {
    const list = document.querySelector('#activityList ul');
    list.innerHTML = activities.map(item => `<li>${item.description} - ${new Date(item.timestamp).toLocaleString()}</li>`).join('');
};

const fetchActivities = async (filter = '') => {
    const url = filter ? `http://localhost:3000/api/activities/filter?filter=${filter}` : 'http://localhost:3000/api/activities';
    const response = await fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const activities = await response.json();
        updateActivityList(activities);
    } else {
        alert('Failed to fetch activities');
    }
};

document.getElementById('filterForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const filter = document.getElementById('filterActivity').value;
    fetchActivities(filter);
});

fetchActivities();