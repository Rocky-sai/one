document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

const resources = [
    { title: 'JavaScript Basics', category: 'JavaScript', link: '#' },
    { title: 'React Tutorial', category: 'React', link: '#' },
    { title: 'Python for Beginners', category: 'Python', link: '#' },
    { title: 'SQL Guide', category: 'SQL', link: '#' },
];

const updateResourcesList = (filteredResources) => {
    const list = document.querySelector('#resourcesList ul');
    list.innerHTML = filteredResources.map(resource => `<li>${resource.title} (${resource.category}) - <a href="${resource.link}">Link</a></li>`).join('');
};

document.getElementById('searchResourcesForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const query = document.getElementById('searchQuery').value.toLowerCase();
    const filteredResources = resources.filter(resource => 
        resource.title.toLowerCase().includes(query) || resource.category.toLowerCase().includes(query)
    );
    updateResourcesList(filteredResources);
});

updateResourcesList(resources);