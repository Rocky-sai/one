document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'admin_dashboard.html';
});

const token = localStorage.getItem('token');

const updateClientList = (clients) => {
    const list = document.querySelector('#clientList ul');
    list.innerHTML = clients.map(client => `<li>${client.name} - ${client.contact}</li>`).join('');
};

const fetchClients = async () => {
    const response = await fetch('http://localhost:3000/api/clients', {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const clients = await response.json();
        updateClientList(clients);
    } else {
        alert('Failed to fetch clients');
    }
};

document.getElementById('addClientForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('clientName').value;
    const contact = document.getElementById('clientContact').value;

    await fetch('http://localhost:3000/api/clients', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ name, contact }),
    });
    fetchClients();
});

fetchClients();