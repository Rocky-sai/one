document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

const token = localStorage.getItem('token');
const username = jwt_decode(token).username;

const updateChatMessages = (messages) => {
    const list = document.querySelector('#chatMessages ul');
    list.innerHTML = messages.map(msg => `<li>${msg.sender}: ${msg.message} (${new Date(msg.timestamp).toLocaleString()})</li>`).join('');
};

const fetchMessages = async () => {
    const response = await fetch('http://localhost:3000/api/chat-messages', {
        headers: { 'Authorization': `Bearer ${token}` },
    });
    if (response.ok) {
        const messages = await response.json();
        updateChatMessages(messages);
    } else {
        alert('Failed to fetch messages');
    }
};

document.getElementById('chatForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = document.getElementById('chatMessage').value;

    await fetch('http://localhost:3000/api/chat-messages', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({ sender: username, message }),
    });
    document.getElementById('chatMessage').value = '';
    fetchMessages();
});

fetchMessages();