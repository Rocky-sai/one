// ---------------- Candidate Dashboard Navigation ----------------
document.getElementById('back')?.addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

// ---------------- Learning Goals Logic ----------------
let goals = JSON.parse(localStorage.getItem('learningGoals')) || [];
const updateGoalsList = () => {
    const listContainer = document.querySelector('#goalsList ul');
    if (!listContainer) return;
    listContainer.innerHTML = goals.map(goal => `<li>${goal}</li>`).join('');
    localStorage.setItem('learningGoals', JSON.stringify(goals));
};
const learningGoalForm = document.getElementById('learningGoalForm');
if (learningGoalForm) {
    learningGoalForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const goalInput = document.getElementById('learningGoal');
        const goal = goalInput?.value.trim();
        if (goal) {
            goals.push(goal);
            updateGoalsList();
            goalInput.value = '';
        }
    });
    updateGoalsList();
}

// ---------------- Chat Sessions Logic ----------------
let chatSessions = JSON.parse(localStorage.getItem('aiChatSessions')) || [];
let activeSessionIdx = chatSessions.length ? 0 : null; // Default to first if any chats exist

const chatSessionsDiv = document.getElementById('chatSessions');
const activeChatDiv = document.getElementById('activeChat');

function renderChatSessions() {
    if (!chatSessionsDiv) return;
    if (chatSessions.length === 0) {
        chatSessionsDiv.innerHTML = "<em>No chats yet. Start a new topic!</em>";
        activeChatDiv.innerHTML = '';
        return;
    }
    // List chat titles as clickable items
    chatSessionsDiv.innerHTML = chatSessions.map((session, idx) =>
        `<span class="chat-session-title${activeSessionIdx === idx ? ' active-session-title' : ''}" data-session-idx="${idx}">${session.title}</span>`
    ).join(' ');
    // Show active chat conversation
    renderActiveChat();
    // Add click handlers to switch active chat
    document.querySelectorAll('.chat-session-title').forEach(el => {
        el.onclick = function() {
            activeSessionIdx = parseInt(this.getAttribute('data-session-idx'));
            renderChatSessions();
        };
    });
}

function renderActiveChat() {
    if (activeSessionIdx === null || !chatSessions[activeSessionIdx]) {
        activeChatDiv.innerHTML = '';
        return;
    }
    const session = chatSessions[activeSessionIdx];
    activeChatDiv.innerHTML = session.messages.map(msg =>
        `<div class="chat-block">
            <div class="user-question"><b>You:</b> ${msg.user}</div>
            <div class="ai-answer"><b>Acharya:</b> ${msg.ai}</div>
        </div>`
    ).join('');
}

function saveChatSessions() {
    localStorage.setItem('aiChatSessions', JSON.stringify(chatSessions));
}

// ---------------- AI Teacher Logic ----------------
// For production, use a backend endpoint. Do NOT expose this key in the frontend.
const API_KEY = 'AIzaSyCEfBjtgmX3YCBoMUbnIacHXo6BbsIVMX0'; // <-- Replace with your Gemini API Key
const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${API_KEY}`;

const aiForm = document.getElementById('aiQueryForm');
const aiResponseContainer = document.getElementById('aiResponseContainer');
const loader = document.getElementById('loader');

aiForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const chatTitleInput = document.getElementById('chatTitleInput');
    const queryInput = document.getElementById('aiQuery');
    const title = chatTitleInput.value.trim();
    const query = queryInput.value.trim();
    if (!title || !query) return;

    aiResponseContainer.style.display = 'block';
    loader.style.display = 'block';

    // Find or create chat session by title
    let sessionIdx = chatSessions.findIndex(s => s.title === title);
    if (sessionIdx === -1) {
        // New session
        chatSessions.push({ title, messages: [] });
        sessionIdx = chatSessions.length - 1;
    }
    activeSessionIdx = sessionIdx;

    // Always get latest goals
    goals = JSON.parse(localStorage.getItem('learningGoals')) || [];

    try {
        const prompt = `
        You are Acharya, an expert AI teacher.
        The user's current learning goals are: ${goals.length ? goals.map(g => `"${g}"`).join(', ') : 'None'}
        The current chat topic is: "${title}".
        If the user's question is related to any of their goals or the chat topic, provide extra detailed and practical help.
        Reply in clear, visually structured Markdown:
        - Use headings for main sections.
        - Numbered lists for steps or phases.
        - Bullet points for key concepts.
        - Real-world analogies and practical examples.
        - At the end, always include a "Further Reading" section with at least 2-3 external resources (links to docs, courses, tutorials).
        Here is the student's question: "${query}"
        Also, suggest 2-3 follow-up questions based on their goals or the chat topic.
        `;

        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
            }),
        });

        if (!response.ok) {
            // Connection failed: start a new chat session and preserve previous history
            chatSessions.push({
                title: title + " (new session due to connection failure)",
                messages: [{
                    user: query,
                    ai: `<span style="color:#ff6f61">Connection failed. Please retry your question.</span>`
                }]
            });
            activeSessionIdx = chatSessions.length - 1;
            saveChatSessions();
            renderChatSessions();
            loader.style.display = 'none';
            return;
        }

        const data = await response.json();
        let answer = data.candidates?.[0]?.content?.parts?.[0]?.text ?? 'No answer received.';
        answer = window.marked.parse(answer);

        // Save to session
        chatSessions[sessionIdx].messages.push({ user: query, ai: answer });
        saveChatSessions();
        renderChatSessions();

    } catch (err) {
        chatSessions[sessionIdx].messages.push({
            user: query,
            ai: `<span style="color:#ff6f61">Error: ${err.message}</span>`
        });
        saveChatSessions();
        renderChatSessions();
    } finally {
        loader.style.display = 'none';
    }
});

// Initialize sessions view on page load
renderChatSessions();