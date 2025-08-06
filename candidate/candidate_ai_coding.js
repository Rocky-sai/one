document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

document.getElementById('codingQuestionForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const question = document.getElementById('codingQuestion').value.toLowerCase();
    let answer = 'Sorry, I don’t have an answer for that yet.';

    if (question.includes('javascript')) {
        answer = 'To learn JavaScript, start with variables, functions, and DOM manipulation. Try this example: `const greet = () => console.log("Hello!");`';
    } else if (question.includes('react')) {
        answer = 'React is a JavaScript library for building UIs. Start with components and hooks. Example: `function App() { return <h1>Hello React</h1>; }`';
    }

    document.getElementById('codingAnswer').style.display = 'block';
    document.getElementById('answerText').textContent = answer;
});