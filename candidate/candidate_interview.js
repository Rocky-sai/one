document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

document.getElementById('interviewForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const answer1 = document.getElementById('question1').value;
    const answer2 = document.getElementById('question2').value;

    let feedback = 'Good effort! ';
    if (answer1.length < 50) feedback += 'Your "Tell me about yourself" answer is too short. Add more details about your background. ';
    if (answer2.length < 50) feedback += 'Your strengths answer is too short. Highlight specific skills and examples.';

    document.getElementById('interviewFeedback').style.display = 'block';
    document.getElementById('feedbackText').textContent = feedback;
});