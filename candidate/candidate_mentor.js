document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

document.getElementById('careerGoalForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const goal = document.getElementById('careerGoal').value.toLowerCase();
    let advice = 'Great goal! Here’s some advice: ';

    if (goal.includes('software engineer')) {
        advice += 'Focus on mastering data structures and algorithms. Practice coding on platforms like LeetCode and build projects to showcase your skills.';
    } else if (goal.includes('data scientist')) {
        advice += 'Learn Python, R, and SQL. Work on machine learning projects and get familiar with tools like TensorFlow and Pandas.';
    } else {
        advice += 'Set clear milestones, upskill regularly, and network with professionals in your field.';
    }

    document.getElementById('careerAdvice').style.display = 'block';
    document.getElementById('adviceText').textContent = advice;
});