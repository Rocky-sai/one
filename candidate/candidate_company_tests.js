document.getElementById('back').addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html';
});

document.getElementById('companyTestForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const companyName = document.getElementById('companyName').value;
    const testScore = document.getElementById('testScore').value;

    let feedback = `You scored ${testScore} in the ${companyName} test. `;
    if (testScore >= 80) feedback += 'Excellent performance!';
    else if (testScore >= 50) feedback += 'Good effort, but you can improve.';
    else feedback += 'You need more practice.';

    document.getElementById('testResult').style.display = 'block';
    document.getElementById('resultText').textContent = feedback;
}); 