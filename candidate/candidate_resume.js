// Configure PDF.js worker
pdfjsLib.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js`;

const backButton = document.getElementById('back');
const analyzerForm = document.getElementById('analyzerForm');
const analysisContainer = document.getElementById('analysisContainer');
const loader = document.getElementById('loader');
const analysisResultDiv = document.getElementById('analysisResult');
const fileInput = document.getElementById('resumeFile');
const fileLabel = document.querySelector('.file-upload-label');
const fileNameSpan = document.getElementById('fileName');

// --- IMPORTANT: API KEY ---
// For production, use a backend endpoint. Do NOT expose this key in the frontend.
const API_KEY = 'AIzaSyCEfBjtgmX3YCBoMUbnIacHXo6BbsIVMX0'; // <-- Replace with your Gemini API Key
const API_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${API_KEY}`;

backButton.addEventListener('click', () => {
    window.location.href = 'candidate_dashboard.html'; // Update as needed
});

// Show file name when selected
fileInput.addEventListener('change', function() {
    fileNameSpan.textContent = fileInput.files[0] ? fileInput.files[0].name : '';
});
fileLabel.addEventListener('keydown', function(e) {
    if (e.key === "Enter" || e.key === " ") {
        fileInput.click();
    }
});
fileLabel.addEventListener('click', function() {
    fileInput.click();
});

analyzerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Get form data
    const jobRole = document.getElementById('jobRole').value.trim();
    const jobDescription = document.getElementById('jobDescription').value.trim();
    const resumeFile = fileInput.files[0];

    if (!resumeFile) {
        alert('Please upload a resume file.');
        return;
    }

    // Show loader and clear previous results
    analysisContainer.style.display = 'block';
    analysisResultDiv.innerHTML = '';
    loader.style.display = 'flex';

    try {
        // 1. Read text from the PDF file
        const resumeText = await readPdfText(resumeFile);

        // 2. Construct the detailed prompt for the AI
        const prompt = createAnalysisPrompt(jobRole, jobDescription, resumeText);

        // 3. Call the Gemini AI model
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: prompt }] }],
            }),
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();

        // The AI response is often a string of JSON inside a markdown block. Extract and parse it.
        let responseText = '';
        try {
            responseText = data.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
            const jsonString = responseText.replace(/```json\n?|```/g, '').trim();
            const analysisData = JSON.parse(jsonString);
            displayAnalysis(analysisData);
        } catch (parseErr) {
            throw new Error("Failed to parse AI response. Response text: " + responseText);
        }

    } catch (error) {
        console.error('Analysis failed:', error);
        analysisResultDiv.innerHTML = `<p style="color: #ff6f61;">An error occurred during analysis.<br>${error.message}</p>`;
    } finally {
        loader.style.display = 'none';
    }
});

/**
 * Reads the text content from an uploaded PDF file.
 * @param {File} file The PDF file object.
 * @returns {Promise<string>} A promise that resolves with the text content of the PDF.
 */
async function readPdfText(file) {
    const fileReader = new FileReader();
    return new Promise((resolve, reject) => {
        fileReader.onload = async function() {
            try {
                const typedarray = new Uint8Array(this.result);
                const pdf = await pdfjsLib.getDocument(typedarray).promise;
                let fullText = '';
                for (let i = 1; i <= pdf.numPages; i++) {
                    const page = await pdf.getPage(i);
                    const textContent = await page.getTextContent();
                    fullText += textContent.items.map(item => item.str).join(' ') + '\n';
                }
                resolve(fullText);
            } catch (error) {
                reject(error);
            }
        };
        fileReader.onerror = function() {
            reject(fileReader.error);
        };
        fileReader.readAsArrayBuffer(file);
    });
}

/**
 * Creates the detailed prompt to be sent to the Gemini API.
 * @param {string} role - The job role.
 * @param {string} description - The job description.
 * @param {string} resume - The text from the candidate's resume.
 * @returns {string} The formatted prompt.
 */
function createAnalysisPrompt(role, description, resume) {
    return `
        Analyze the following resume in the context of the provided job role and description.
        Provide a detailed, critical, and constructive analysis.

        **Job Role:**
        ${role}

        **Job Description:**
        ${description}

        **Candidate's Resume Text:**
        ${resume}

        ---

        Your task is to return a single JSON object. Do not include any text outside of the JSON object.
        The JSON object must have the following structure:

        {
          "matchPercentage": <A number from 0 to 100 representing the resume's match to the job description>,
          "overallSummary": "<A concise, one-paragraph summary of the candidate's suitability.>",
          "keyStrengths": [
            "<Strength 1: A key skill or experience from the resume that strongly matches the job.>",
            "<Strength 2>",
            "<Strength 3>"
          ],
          "areasForImprovement": [
            "<Improvement 1: A specific, actionable suggestion to improve the resume. Example: 'Quantify achievements in the X project with metrics like percentage improvement or revenue generated.'>",
            "<Improvement 2>",
            "<Improvement 3>"
          ],
          "alignmentGaps": [
            "<Gap 1: A skill or requirement from the job description that is missing or not evident in the resume.>",
            "<Gap 2>"
          ],
          "formattingAndClarity": [
            "<Issue 1: Point out any typos, grammatical errors, or confusing statements. If none, state that the resume is well-written.>"
          ]
        }
    `;
}

/**
 * Renders the analysis data into the HTML with new styling classes.
 * @param {object} data The parsed JSON data from the AI.
 */
function displayAnalysis(data) {
    analysisResultDiv.innerHTML = `
        <h2>Analysis Complete</h2>
        <h3 class="summary">Overall Match Score: ${data.matchPercentage ?? 'N/A'}%</h3>
        <p>${data.overallSummary ?? 'No summary provided.'}</p>

        <h3 class="strengths">✅ Key Strengths (Matches Job Description)</h3>
        <ul>${(data.keyStrengths ?? []).map(item => `<li>${item}</li>`).join('')}</ul>

        <h3 class="improvements">📈 Areas for Improvement</h3>
        <ul>${(data.areasForImprovement ?? []).map(item => `<li>${item}</li>`).join('')}</ul>

        <h3 class="gaps">❌ Alignment Gaps (Missing from Resume)</h3>
        <ul>${(data.alignmentGaps ?? []).map(item => `<li>${item}</li>`).join('')}</ul>

        <h3 class="formatting">📝 Formatting & Clarity Check</h3>
        <ul>${(data.formattingAndClarity ?? []).map(item => `<li>${item}</li>`).join('')}</ul>
    `;
}