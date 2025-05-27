
document.getElementById('scanForm').addEventListener('submit', async (e) => {
  e.preventDefault();

  const url = document.getElementById('urlInput').value;
  const scanType = document.getElementById('scanType').value;
  const resultDiv = document.getElementById('result');

  resultDiv.innerHTML = 'Scanning...';

  try {
    const response = await fetch('http://localhost:3001/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, scanType }),
    });

    const data = await response.json();

    resultDiv.innerHTML = `
      <h3>Scan Result</h3>
      <p>Status: <span style="color: ${data.status === 'Safe' ? 'green' : 'red'}">${data.status}</span></p>
      <p>Scan Type: ${data.scanType}</p>
      <ul>
        ${data.issues.map(issue => {
          const color = issue.risk === 'high' ? 'red'
                      : issue.risk === 'medium' ? 'orange'
                      : issue.risk === 'low' ? 'green'
                      : 'gray';
          return `<li style="color:${color}">${issue.message} (${issue.risk.toUpperCase()} risk)</li>`;
        }).join('')}
      </ul>
    `;
  } catch (error) {
    resultDiv.innerHTML = `<p style="color:red;">Error: ${error.message}</p>`;
  }
});

