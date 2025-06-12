document.addEventListener('DOMContentLoaded', function() {
    const generateProofButton = document.getElementById('generateProof');
    const expandableSections = document.getElementById('expandableSections');
    const contributorsContent = document.getElementById('contributorsContent');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const repoUrlInput = document.getElementById('repoUrl');

    function displayContributors(data) {
        let html = '';
        
        for (const [username, info] of Object.entries(data.contributors)) {
            html += `
                <div class="contributor-item">
                    <h5>${username}</h5>
                    <p class="text-muted">Contributions: ${info.contributions}</p>
                    <div class="public-keys">
                        ${info.publicKeys.map(key => `
                            <div class="mb-2">
                                <small class="text-muted">${key.title}</small>
                                <div class="public-key">${key.key}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }
        
        contributorsContent.innerHTML = html;
    }

    generateProofButton.addEventListener('click', async function() {
        const repoUrl = repoUrlInput.value.trim();
        
        if (!repoUrl) {
            alert('Please enter a repository URL');
            return;
        }

        // Show loading spinner
        loadingSpinner.style.display = 'block';
        expandableSections.style.display = 'none';

        try {
            // Call the backend API
            const response = await fetch('/fetch-repo-data', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ repoUrl })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to fetch repository data');
            }

            const data = await response.json();
            
            // Display the contributors data
            displayContributors(data);
            
            // Show the expandable sections
            expandableSections.style.display = 'block';
            
            // Scroll to the expandable sections
            expandableSections.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            alert(error.message);
        } finally {
            // Hide loading spinner
            loadingSpinner.style.display = 'none';
        }
    });
}); 