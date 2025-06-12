document.addEventListener('DOMContentLoaded', function() {
    const generateProofButton = document.getElementById('generateProof');
    const expandableSections = document.getElementById('expandableSections');
    const contributorsContent = document.getElementById('contributorsContent');

    // Sample data - replace this with actual data from your backend
    const sampleData = {
        repository: {
            owner: "example",
            repo: "sample-repo",
            url: "https://github.com/example/sample-repo"
        },
        contributors: {
            "user1": {
                contributions: 42,
                publicKeys: [
                    {
                        id: "key1",
                        key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
                        title: "Work Laptop"
                    }
                ]
            },
            "user2": {
                contributions: 15,
                publicKeys: [
                    {
                        id: "key2",
                        key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...",
                        title: "Home Computer"
                    }
                ]
            }
        }
    };

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

    generateProofButton.addEventListener('click', function() {
        // Show the expandable sections
        expandableSections.style.display = 'block';
        
        // Display the contributors data
        displayContributors(sampleData);
        
        // Scroll to the expandable sections
        expandableSections.scrollIntoView({ behavior: 'smooth' });
    });
}); 