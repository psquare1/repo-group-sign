const axios = require('axios');
const { Octokit } = require('@octokit/rest');
const fs = require('fs').promises;

// Initialize Octokit with GitHub token
const octokit = new Octokit({
    auth: process.env.GITHUB_TOKEN
});

async function getRepositoryContributors(owner, repo) {
    try {
        const contributors = await octokit.repos.listContributors({
            owner,
            repo,
            per_page: 100
        });
        return contributors.data;
    } catch (error) {
        console.error('Error fetching contributors:', error.message);
        return [];
    }
}

async function getUserPublicKeys(username) {
    try {
        const response = await octokit.users.listPublicKeysForUser({
            username
        });
        return response.data;
    } catch (error) {
        console.error(`Error fetching public keys for ${username}:`, error.message);
        return [];
    }
}

// Function to determine key type
function getKeyType(keyString) {
    if (keyString.startsWith('ssh-rsa')) return 'RSA';
    if (keyString.startsWith('ssh-ed25519')) return 'ED25519';
    if (keyString.startsWith('ecdsa-sha2-nistp256')) return 'ECDSA';
    if (keyString.startsWith('ssh-dss')) return 'DSA';
    return 'UNKNOWN';
}

// Function to filter out non-RSA keys
function filterRSAKeys(publicKeys) {
    return publicKeys.filter(key => {
        const keyType = getKeyType(key.key);
        return keyType === 'RSA';
    });
}

async function scrapeRepositoryPublicKeys(repoUrl) {
    // Extract owner and repo from URL
    const [owner, repo] = repoUrl.split('/').slice(-2);
    
    console.log(`Scraping public keys for repository: ${owner}/${repo}`);
    
    // Get all contributors
    const contributors = await getRepositoryContributors(owner, repo);
    console.log(`Found ${contributors.length} contributors`);
    
    // Get public keys for each contributor
    const results = {
        repository: {
            owner,
            repo,
            url: repoUrl
        },
        contributors: {}
    };
    
    for (const contributor of contributors) {
        const username = contributor.login;
        const publicKeys = await getUserPublicKeys(username);
        if (publicKeys.length > 0) {
            // Filter for RSA keys only
            // TODO: Expand functionality to include other key types
            const rsaKeys = filterRSAKeys(publicKeys);
            if (rsaKeys.length > 0) {
                results.contributors[username] = {
                    contributions: contributor.contributions,
                    publicKeys: rsaKeys.map(key => ({
                        id: key.id,
                        key: key.key,
                        title: key.title,
                        type: getKeyType(key.key)  // Add key type to output
                    }))
                };
            }
        }
    }
    
    return results;
}

// Example usage
async function main() {
    if (process.argv.length < 3) {
        console.log('Please provide a GitHub repository URL');
        console.log('Usage: node github_scraper.js <repository-url>');
        process.exit(1);
    }

    const repoUrl = process.argv[2];
    const results = await scrapeRepositoryPublicKeys(repoUrl);
    
    // Create filename from repository name
    const filename = `repo_public_keys/${results.repository.owner}_${results.repository.repo}_data.json`;
    
    // Save results to file
    try {
        await fs.writeFile(filename, JSON.stringify(results, null, 2));
        console.log(`Data successfully saved to ${filename}`);
    } catch (error) {
        console.error('Error saving data to file:', error.message);
    }
}

main().catch(console.error);
