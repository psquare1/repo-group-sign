require('dotenv').config();
const express = require('express');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const app = express();
const port = 3001;


// Middleware to parse JSON bodies
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory

// Endpoint to fetch repository data
app.post('/fetch-repo-data', async (req, res) => {
    const { repoUrl } = req.body;
    
    if (!repoUrl) {
        return res.status(400).json({ error: 'Repository URL is required' });
    }

    console.log('Received request for repo:', repoUrl);

    try {
        // Run the GitHub scraper script
        console.log('Spawning github_scraper.js...');
        const scraper = spawn('node', ['github_scraper.js', repoUrl]);
        
        let errorOutput = '';
        
        scraper.stderr.on('data', (data) => {
            errorOutput += data.toString();
            console.error('Scraper error:', data.toString());
        });

        scraper.on('close', async (code) => {
            console.log('Scraper process exited with code:', code);
            if (code !== 0) {
                return res.status(500).json({ error: `Scraper failed: ${errorOutput}` });
            }

            try {
                // Extract owner and repo from URL
                const [owner, repo] = repoUrl.split('/').slice(-2);
                const filename = `repo_public_keys/${owner}_${repo}_data.json`;
                console.log('Looking for file:', filename);
                
                // Read the generated file
                const data = await fs.readFile(filename, 'utf8');
                console.log('Successfully read data file');
                res.json(JSON.parse(data));
            } catch (error) {
                console.error('Error reading data file:', error);
                res.status(500).json({ error: 'Failed to read generated data file' });
            }
        });
    } catch (error) {
        console.error('Error running scraper:', error);
        res.status(500).json({ error: 'Failed to run scraper' });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
}); 