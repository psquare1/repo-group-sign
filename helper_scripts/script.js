import { groth16 } from "snarkjs";
document.addEventListener('DOMContentLoaded', function() {
    const generateProofButton = document.getElementById('generateProof');
    const expandableSections = document.getElementById('expandableSections');
    const contributorsContent = document.getElementById('contributorsContent');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const repoUrlInput = document.getElementById('repoUrl');
    const messageInput = document.getElementById('message');
    const signatureInput = document.getElementById('signature');
    const parsedSignatureSection = document.getElementById('parsedSignatureSection');
    const parsedPublicKey = document.getElementById('parsedPublicKey');
    const parsedSignature = document.getElementById('parsedSignature');
    const messageDisplaySection = document.getElementById('messageDisplaySection');
    const rawMessage = document.getElementById('rawMessage');
    const messageBigInt = document.getElementById('messageBigInt');
    const fillDefaultsButton = document.getElementById('fillDefaults');

    // Helper function to convert BigInt to hex string
    function bigIntToHex(bigInt) {
        return '0x' + bigInt.toString(16);
    }

    // Helper function to format hex string with line breaks
    function formatHexString(hex) {
        // Add a line break every 64 characters
        return hex.match(/.{1,64}/g).join('\n');
    }

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

    // Function to process and display message
    async function processMessage(message) {
        if (!message) {
            return;
        }
        let messageChunks;
        try {
            // Convert message to BigInt and log to console
            const messageAsBigInt = await messageToBigInt(message);
            console.log('Message:', message);
            console.log('Message as BigInt:', formatHexString(bigIntToHex(messageAsBigInt)));
            messageChunks = splitBigIntToChunks(messageAsBigInt);
        } catch (error) {
            console.error('Error processing message:', error);
            messageChunks = [];
        }
        return messageChunks;
    }

    // Function to process and display signature
    function processSignature(signature) {
        if (!signature) {
            return;
        }
        let parsedSignatureChunks;
        try {
            const parsed = parseSSHSignature(signature);
            console.log('Parsed signature:', parsed);
            
            // Log the parsed signature details to console
            parsedSignatureChunks = {
                signature: splitBigIntToChunks(parsed.signature),
                publicKey: splitBigIntToChunks(parsed.publicKey),
            };
            console.log('Public Key:', formatHexString(bigIntToHex(parsed.publicKey)));
            console.log('Signature:', formatHexString(bigIntToHex(parsed.signature)));
        } catch (error) {
            console.error('Error parsing signature:', error);
            parsedSignatureChunks = [];
        }   
        return parsedSignatureChunks;
    }

    generateProofButton.addEventListener('click', async function() {
        const repoUrl = repoUrlInput.value.trim();
        const message = messageInput.value.trim();
        const signature = signatureInput.value.trim();
        
        if (!repoUrl) {
            alert('Please enter a repository URL');
            return;
        }

        // Process message and signature
        const parsedHashedMessage = await processMessage(message);
        const processedSignature = await processSignature(signature);
        const parsedSignature = processedSignature.signature;
        const parsedPublicKey = processedSignature.publicKey;
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
            
            // Display contributors immediately after fetching data
            displayContributors(data);
            expandableSections.style.display = 'block';
            
            let allPublicKeyChunks;
            try {
            // Create array of arrays, where each inner array contains chunks from a single public key
                allPublicKeyChunks = Object.values(data.contributors).flatMap(contributor => 
                    contributor.publicKeys.map(key => {
                        try {
                            const parsedKey = parseRSAPublicKey(key.key);
                            console.log('parsed key from contributors:', formatHexString(bigIntToHex(parsedKey)));
                            return splitBigIntToChunks(parsedKey);
                        } catch (error) {
                            console.error(`Error parsing key for ${contributor.username}:`, error);
                            return [];
                        }
                    })
                ).filter(chunks => chunks.length > 0); // Remove any empty arrays from failed parses
                const totalKeys = 7;
                console.log('All public key chunks:', allPublicKeyChunks);
                if (allPublicKeyChunks.length > totalKeys) {
                throw new Error(`Too many keys: maximum allowed is ${totalKeys}`);
                }
            } catch (error) {
                console.error('Error creating public key chunks:', error);
                throw new Error('Failed to create public key chunks');
            }
            console.log(parsedHashedMessage, parsedSignature, parsedPublicKey);
            console.log('All public key chunks:', allPublicKeyChunks);
            const hashedKeys = allPublicKeyChunks.map(key => hashArray(key));
            // try {
            //     const keyValuePairs = await Promise.all(
            //         allPublicKeyChunks.map(async key => [key, await hashArray(key)])
            //     );
            //     hashedKeys = new Map(keyValuePairs);
            // } catch (error) {
            //     console.error('Error hashing keys:', error);
            //     throw new Error('Failed to hash public keys');
            // }
            const merkleTreeRoot = await merkleTree(hashedKeys);
            let hashedKey;
            try {
                console.log('parsedPublicKey:', parsedPublicKey);
                hashedKey = hashArray(parsedPublicKey);
            } catch (error) {
                console.error('Error hashing key:', error);
                throw new Error('Failed to hash key');
            }
            const [calculatedMerkleProof, merkleDirectionsTF] = await merkleProof(merkleTreeRoot, hashedKey, hashedKeys.indexOf(hashedKey));
            const merkleDirections = merkleDirectionsTF.map((x) => x ? "1" : "0");
            console.log(verifyMerkleProof(merkleTreeRoot, hashedKey, calculatedMerkleProof, merkleDirectionsTF));
            const { proof, publicSignals } =
                await groth16.fullProve({
                    message: parsedHashedMessage,
                    treeProofs: calculatedMerkleProof,
                    treeDirections: merkleDirections,
                    signature: parsedSignature,
                    correctKey: parsedPublicKey,
                    merkleRoot: merkleTreeRoot.data,
                }, "circuit_files/circuit.wasm", "circuit_files/circuit_final.zkey");

            proofComponent.innerHTML = JSON.stringify(proof, null, 1);

            const vkey = await fetch("circuit_files/verification_key.json").then( function(res) {
                return res.json();
            });

            await groth16.verify(vkey, publicSignals, proof);
            
            // Scroll to the expandable sections
            expandableSections.scrollIntoView({ behavior: 'smooth' });
        } catch (error) {
            console.error('Error:', error);
            alert('Error: ' + error.message);
        } finally {
            // Hide loading spinner
            loadingSpinner.style.display = 'none';
        }
    });

    fillDefaultsButton.addEventListener('click', function() {
        repoUrlInput.value = 'https://github.com/psquare1/repo-group-sign';
        messageInput.value = '0xPARC';
        signatureInput.value = `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAMeroewqNQMc3NrpCXX/Wz
BvDUB/b27cv3+lIu3EH+CUyNfcP6cV/rpH9HYAhVEpnn50vIrDFZs1Rf0k1te/inCNQKMj
qSHSSFNE6XUy29BXSNFda/YoUyDhtfJv/69m9XEZBnCCO3Lx3pVnG1j1LaKn00rhftceZc
Mx5dvB4euWUkzdWQLpk11qwtdGv+I1/cmgy5ETFgLkJj2RDZEtVtq/cBEX+R2GV9CwHwZ3
lJ/E2QPYY0N2knwQCmA0AGm63qc4LziXO1erIpaMVUAsPx2mWrRHlQbjBDFuJYgoORtF3Y
aZbJdUrW39Tf0BWFZsutmRn9VX+1mZctbEMmuIAU1zXrymBXeCdjyLJibed+LnzGPVe6hl
tAutWMVij9dBaMGQi+/p5VkBhOnmoPAsUAfhgHuk9cTiMLJtnR+JuE5dKlKi9BscaOQQ79
Ih69gEmysqdmp+nOZbs3kNxz+7lidJt0EYmhkCTBwwxmmRrY1xagHORQWz/5MU/OFDh0d+
mYcqsONYk9eAxCZhPEOg8Nn/LsvgcUO05NoTS8RHwQ4OImk36lCdN5ql/dy1GU1uu3zh9l
5fQsw/Lp8q8sXYU2eVWESrFeduDWPG6Y34dp5vrLoWW/oRHLM+LXPJzYdjezD010DEkbzk
78tqIlBmJo01TEjQQW/znoVUoLQ2VPd1AAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAA
AMcnNhLXNoYTItNTEyAAACAIR3B+M+wyOfyw6wNVLiSCp5AjEcs6zczGpSSl8ExxLQ7nMd
Zw9oL20Z39mq8Hfv8bbXOntUqqRk2hFH8D5HiDzqEELNVps4BqRgrOC7u0LMlTs6CPWBFE
cI4FP4uzS36+uOppVln7XMYNZX3iVTVSjKcB5EBxpCULoqfNN8ee/t0/bq1ZCRazYvzlTO
oXQf6iEgeTQTaR9xLDh3YueVUZRWfl4p2PhgKdawH56BXk9T6trIMzMIhuAH5qxJ4ZyrEd
Jh4qgg5KKDzkN/k5w3Is1bTgTNzGOBqN5EFXIizWt5xInbCo9diGT6zjyFjxLSWm+79KrW
+u0aq7zwdwBKzBBM5oiymAFfCMllxY2NaqHdgQ1xMqk9FOyBCFVnqBDzGhApTMHlaWoEHk
KlB49RmURUItcn09fzCxmXiP267dgf9lvTkvpDqQkQpRe02vhAOWRYTIer+AtWLeIFYvE5
N6GDR9guXww9+Ka9Hn+xm2jrkqFXuD2y33h0P2NlD3t3EMyatvfPeGwWwGh6upg++BWXU+
1QvFjWQup0fXH60utOcdGauMn42jf7Ifwg/MpICBRaYkmcrJfzYRD5DTiSy9svk0Bt4vy1
iUlBrRY8FrBLEy3CurvpAx+o1I/i0smCHTAebx7U7NmmedC12O3fqS7jpD8E3h5jIGfuEb
Hue5Ug`; // Example base64, replace with a real one if needed
    });
}); 