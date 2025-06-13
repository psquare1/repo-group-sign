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
            messageDisplaySection.style.display = 'none';
            return;
        }
        let messageChunks;
        try {
            // Display raw message
            rawMessage.textContent = message;
            
            // Convert message to BigInt and display
            const messageAsBigInt = await messageToBigInt(message);
            messageBigInt.textContent = formatHexString(bigIntToHex(messageAsBigInt));
            messageChunks 
            messageDisplaySection.style.display = 'block';
        } catch (error) {
            console.error('Error processing message:', error);
            messageChunks = [];
            rawMessage.textContent = 'Error: ' + error.message;
            messageBigInt.textContent = '';
            messageDisplaySection.style.display = 'block';
        }
        return messageChunks;
    }

    // Function to process and display signature
    function processSignature(signature) {
        if (!signature) {
            parsedSignatureSection.style.display = 'none';
            return;
        }
        let parsedSignatureChunks;
        try {

            const parsed = parseSSHSignature(signature);
            console.log('Parsed signature:', parsed);
            
            // Display the parsed signature details in hex
            parsedSignatureChunks = {
                signature: splitBigIntToChunks(parsed.signature),
                publicKey: splitBigIntToChunks(parsed.publicKey),
            };
            parsedPublicKey.textContent = formatHexString(bigIntToHex(parsed.publicKey));
            parsedSignature.textContent = formatHexString(bigIntToHex(parsed.signature));
            parsedSignatureSection.style.display = 'block';
        } catch (error) {
            console.error('Error parsing signature:', error);
            // Show error in the UI
            parsedSignatureChunks = [];
            parsedPublicKey.textContent = 'Error: ' + error.message;
            parsedSignature.textContent = '';
            parsedSignatureSection.style.display = 'block';
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
                const totalKeys = 100;
                console.log('All public key chunks:', allPublicKeyChunks);
                if (allPublicKeyChunks.length > totalKeys) {
                throw new Error(`Too many keys: maximum allowed is ${totalKeys}`);
                }
                while (allPublicKeyChunks.length < totalKeys) {
                    allPublicKeyChunks.push(allPublicKeyChunks[allPublicKeyChunks.length - 1]);
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
        
            const { proof, publicSignals } =
                await snarkjs.groth16.fullProve({
                    message: parsedHashedMessage,
                    treeProofs: calculatedMerkleProof,
                    treeDirections: merkleDirections,
                    signature: parsedSignature,
                    correctKey: parsedPublicKey}, "circuit_js/circuit.wasm", "circuit_final.zkey");

            proofComponent.innerHTML = JSON.stringify(proof, null, 1);

            const vkey = await fetch("verification_key.json").then( function(res) {
                return res.json();
            });

            await snarkjs.groth16.verify(vkey, publicSignals, proof);
            
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
        repoUrlInput.value = 'https://github.com/The-Turtle/0xparc-week-1';
        messageInput.value = '0xPARC';
        signatureInput.value = `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAJJi1WywAy7izdX7fADbjLxQJeoYIMm02pMOi6jrwpRN0zbHKrDsn9wK+OV7cyckAqf3vmdW9v6wZZ7VdEtvrAImonh7Nv5X1NzWOs7A0tQYSJFsjUxHzRIe+Wxj3A0231TsTOoPwYtfCmCuNtofJKxpHb1mPq51p9N0ec1WxvYUc1LOTk1q51yBSFxTFJOmQWEYURN3Gd+udnh+quwIeKdmNTYVM+qoIjb//u8ErODwA/DZ7lvFfaos/v1hKlRaCV1/zXSt/9xxfLDtFPWJgj7EWy7WOSh9cjx2L6qiHiwpn/uw+EN1bPYSnbbL0vqtSEdvHjZHYtFX4ooLGqP0Zpzy6T9gDd+vWq2xWIBewR3w6q0KDalTQwDyb0k0PAuqYjMko6qMUieofsw8+cfEENfKbhHYOHQSho9FTYVn5m3MWBgFsv/f1vmOPURa5oYiRKFthOdjXAqnHVkTH2+m7IBw/d0TfsUM5rw6oe/oSXbo20T1qRsv8AZWJh941PI9OAc4vydMXpz9pDHPP2nXC1E/JgpG7H28npjNAwREj/LlTU1OjZcC5TUkDt/39hogc91bV++0TD/3l2vt97EJ4lbYBQvjVxnTVs4hqE9O4S219m5QzQtx459Ga9bRcAC7Rzg8/qt09geGWyf0y4xNsTnHLA+kf8sxOtaK+nGzz7MRAAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAAAMcnNhLXNoYTItNTEyAAACAGhJDy15QzBMNbEp1KrsuyGYFaI0y3vKrIRfbxv03N+qV2AJwZXsTYc+LGcD53TH0xmE/ixo4zJFYvAqqL6o7+5D97pCszWJcKmPG2QvpO4fu0mJLVwgw2bEO/iVL3JsMMqKCegDzC3byqDv44NT3OltWtQRdaxYpGGsNQJ4j1D95iBJ85ua4oy1MdGgImD+fI+RPxZ+GZWHhfiHUDUxhmrRX7g+JXT2igE5ny6llLe/HEpkaGwS1eiov36ZQNlrwsWIkdi1MoWx9xiXrHeLoSqh8m8I7Qsf6xYZqcZ97eotgrrcvMP00sWs17+JzLR6spEx3czMpP/ZR8CBOSy2pflZd+0gRgt8lNNmE71YptUdfw5RK/+NYULDc90KdAyw3D4RW0eWmwjN1GZphTZUWTyOsd2shJTTeZg+PUc2OCvEP4Okcfg63yzgAMCUk0OBCZVc4JtvfNRFKCkXKFYYK3EP7k8fjfC70iTVxu1d6oWfg670zgAssTWXvc2gstRyFfNdSv+AAYbNCtf3AF/OwIydqBpv2PxJfTse22OJwNuppQ7R9XOIyFprp5eFfRSKXm6fOwPLsE4uIqvxs7EQQ10SNzWae2B6bh1rPZKnVxFP34UKrHdc0HYV/Hy3AcSGTJNTSlhuV/ajAD75s+HmOlsJE0L2wrSvl/dMPPtcpcoI`; // Example base64, replace with a real one if needed
    });
}); 