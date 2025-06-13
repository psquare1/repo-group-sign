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
            
            // Create array of arrays, where each inner array contains chunks from a single public key
            const allPublicKeyChunks = Object.values(data.contributors).flatMap(contributor => 
                contributor.publicKeys.map(key => {
                    try {
                        const parsedKey = parseRSAPublicKey(key.key);
                        return splitBigIntToChunks(parsedKey);
                    } catch (error) {
                        console.error(`Error parsing key for ${contributor.username}:`, error);
                        return [];
                    }
                })
            ).filter(chunks => chunks.length > 0); // Remove any empty arrays from failed parses
            const totalKeys = 100;
            if (allPublicKeyChunks.length > totalKeys) {
            throw new Error(`Too many keys: maximum allowed is ${totalKeys}`);
            }
            while (allPublicKeyChunks.length < totalKeys) {
                allPublicKeyChunks.push(allPublicKeyChunks[allPublicKeyChunks.length - 1]);
            }
            
            console.log(parsedHashedMessage, parsedSignature, parsedPublicKey);
            console.log('All public key chunks:', allPublicKeyChunks);
            let hashedKeys;
            try {
                const keyValuePairs = await Promise.all(
                    allPublicKeyChunks.map(async key => [key, await hashArray(key)])
                );
                hashedKeys = new Map(keyValuePairs);
            } catch (error) {
                console.error('Error hashing keys:', error);
                throw new Error('Failed to hash public keys');
            }
            const merkleTreeRoot = merkleTree(hashedKeys);
            const hashedKey = hashArray(parsedSignature.publicKey);
            const [merkleProof, merkleDirectionsTF] = merkleProof(merkleTreeRoot, hashedKey, hashedKeys.indexOf(hashedKey));
            const merkleDirections = merkleDirectionsTF.map((x) => x ? "1" : "0");

            const { proof, publicSignals } =
                await snarkjs.groth16.fullProve({
                    message: parsedHashedMessage,
                    treeProofs: merkleProof,
                    treeDirections: merkleDirections,
                    signature: parsedSignature,
                    correctKey: parsedPublicKey}, "circuit_js/circuit.wasm", "circuit_final.zkey");

            proofComponent.innerHTML = JSON.stringify(proof, null, 1);

            const vkey = await fetch("verification_key.json").then( function(res) {
                return res.json();
            });

            await snarkjs.groth16.verify(vkey, publicSignals, proof);
            // Display the contributors data
            displayContributors(data);
            
            // Show the expandable sections
            expandableSections.style.display = 'block';
            
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
        repoUrlInput.value = 'https://github.com/TritonDataCenter/node-sshpk';
        messageInput.value = 'Hello, World';
        signatureInput.value = `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAN3BiNA0ZFp4XZsN3M+E9C
44a/T6mSkZiMfB+y8n7bBVuhGAa0peaboPt2ZM3tapfZ8xFFwe/nCWtxxvgkowMuLoEI4i
QODNT/uyJhvUSuYU8vH/eVtDdjp4ZBYtwCmHExIzRcpdJgyE7HRxEg155U4+awJ5Zdc8uw
D6Hax9+Wey/rMnBYQHCE2Sw3BZDSy+9cR/2oyu/MKNWU1yGwrZC6sxOuezAsqtfu7GF8n5
jc+gIgheNtEK8vsobJ/WPQO3v0TmC6wYT7Y4hG/lWtGKs4cpz0jL1etyl2yVPghYzLskqA
Fk62v2ZLQoIto4oJxM0eh/TDUKVCP0MvsWYy1OVHaKxhPK2nXKGZFltKihIbMAlWIMwDA3
VQ2P/KHsdevH49Sw1smH3UViHzT5OJhumfOOuG645JNP2FIq41KVJPJLI7hUytKy85VBoz
mY6eeg6fQ26mxS8GXdwouWRNkseu+vPCKlf9A4Sp6MOVSMGR4hrclPNjszH1yFXZTdH9Ay
xE/XcCSWEelhPtWEi/RzPJfHYPvFaNDcGlRDeiBpoWkJzx6F/ljHKK7AgZABrG3Qjp1F4v
CGWQJZYc23l4wBXo98gRe2tUdX1bJI0N739XgGQBU5FxNN1n4flHJC64IyYfJ9KuWGaaXa
MrAtgV9N4w5+BZq7wxOzVHnTVkozjAsNAAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAA
AMcnNhLXNoYTItNTEyAAACAM4QAdCdxWyw2DwWejDJV55RE+2Ddu8dYJwfhYZCJa/NAeZw
ICFxiRY4plomoIp+b0+amKq+wf8yTneXcGfG41Bn00/pttVG9CRmemiXUdTOzm0MnT9Oht
PO8/9ubC5laTFZgj2R+vtIVIV9P08xVEITT3cl2HbK6ImcZsoHIARXilagzhGOXaSLdAQh
86lR4UzR4H1flVPswvyreIa73kqG3AAdVXG550mv7AaqJU/2GO3xCkKiAn9UMaEemfTho+
DRiWuIJjc7JSZtnxV1lZTrVDilXYzchEYsXUBzgHCKoQC+QOkfDmCi+T5/JO64vHBuQrOP
PWdzVEUojpjREeMzICzg89bkCqx3xRBZfYW2JebEotTME2r6D5PyOUJti8vL12kOUOnfA2
vDv5nZjKcJiYDsm25Rw39bcN7ow4UWwifhlZJ65W+CliuYNUfu6t634CNFJHUTnlc/HaQI
2Nc/1BYo4UaUklWMY8oQQd87g6sWkUDhzdcxakFBKL7NyqLWLnSg+Sd4fTW5BsUO2ygdb0
yoKrnMAGHHNQuJfPY416b1Ere+Fg6vJk9SmXLEBBraSYQ2ayr749PXA9bGnekiNgQ6rj5A
PiC1V4NDqgesvN7CMv9D+KI3P3xjX8rB8iw2lfiiZ6vIW/q87L1wPVfJB2e3t+KbDrpBTW
OAqPXv`; // Example base64, replace with a real one if needed
    });
}); 