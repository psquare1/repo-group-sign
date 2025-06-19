import { groth16 } from "snarkjs";
import { Buffer } from "buffer"


const ED25519_DEFAULT_SIG = `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgUCQmQQJ/YZx5sYzOo1B2jIatrS
VnmFUyrAU68EkvGeoAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEBYeLSoInmSXk0WqpMv8AtWz/m0641Yuyo1ssueTiOBEc3mGLL07W7mrw5KyE9Loh
1N5+kzrcxJVCleR73+MRcI`.trim();
const RSA_DEFAULT_SIG = `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBALj6oPz4VgbrZENVPMyNTk
xoNT4Ws2zmDNHRKQNCC8XscZrEYGU1zBam4WFt+MrJpIOXgBdGUIASO1UIaZ8l0DPROaaV
nyhAvN2oq5xCYKPqY/hpuxHScN84PEqWSHh6qW4QsGmKKSXiCggvkhJsi6O/ySwqPwJc7J
oJLNyEPFfx3Kbg8e5eMpO1f9mqtJx3MFpGUxEfUv9fzqs/c8s2Y6SUH22pjrNEVcVy++ex
maLezwGRvBlbWOrFHjp1b6n5c6uPSq1L2t8TwR5TS6JKSjpVayDr0sZbMlUghIT6B5A+o3
gl3G9rW7HJAhLqGN3nt52VHEKCuvLKKfXax4JZqtK1lPYTfSjetOkgraUNcdvWBPF9MEFU
d1Sr/IpxEAHFiZBXzcv5317Bx4EGigIDL1yc1o1wpx6hQiLngKzKQ+SZRwMvbIkmSQvghT
6cpVkTCm7BuXfGVsgODP8ehgjfvKCxc48c5k5rNnuumnukO/KkiJagV5+ie6FIxU4wkPA8
6CXVrtyfSjZOYaQYHsTS4f/+eJKWDJD8w9rA64nOT8dQphZrnqrq0fnLI+QcQzcNFNkvQA
4zKIiIbhMWvEYL989gLsltSQSnzyimD06AlBH1doi/zX68CGos16owl6WVeLalo2kbm0jo
v+1kEFQbMZ49Et5lEIw4O/hC31yKchu1AAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAA
AMcnNhLXNoYTItNTEyAAACAEfU2Bp6qJMWhU5MmAPOuhVTxd2Px6m8wgBAaRkDTFr/ca7l
IT/pAVk+qxK+fq/KtdqNqajFKM8URq1wP1Jq/BGPpEJ1ZI1GQEK3ONvA8YzEMhQ4cWXQwi
U06zRhsab+4+RoUQLFvFfxuYOu1GUwVXm6Md2TxNHcHQZ9Aii4WDT9DuRxd1PwCcsymytb
Ynb4JCtj/BW1/jWFYr4KnG+7MQ53PZ17krN09SqAew6svzqQk4WUigknCQuN+XPX/vq9q/
6PqbDQYk6feN1xLiS5mNmJgQdZmeCrYIpG2nOzToQw9dmYnFob59LR1HBtP8TiVT7mDybS
SWQj/lJ9mnBRgbo2Rf/tMKoaWKw2hZYClnakBXYygvEmJmB2nBGG/1S3OQ+wBqOZ6ZhS4y
BGwLiGKPth+4/Dn7HLuYCP7iGztXZzeyYIrun9SBAI+DYVkVmlXaUJ+wK8Ka/Xlg63IHlN
xPaolD3g02oF4CLA4SgE+6msTepDB8RsatGFMFfuR2PwczKrobfsJXDg+CQjKmpTk9J4Jt
XJyZz0fSxZvR1O6N7LrXOkdM/l3a3Yt4dWUnSx9OGsgvf2z+8IU/8JNAKVNsnJjBYGAAVl
fLX7UlAjc179pE4xSZkvZgCknedPHdZBQsBJLEyYSlLNZpfHC4KWONNwlgiZQbmGTY3Smz
591e2g`.trim();

document.addEventListener('DOMContentLoaded', function() {
    const actionButton = document.getElementById('actionButton');
    const expandableSections = document.getElementById('expandableSections');
    const contributorsContent = document.getElementById('contributorsContent');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const loadingText = document.getElementById('loadingText');
    const repoUrlInput = document.getElementById('repoUrl');
    const messageInput = document.getElementById('message');
    const signatureInput = document.getElementById('signature');
    const signatureInputContainer = document.getElementById('signatureInputContainer');
    const rInput = document.getElementById('rInput');
    const rInputContainer = document.getElementById('rInputContainer');
    const modeToggle = document.getElementById('modeToggle');
    const resultMessage = document.getElementById('resultMessage');
    const fillDefaultsButton = document.getElementById('fillDefaults');
    const rOutputContainer = document.getElementById('rOutputContainer');

    // Function to auto-resize textarea
    function autoResizeTextarea(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = (textarea.scrollHeight) + 'px';
    }

    // Add input event listeners for auto-resizing
    messageInput.addEventListener('input', () => autoResizeTextarea(messageInput));
    signatureInput.addEventListener('input', () => autoResizeTextarea(signatureInput));

    // Initial resize for any pre-filled content
    autoResizeTextarea(messageInput);
    autoResizeTextarea(signatureInput);

    // Helper function to convert BigInt to hex string
    function bigIntToHex(bigInt) {
        return '0x' + bigInt.toString(16);
    }

    // Helper function to format hex string with line breaks
    function formatHexString(hex) {
        return hex.match(/.{1,64}/g).join('\n');
    }

    // Function to process message
    async function processMessage(message) {
        if (!message) {
            return;
        }
        try {
            // Add a timeout to prevent hanging
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Message processing timed out')), 30000);
            });

            // Convert message to BigInt and log to console
            const messageAsBigInt = await Promise.race([
                messageToBigInt(message),
                timeoutPromise
            ]);
            
            const chunks = splitBigIntToChunks(messageAsBigInt);
            
            // Ensure we have valid chunks before returning
            if (!chunks || chunks.length === 0) {
                throw new Error('Failed to generate valid message chunks');
            }
            
            return chunks;
        } catch (error) {
            console.error('Error processing message:', error);
            throw new Error(`Failed to process message: ${error.message}`);
        }
    }

    async function processSSHSignature (signature, message) {
        if (!signature) {
            return;
        }
        const algo = getSignatureAlgo(signature);
        let parsed = { 
            ...reduceToCurveMultiplication(ED25519_DEFAULT_SIG, message), 
            ...parseRSASignature(RSA_DEFAULT_SIG) 
        };
        
        if (algo === 'ssh-ed25519') {   
            const ed25519Parsed = reduceToCurveMultiplication(signature, message);
            parsed = {
                ...parsed,
                s: ed25519Parsed.s,
                R: ed25519Parsed.R,
                h: ed25519Parsed.h,
                A: ed25519Parsed.A,
                R_enc: ed25519Parsed.R_enc,
                pk_enc: ed25519Parsed.pk_enc
            };
        } else {
            const rsaParsed = parseRSASignature(signature);
            parsed = {
                ...parsed,
                signature: rsaParsed.signature,
                publicKey: rsaParsed.publicKey
            };
        }
        return parsed;
    }

    // Function to update UI based on mode
    function updateUIMode(isVerifyMode) {
        const label = signatureInputContainer.querySelector('label');
        const placeholder = signatureInput.getAttribute('placeholder');
        
        if (isVerifyMode) {
            label.textContent = 'Proof';
            signatureInput.setAttribute('placeholder', 'Enter your proof here...');
            actionButton.textContent = 'Verify Proof';
            loadingText.textContent = 'Verifying Proof';
            rInputContainer.style.display = 'block';
            rOutputContainer.style.display = 'none';
        } else {
            label.textContent = 'Signature';
            signatureInput.setAttribute('placeholder', 'Enter your signature here...');
            actionButton.textContent = 'Generate Proof';
            loadingText.textContent = 'Generating Proof';
            rInputContainer.style.display = 'none';
            rOutputContainer.style.display = 'block';
        }
    }

    // Initialize UI mode
    updateUIMode(modeToggle.checked);

    // Handle mode toggle
    modeToggle.addEventListener('change', function() {
        updateUIMode(this.checked);
        resultMessage.style.display = 'none';
    });

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
        expandableSections.style.display = 'block';
        
        // Get the accordion button and collapse element
        const accordionButton = document.querySelector('.accordion-button');
        const contributorsCollapse = document.getElementById('contributorsCollapse');
        
        // Create a new bootstrap collapse instance if it doesn't exist
        if (!contributorsCollapse._bsCollapse) {
            new bootstrap.Collapse(contributorsCollapse, {
                toggle: false
            });
        }
        
        // Show the collapse
        bootstrap.Collapse.getInstance(contributorsCollapse).show();
        
        // Update button state
        accordionButton.classList.add('collapsed');
        accordionButton.setAttribute('aria-expanded', 'true');
    }

    // Function to process and display signature
    async function processSignature(signature, message) {
        if (!signature) {
            return;
        }
        let parsedSignatureChunks;
        let parsed;
        
        try {
            // Add a timeout to prevent hanging
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('Signature processing timed out')), 30000);
            });

            // Process the signature with timeout
            parsed = await Promise.race([
                processSSHSignature(signature, message),
                timeoutPromise
            ]);
            
            
            if (!parsed) {
                throw new Error('Failed to parse signature');
            }

            // Process RSA components if they exist
            if (parsed.signature && parsed.publicKey) {
                const signatureChunks = splitBigIntToChunks(parsed.signature);
                const publicKeyChunks = splitBigIntToChunks(parsed.publicKey);
                
                if (!signatureChunks || !publicKeyChunks) {
                    throw new Error('Failed to process RSA components');
                }
                
                parsedSignatureChunks = {
                    ...parsed,
                    signature: signatureChunks,
                    publicKey: publicKeyChunks
                };
            }
            
            // Process ED25519 components if they exist
            if (parsed.s && parsed.R && parsed.h && parsed.A) {
                parsedSignatureChunks = {
                    ...parsedSignatureChunks,
                    s: split256BitIntegerTo64(parsed.s),
                    R: { 
                        x: split256BitIntegerTo64(parsed.R.x), 
                        y: split256BitIntegerTo64(parsed.R.y) 
                    },
                    h: split256BitIntegerTo64(parsed.h),
                    A: { 
                        x: split256BitIntegerTo64(parsed.A.x), 
                        y: split256BitIntegerTo64(parsed.A.y) 
                    },
                    R_enc: parsed.R_enc,
                    pk_enc: parsed.pk_enc
                };
            }

            if (!parsedSignatureChunks) {
                throw new Error('No valid signature components found');
            }

            return parsedSignatureChunks;
            
        } catch (error) {
            console.error('Error processing signature:', error);
            throw new Error(`Failed to process signature: ${error.message}`);
        }
    }


    actionButton.addEventListener('click', async function() {
        const repoUrl = repoUrlInput.value.trim();
        const message = messageInput.value.trim();
        const input = signatureInput.value.trim();
        const rValue = Buffer.from(rInput.value.trim(), "hex");
        const isVerifyMode = modeToggle.checked;
        
        if (!repoUrl) {
            alert('Please enter a repository URL');
            return;
        }

        // Show loading spinner
        loadingSpinner.style.display = 'block';
        expandableSections.style.display = 'none';
        resultMessage.style.display = 'none';

        try {
            // Call the backend API to fetch repo data
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
            
            // Display contributors
            displayContributors(data);
            expandableSections.style.display = 'block';

            if (isVerifyMode) {
                // Verify mode
                let proof = JSON.parse(input);
                const parsedHashedMessage = await processMessage(message);
                const processedKeysandMerkleTree = processKeysAndBuildMerkleTree(data);
                const merkleTreeRoot = processedKeysandMerkleTree.root;
                const r_bytes = Buffer.from(rValue, "hex");
                const processedKeysandMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash(data, message, r_bytes);
                const merkleTreeRootForMsghash = processedKeysandMerkleTreeForMsghash.root;
                const R_weierstrass = R_enc_to_R(r_bytes);
                const vkey = await fetch("circuit_files/verification_key.json").then( function(res) {
                    return res.json();
                });
                const publicSignals = [...parsedHashedMessage, merkleTreeRoot.data, merkleTreeRootForMsghash.data, ...(split256BitIntegerTo64(R_weierstrass.x).map(b => b.toString())), ...(split256BitIntegerTo64(R_weierstrass.y).map(b => b.toString()))];
                //const publicSignals = [merkleTreeRootForMsghash.data, ...(split256BitIntegerTo64(R_weierstrass.x).map(b => b.toString())), ...(split256BitIntegerTo64(R_weierstrass.y).map(b => b.toString()))];
                console.log(publicSignals);
                const isValid = await groth16.verify(vkey, publicSignals, proof);
                resultMessage.textContent = isValid ? 'Proof Verified Successfully!' : 'Proof Verification Failed';
                resultMessage.className = `alert alert-${isValid ? 'success' : 'danger'} text-center mb-4`;
                resultMessage.style.display = 'block';
            } else {
                // Generate mode
                const parsedHashedMessage = await processMessage(message);
                const processedSignature = await processSignature(input, message);
                const parsedRSASignature = processedSignature.signature;
                const parsedRSAPublicKey = processedSignature.publicKey;
                const parsedED25519Signature_s = processedSignature.s;
                const parsedED25519_A = processedSignature.A;  
                const parsedED25519_R = processedSignature.R;
                const parsedED25519_h = processedSignature.h;
                const signatureAlgo = processedSignature.algo;
                const parsedED25519_R_enc = processedSignature.R_enc;
                const parsedED25519_pk_enc = processedSignature.pk_enc;
                // Display the R value
                const rOutput = document.getElementById('rOutput');
                rOutput.value = JSON.stringify(parsedED25519_R_enc.toString('hex'), null, 2);
                const hashedKey = hashArray([...parsedRSAPublicKey, ...parsedED25519_A.x, ...parsedED25519_A.y]);
                //todo add ed25519 public key to processKeysAndBuildMerkleTree
                const processedKeysandMerkleTree = processKeysAndBuildMerkleTree(data);
                const merkleTreeRoot = processedKeysandMerkleTree.root;
                const hashedKeys = processedKeysandMerkleTree.keys;
                const [calculatedMerkleProof, merkleDirectionsTF] = await merkleProof(merkleTreeRoot, hashedKey, hashedKeys.indexOf(hashedKey));
                const merkleDirections = merkleDirectionsTF.map((x) => x ? "1" : "0");
                
                const processedKeysandMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash(data, message, parsedED25519_R_enc);
                const merkleTreeRootForMsghash = processedKeysandMerkleTreeForMsghash.root;
                const hashedKeysForMsghash = processedKeysandMerkleTreeForMsghash.keys;
                const h = processPublicKeyForMsghash(parsedED25519_pk_enc, message, parsedED25519_R_enc);
                const hashedMsghash = hashArray(split256BitIntegerTo64(h));
                const [calculatedMerkleProofForMsghash, merkleDirectionsTFForMsghash] = await merkleProof(merkleTreeRootForMsghash, hashedMsghash, hashedKeysForMsghash.indexOf(hashedMsghash));
                const merkleDirectionsForMsghash = merkleDirectionsTFForMsghash.map((x) => x ? "1" : "0");
                console.log("INPUTS", JSON.stringify({
                    message: parsedHashedMessage,
                    signature: parsedRSASignature,
                    correctKey: parsedRSAPublicKey,
                    pubKeyMerkleRoot: merkleTreeRoot.data,
                    pubKeyTreeProofs: calculatedMerkleProof,
                    pubKeyTreeDirections: merkleDirections,
                    
                    msghashMerkleRoot: merkleTreeRootForMsghash.data,
                    msghashTreeProofs: calculatedMerkleProofForMsghash,
                    msghashTreeDirections: merkleDirectionsForMsghash,
                    
                    s: parsedED25519Signature_s.map(b => b.toString()),
                    R: [parsedED25519_R.x.map(b => b.toString()), parsedED25519_R.y.map(b => b.toString())],
                    m: parsedED25519_h.map(b => b.toString()),
                    A: [parsedED25519_A.x.map(b => b.toString()), parsedED25519_A.y.map(b => b.toString())],
                    
                }, null, 2));
                const { proof, publicSignals } = await groth16.fullProve({
                    message: parsedHashedMessage,
                    signature: parsedRSASignature,
                    correctKey: parsedRSAPublicKey,
                    pubKeyMerkleRoot: merkleTreeRoot.data,
                    pubKeyTreeProofs: calculatedMerkleProof,
                    pubKeyTreeDirections: merkleDirections,
                    
                    msghashMerkleRoot: merkleTreeRootForMsghash.data,
                    msghashTreeProofs: calculatedMerkleProofForMsghash,
                    msghashTreeDirections: merkleDirectionsForMsghash,
                    
                    s: parsedED25519Signature_s,
                    R: [parsedED25519_R.x, parsedED25519_R.y],
                    m: parsedED25519_h,
                    A: [parsedED25519_A.x, parsedED25519_A.y],
                    
                }, "circuit_files/circuit.wasm", "circuit_files/circuit_final.zkey");

                // Display the proof
                const proofStr = JSON.stringify({proof:proof, publicSignals:publicSignals}, null, 2);

                resultMessage.innerHTML = `
                    <div class="alert alert-success text-center mb-4">
                        Proof Generated Successfully!
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Generated Proof</h5>
                        </div>
                        <div class="card-body">
                            <pre class="mb-0"><code>${proofStr}</code></pre>
                        </div>
                    </div>
                `;
                resultMessage.style.display = 'block';
            }
        } catch (error) {
            console.error('Error:', error);
            resultMessage.textContent = 'Error: ' + error.message;
            resultMessage.className = 'alert alert-danger text-center mb-4';
            resultMessage.style.display = 'block';
        } finally {
            loadingSpinner.style.display = 'none';
        }
    });

    fillDefaultsButton.addEventListener('click', function() {
        repoUrlInput.value = 'https://github.com/psquare1/repo-group-sign';
        messageInput.value = '0xPARC';
        
        if (modeToggle.checked) {
            // Verify mode
            signatureInput.value = `
{
    "pi_a": [
      "11287617555005531314307598695521687255870840654989007139356484446189556764997",
      "3522590115965740844744497810120719570701349321901000828747194512538242548283",
      "1"
    ],
    "pi_b": [
      [
        "12919536697313723705478798888353702522901806641407830717994355723789562715682",
        "5953109678605024206108900660985911426124989571311366271407730470489072498917"
      ],
      [
        "20839985050101043585462517064450311864279277096735555310122594308064986253955",
        "8249457606177971987827449563293440084179863349043198696381428789233468905645"
      ],
      [
        "1",
        "0"
      ]
    ],
    "pi_c": [
      "11674263771239781116100933362080920192116200378307521959995778201573644282477",
      "16390729114952418824971257673716434061765101560598380314193611351987585444964",
      "1"
    ],
    "protocol": "groth16",
    "curve": "bn128"
  }`;
rInput.value = "5878b4a82279925e4d16aa932ff00b56cff9b4eb8d58bb2a35b2cb9e4e238111";
        } else {
            // Generate mode
            signatureInput.value = `U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbioQPTTkiqMF+czNN5aIigXs1M
6/mB158ZN69E21/4IAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEAA/hLYJk1jAdQJz26hrjHkGrqExY+7S4n3dxDMUBgezhw+sWtKAauP0kw39CYrYI
1fgBmVcvlzy0Q0BqFyU20B`.trim()
        }
        
        // Trigger auto-resize after setting values
        autoResizeTextarea(messageInput);
        autoResizeTextarea(signatureInput);
    });
}); 

// Valid RSA Signature: `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAMeroewqNQMc3NrpCXX/WzBvDUB/b27cv3+lIu3EH+CUyNfcP6cV/rpH9HYAhVEpnn50vIrDFZs1Rf0k1te/inCNQKMjqSHSSFNE6XUy29BXSNFda/YoUyDhtfJv/69m9XEZBnCCO3Lx3pVnG1j1LaKn00rhftceZcMx5dvB4euWUkzdWQLpk11qwtdGv+I1/cmgy5ETFgLkJj2RDZEtVtq/cBEX+R2GV9CwHwZ3lJ/E2QPYY0N2knwQCmA0AGm63qc4LziXO1erIpaMVUAsPx2mWrRHlQbjBDFuJYgoORtF3YaZbJdUrW39Tf0BWFZsutmRn9VX+1mZctbEMmuIAU1zXrymBXeCdjyLJibed+LnzGPVe6hltAutWMVij9dBaMGQi+/p5VkBhOnmoPAsUAfhgHuk9cTiMLJtnR+JuE5dKlKi9BscaOQQ79Ih69gEmysqdmp+nOZbs3kNxz+7lidJt0EYmhkCTBwwxmmRrY1xagHORQWz/5MU/OFDh0d+mYcqsONYk9eAxCZhPEOg8Nn/LsvgcUO05NoTS8RHwQ4OImk36lCdN5ql/dy1GU1uu3zh9l5fQsw/Lp8q8sXYU2eVWESrFeduDWPG6Y34dp5vrLoWW/oRHLM+LXPJzYdjezD010DEkbzk78tqIlBmJo01TEjQQW/znoVUoLQ2VPd1AAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAAAMcnNhLXNoYTItNTEyAAACAIR3B+M+wyOfyw6wNVLiSCp5AjEcs6zczGpSSl8ExxLQ7nMdZw9oL20Z39mq8Hfv8bbXOntUqqRk2hFH8D5HiDzqEELNVps4BqRgrOC7u0LMlTs6CPWBFEcI4FP4uzS36+uOppVln7XMYNZX3iVTVSjKcB5EBxpCULoqfNN8ee/t0/bq1ZCRazYvzlTOoXQf6iEgeTQTaR9xLDh3YueVUZRWfl4p2PhgKdawH56BXk9T6trIMzMIhuAH5qxJ4ZyrEdJh4qgg5KKDzkN/k5w3Is1bTgTNzGOBqN5EFXIizWt5xInbCo9diGT6zjyFjxLSWm+79KrW+u0aq7zwdwBKzBBM5oiymAFfCMllxY2NaqHdgQ1xMqk9FOyBCFVnqBDzGhApTMHlaWoEHkKlB49RmURUItcn09fzCxmXiP267dgf9lvTkvpDqQkQpRe02vhAOWRYTIer+AtWLeIFYvE5N6GDR9guXww9+Ka9Hn+xm2jrkqFXuD2y33h0P2NlD3t3EMyatvfPeGwWwGh6upg++BWXU+1QvFjWQup0fXH60utOcdGauMn42jf7Ifwg/MpICBRaYkmcrJfzYRD5DTiSy9svk0Bt4vy1iUlBrRY8FrBLEy3CurvpAx+o1I/i0smCHTAebx7U7NmmedC12O3fqS7jpD8E3h5jIGfuEbHue5Ug`;
