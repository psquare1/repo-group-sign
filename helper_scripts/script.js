import { groth16 } from "snarkjs";

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
            // Convert message to BigInt and log to console
            const messageAsBigInt = await messageToBigInt(message);
            console.log('Message:', message);
            //console.log('Message as BigInt:', formatHexString(bigIntToHex(messageAsBigInt)));
            return splitBigIntToChunks(messageAsBigInt);
        } catch (error) {
            console.error('Error processing message:', error);
            throw new Error('Failed to process message');
        }
    }

    async function processSSHSignature (signature) {
        if (!signature) {
            return;
        }
        const algo = getSignatureAlgo(signature);
        let parsed = {
            signature: 0n,
            publicKey: 0n,
            s: 0n,
            R: { x: 0n, y: 0n },
            h: 0n,
            A: { x: 0n, y: 0n },
            algo: algo
        };
        
        if (algo === 'ssh-ed25519') {   
            const ed25519Parsed = reduceToCurveMultiplication(signature);
            parsed = {
                ...parsed,
                s: ed25519Parsed.s,
                R: ed25519Parsed.R,
                h: ed25519Parsed.h,
                A: ed25519Parsed.A
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
        } else {
            label.textContent = 'Signature';
            signatureInput.setAttribute('placeholder', 'Enter your signature here...');
            actionButton.textContent = 'Generate Proof';
            loadingText.textContent = 'Generating Proof';
            rInputContainer.style.display = 'none';
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
    function processSignature(signature) {
        if (!signature) {
            return;
        }
        let parsedSignatureChunks;
        try {
            const parsed = processSSHSignature(signature);
            console.log('Parsed signature:', parsed);
            
            parsedSignatureChunks = {
                signature: splitBigIntToChunks(parsed.signature),
                publicKey: splitBigIntToChunks(parsed.publicKey),
                s: split256BitIntegerTo64(parsed.s),
                R: { x: split256BitIntegerTo64(parsed.R.x), y: split256BitIntegerTo64(parsed.R.y) },
                h: split256BitIntegerTo64(parsed.h),
                A: { x: split256BitIntegerTo64(parsed.A.x), y: split256BitIntegerTo64(parsed.A.y) },
                algo: parsed.algo
            };
            //console.log('Public Key:', formatHexString(bigIntToHex(parsed.publicKey)));
            //console.log('Signature:', formatHexString(bigIntToHex(parsed.signature)));
        } catch (error) {
            console.error('Error parsing signature:', error);
            parsedSignatureChunks = [];
        }   
        return parsedSignatureChunks;
    }


    actionButton.addEventListener('click', async function() {
        const repoUrl = repoUrlInput.value.trim();
        const message = messageInput.value.trim();
        const input = signatureInput.value.trim();
        const rValue = rInput.value.trim();
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
                const proof = JSON.parse(input);
                console.log(proof);
                const parsedHashedMessage = await processMessage(message);
                const processedKeysandMerkleTree = processKeysAndBuildMerkleTree(data);
                const merkleTreeRoot = processedKeysandMerkleTree.root;
                const parsedED25519_R = processSignature(rValue).R;
                const processedKeysandMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash(data, message, parsedED25519_R);
                const merkleTreeRootForMsghash = processedKeysandMerkleTreeForMsghash.root;

                const vkey = await fetch("circuit_files/verification_key.json").then( function(res) {
                    return res.json();
                });
                const publicSignals = [...parsedHashedMessage, merkleTreeRoot.data, merkleTreeRootForMsghash.data];
                
                console.log(publicSignals);
                const isValid = await groth16.verify(vkey, publicSignals, proof);
                resultMessage.textContent = isValid ? 'Proof Verified Successfully!' : 'Proof Verification Failed';
                resultMessage.className = `alert alert-${isValid ? 'success' : 'danger'} text-center mb-4`;
                resultMessage.style.display = 'block';
            } else {
                // Generate mode
                const parsedHashedMessage = await processMessage(message);
                const processedSignature = await processSignature(input);
                const parsedRSASignature = processedSignature.signature;
                const parsedRSAPublicKey = processedSignature.publicKey;
                const parsedED25519Signature_s = processedSignature.s;
                const parsedED25519_A = processedSignature.A;  
                const parsedED25519_R = processedSignature.R;
                const parsedED25519_h = processedSignature.h;
                const signatureAlgo = processedSignature.algo;
                const hashedKey = hashArray([...parsedRSAPublicKey, ...parsedED25519_A.x, ...parsedED25519_A.y]);
                //todo add ed25519 public key to processKeysAndBuildMerkleTree
                const processedKeysandMerkleTree = processKeysAndBuildMerkleTree(data);
                const merkleTreeRoot = processedKeysandMerkleTree.root;
                const hashedKeys = processedKeysandMerkleTree.keys;
                const [calculatedMerkleProof, merkleDirectionsTF] = await merkleProof(merkleTreeRoot, hashedKey, hashedKeys.indexOf(hashedKey));
                const merkleDirections = merkleDirectionsTF.map((x) => x ? "1" : "0");
            

                const processedKeysandMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash(data, message, parsedED25519_R);
                const merkleTreeRootForMsghash = processedKeysandMerkleTreeForMsghash.root;
                const hashedKeysForMsghash = processedKeysandMerkleTreeForMsghash.keys;
                const [calculatedMerkleProofForMsghash, merkleDirectionsTFForMsghash] = await merkleProof(merkleTreeRootForMsghash, hashedKey, hashedKeysForMsghash.indexOf(hashedKey));
                const merkleDirectionsForMsghash = merkleDirectionsTFForMsghash.map((x) => x ? "1" : "0");

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
                    R: parsedED25519_R,
                    m: parsedED25519_h,
                    A: parsedED25519_A,
                    
                }, "circuit_files/circuit.wasm", "circuit_files/circuit_final.zkey");

                // Display the proof
                const proofStr = JSON.stringify(proof, null, 2);

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
            signatureInput.value = `{
  "pi_a": [
    "2087816746059447378613789863274171259955441565100867431687607166526213851626",
    "45262406362907528750070471807415002638149226887668432177363135831808643290",
    "1"
  ],
  "pi_b": [
    [
      "19965353234120306143391199371005958432150949802662795651713269690765962120242",
      "16808042615410842339135962245268752563507787134887832251905046661912270898217"
    ],
    [
      "7470543474023249126992756947356802688766728401791962016458074213854977415270",
      "2930904658534389389614780738614406021966148062555037350220656329753951602420"
    ],
    [
      "1",
      "0"
    ]
  ],
  "pi_c": [
    "13022010164535466054584048196755925960469404079368849456065147331990151959473",
    "21250807891549099311602617214656054329993945948190668318077879021131129902838",
    "1"
  ],
  "protocol": "groth16",
  "curve": "bn128"
}`;
        } else {
            // Generate mode
            signatureInput.value = `U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBAMeroewqNQMc3NrpCXX/WzBvDUB/b27cv3+lIu3EH+CUyNfcP6cV/rpH9HYAhVEpnn50vIrDFZs1Rf0k1te/inCNQKMjqSHSSFNE6XUy29BXSNFda/YoUyDhtfJv/69m9XEZBnCCO3Lx3pVnG1j1LaKn00rhftceZcMx5dvB4euWUkzdWQLpk11qwtdGv+I1/cmgy5ETFgLkJj2RDZEtVtq/cBEX+R2GV9CwHwZ3lJ/E2QPYY0N2knwQCmA0AGm63qc4LziXO1erIpaMVUAsPx2mWrRHlQbjBDFuJYgoORtF3YaZbJdUrW39Tf0BWFZsutmRn9VX+1mZctbEMmuIAU1zXrymBXeCdjyLJibed+LnzGPVe6hltAutWMVij9dBaMGQi+/p5VkBhOnmoPAsUAfhgHuk9cTiMLJtnR+JuE5dKlKi9BscaOQQ79Ih69gEmysqdmp+nOZbs3kNxz+7lidJt0EYmhkCTBwwxmmRrY1xagHORQWz/5MU/OFDh0d+mYcqsONYk9eAxCZhPEOg8Nn/LsvgcUO05NoTS8RHwQ4OImk36lCdN5ql/dy1GU1uu3zh9l5fQsw/Lp8q8sXYU2eVWESrFeduDWPG6Y34dp5vrLoWW/oRHLM+LXPJzYdjezD010DEkbzk78tqIlBmJo01TEjQQW/znoVUoLQ2VPd1AAAABGZpbGUAAAAAAAAABnNoYTUxMgAAAhQAAAAMcnNhLXNoYTItNTEyAAACAIR3B+M+wyOfyw6wNVLiSCp5AjEcs6zczGpSSl8ExxLQ7nMdZw9oL20Z39mq8Hfv8bbXOntUqqRk2hFH8D5HiDzqEELNVps4BqRgrOC7u0LMlTs6CPWBFEcI4FP4uzS36+uOppVln7XMYNZX3iVTVSjKcB5EBxpCULoqfNN8ee/t0/bq1ZCRazYvzlTOoXQf6iEgeTQTaR9xLDh3YueVUZRWfl4p2PhgKdawH56BXk9T6trIMzMIhuAH5qxJ4ZyrEdJh4qgg5KKDzkN/k5w3Is1bTgTNzGOBqN5EFXIizWt5xInbCo9diGT6zjyFjxLSWm+79KrW+u0aq7zwdwBKzBBM5oiymAFfCMllxY2NaqHdgQ1xMqk9FOyBCFVnqBDzGhApTMHlaWoEHkKlB49RmURUItcn09fzCxmXiP267dgf9lvTkvpDqQkQpRe02vhAOWRYTIer+AtWLeIFYvE5N6GDR9guXww9+Ka9Hn+xm2jrkqFXuD2y33h0P2NlD3t3EMyatvfPeGwWwGh6upg++BWXU+1QvFjWQup0fXH60utOcdGauMn42jf7Ifwg/MpICBRaYkmcrJfzYRD5DTiSy9svk0Bt4vy1iUlBrRY8FrBLEy3CurvpAx+o1I/i0smCHTAebx7U7NmmedC12O3fqS7jpD8E3h5jIGfuEbHue5Ug`;
        }
        
        // Trigger auto-resize after setting values
        autoResizeTextarea(messageInput);
        autoResizeTextarea(signatureInput);
    });
}); 