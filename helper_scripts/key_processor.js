
//const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
//const { hashArray, merkleTree } = require('./merkle');

function processPublicKey(key){
    let parsed = [];
    
    if (key.type === 'ED25519') {   
        const ed25519Parsed = reduceED25519PubKeyToCurve(key).A;
        parsed = [...splitBigIntToChunks(0n), ...split256BitIntegerTo64(ed25519Parsed.x), ...split256BitIntegerTo64(ed25519Parsed.y)];
    } else if (key.type === 'RSA'){
        const rsaParsed = parseRSASignature(signature);
        parsed = [
            ...splitBigIntToChunks(rsaParsed.signature),
            ...split256BitIntegerTo64(0),
            ...split256BitIntegerTo64(0)
        ];
    }
    return parsed
}

function processPublicKeyForMsghash(key, message, R){
    let ed25519Parsed = Buffer.alloc(32);
    if (key.type === 'ED25519') {   
        ed25519Parsed = parsePublicEd25519Key(key).key;
    }
    return createEncodedMessage(message, ed25519Parsed, R);
}

function processKeysAndBuildMerkleTree(data) {
    try {
        // Extract RSA and ED25519 keys from the data
        const publicKeys = Object.values(data.contributors).flatMap(contributor => 
            contributor.publicKeys
                .filter(key => key.type === 'RSA' || key.type === 'ED25519')
                .map(key => key.key)
        );

        //console.log(`Found ${rsaKeys.length} RSA keys to process`);
        
        // Process each key and collect hashed values
        const hashedKeys = [];
        
        publicKeys.forEach((key, index) => {
        try {
            const parsedKey = processPublicKey(key);
            const currentHashedKey = hashArray(parsedKey);
            console.log(`Hashed SSH Key ${index + 1}:`);
            console.log(currentHashedKey);
            hashedKeys.push(currentHashedKey);
        } catch (error) {
            console.error(`Error processing key ${index + 1}: ${error.message}`);
        }
        });
        // Build the Merkle tree
        const merkleRoot = merkleTree(hashedKeys);
        return {
            root: merkleRoot,
            keys:hashedKeys
        };
    } catch (error) {
        console.error('Error processing keys and building Merkle tree:', error);
        throw error;
    }

}


function processKeysAndBuildMerkleTreeForMsghash(data, message, R) {
    try {
        // Extract RSA and ED25519 keys from the data
        const publicKeys = Object.values(data.contributors).flatMap(contributor => 
            contributor.publicKeys
                .filter(key => key.type === 'RSA' || key.type === 'ED25519')
                .map(key => key.key)
        );  

        //console.log(`Found ${rsaKeys.length} RSA keys to process`);
        
        // Process each key and collect hashed messages
        const hashedMessages = [];
            
        publicKeys.forEach((key, index) => {
            try {
                const h = processPublicKeyForMsghash(key, message, R);
                const currentHashedMessage = hashArray(split256BitIntegerTo64(h));
                hashedMessages.push(currentHashedMessage);
            } catch (error) {
                console.error(`Error processing key ${index + 1}: ${error.message}`);
            }
        });
        // Build the Merkle tree
        const merkleRoot = merkleTree(hashedMessages);
        return {
            root: merkleRoot,
            keys:hashedMessages
        };
    } catch (error) {
        console.error('Error processing keys for msghash and building Merkle tree:', error);
        throw error;
    }
}

function processMerkleProof(merkleRoot, hashedKey, hashedKeys) {
    const [calculatedMerkleProof, merkleDirectionsTF] = merkleProof(merkleRoot, hashedKey, hashedKeys.indexOf(hashedKey));
    const merkleDirections = merkleDirectionsTF.map((x) => x ? "1" : "0");
    return {
        proof: calculatedMerkleProof,
        merkleDirections: merkleDirections
    }
}

window.processKeysAndBuildMerkleTree = processKeysAndBuildMerkleTree;
window.processMerkleProof = processMerkleProof;
