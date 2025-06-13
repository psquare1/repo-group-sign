
//const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
//const { hashArray, merkleTree } = require('./merkle');


function processKeysAndBuildMerkleTree(data) {
    try {
        // Extract all RSA keys from the data
        // TODO: Expand functionality to include other key types
        const rsaKeys = Object.values(data.contributors).flatMap(contributor => 
            contributor.publicKeys
                .filter(key => key.type === 'RSA')
                .map(key => key.key)
        );

        console.log(`Found ${rsaKeys.length} RSA keys to process`);
        
        // Process each RSA key and collect hashed values
        const hashedKeys = [];
        
        rsaKeys.forEach((key, index) => {
            try {
                const parsedKey = parseRSAPublicKey(key);
                const keyArray = splitBigIntToChunks(parsedKey);
                
                const currentHashedKey = hashArray(keyArray);
                console.log(`Hashed RSA Key ${index + 1}:`);
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
