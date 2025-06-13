const fs = require('fs').promises;
const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
const { hashArray, merkleTree } = require('./merkle');


function processKeysAndBuildMerkleTree(data) {
    try {
        // Extract all RSA keys from the data
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
                
                const hashedKey = hashArray(keyArray);
                console.log(`Hashed RSA Key ${index + 1}:`);
                console.log(hashedKey);
                
                hashedKeys.push(hashedKey);
            } catch (error) {
                console.error(`Error processing key ${index + 1}: ${error.message}`);
            }
        });

        console.log(`\nSuccessfully processed ${hashedKeys.length} keys`);

        console.log("HEREE:",hashedKeys)

        // Build the Merkle tree
        const merkleRoot = merkleTree(hashedKeys);

        return {
            merkleRoot,
            processedKeys: hashedKeys
        };
    } catch (error) {
        console.error('Error processing keys and building Merkle tree:', error);
        throw error;
    }
}

// Example usage
if (require.main === module) {
    const jsonFilePath = process.argv[2];
    if (!jsonFilePath) {
        console.error('Please provide a JSON file path');
        process.exit(1);
    }

    processKeysAndBuildMerkleTree(jsonFilePath)
        .then(result => {
            console.log('\nMerkle Root:', result.merkleRoot);
            console.log(`\nProcessed ${result.processedKeys} out of ${result.totalKeys} RSA keys`);
        })
        .catch(error => {
            console.error('Failed to process keys:', error);
            process.exit(1);
        });
}

module.exports = {
    processKeysAndBuildMerkleTree
}; 