
//const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
//const { hashArray, merkleTree } = require('./merkle');
import { Buffer } from "buffer"

const ED25519_DEFAULT_KEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1l7RV1UOAMPQlP3Mj9dHZZxhtfWtzhDAVbfIT+fmFb duruozer13@gmail.com
`.trim();
const RSA_DEFAULT_KEY = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDHq6HsKjUDHNza6Ql1/1swbw1Af29u3L9/pSLtxB/glMjX3D+nFf66R/R2AIVRKZ5+dLyKwxWbNUX9JNbXv4pwjUCjI6kh0khTROl1MtvQV0jRXWv2KFMg4bXyb/+vZvVxGQZwgjty8d6VZxtY9S2ip9NK4X7XHmXDMeXbweHrllJM3VkC6ZNdasLXRr/iNf3JoMuRExYC5CY9kQ2RLVbav3ARF/kdhlfQsB8Gd5SfxNkD2GNDdpJ8EApgNABput6nOC84lztXqyKWjFVALD8dplq0R5UG4wQxbiWIKDkbRd2GmWyXVK1t/U39AVhWbLrZkZ/VV/tZmXLWxDJriAFNc168pgV3gnY8iyYm3nfi58xj1XuoZbQLrVjFYo/XQWjBkIvv6eVZAYTp5qDwLFAH4YB7pPXE4jCybZ0fibhOXSpSovQbHGjkEO/SIevYBJsrKnZqfpzmW7N5Dcc/u5YnSbdBGJoZAkwcMMZpka2NcWoBzkUFs/+TFPzhQ4dHfpmHKrDjWJPXgMQmYTxDoPDZ/y7L4HFDtOTaE0vER8EODiJpN+pQnTeapf3ctRlNbrt84fZeX0LMPy6fKvLF2FNnlVhEqxXnbg1jxumN+Haeb6y6Flv6ERyzPi1zyc2HY3sw9NdAxJG85O/LaiJQZiaNNUxI0EFv856FVKC0NlT3dQ==`;

function processPublicKey(key){
    let parsed = [];
    console.log('key type', key.type);
    if (key.type === 'ED25519') {   
        const ed25519Parsed = reduceED25519PubKeyToCurve(key.key).A;
        const rsaParsed = parseRSAPublicKey(RSA_DEFAULT_KEY);
        parsed = [...splitBigIntToChunks(rsaParsed), ...split256BitIntegerTo64(ed25519Parsed.x), ...split256BitIntegerTo64(ed25519Parsed.y)];
    } else if (key.type === 'RSA'){
        const ed25519Parsed = reduceED25519PubKeyToCurve(ED25519_DEFAULT_KEY).A;
        const rsaParsed = parseRSAPublicKey(key.key);
        parsed = [
            ...splitBigIntToChunks(rsaParsed),
            ...split256BitIntegerTo64(ed25519Parsed.x),
            ...split256BitIntegerTo64(ed25519Parsed.y)
        ];
    }
    console.log('key', key);
    console.log('parsed', parsed);
    return parsed
}

function processPublicKeyForMsghash(key, message, R){
    let ed25519Parsed = parsePublicEd25519Key(ED25519_DEFAULT_KEY).key;
    if (key.type === 'ED25519') {   
        try{
            ed25519Parsed = parsePublicEd25519Key(key.data).key;
        } catch (error) {
            console.error(`Error parsing ED25519 key: ${error.message}`);
            return null;
        }
    }
    console.log('ed25519Parsed', ed25519Parsed);
    console.log('message', message);
    console.log('R', R);
    let encodedMessage;
    try{
        encodedMessage = createEncodedMessage(message, ed25519Parsed, R);
    } catch (error) {
        console.error(`Error creating encoded message: ${error.message}`);
        return null;
    }
    return encodedMessage;
}

function processKeysAndBuildMerkleTree(data) {
    try {
        // Extract RSA and ED25519 keys from the data
        const publicKeys = Object.values(data.contributors).flatMap(contributor => 
            contributor.publicKeys
                .filter(key => key.type === 'RSA' || key.type === 'ED25519')
                //.map(key => key.key)
        );

        //console.log(`Found ${rsaKeys.length} RSA keys to process`);
        
        // Process each key and collect hashed values
        const hashedKeys = [];
        
        publicKeys.forEach((key, index) => {
        try {
            const parsedKey = processPublicKey(key);
            const currentHashedKey = hashArray(parsedKey);
            console.log('key', key);
            console.log('parsedKey', parsedKey);
            console.log(`Hashed SSH Key ${index + 1}:`);
            console.log(currentHashedKey);
            hashedKeys.push(currentHashedKey);
        } catch (error) {
            console.error(`Error processing key ${index + 1}: ${error.message}`);
        }
        });
        // Build the Merkle tree
        console.log('Merkle tree built with hashedKeys', hashedKeys);
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
        console.log('Merkle tree built with hashedMessages', hashedMessages);
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
window.processKeysAndBuildMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash;
window.processPublicKeyForMsghash = processPublicKeyForMsghash;