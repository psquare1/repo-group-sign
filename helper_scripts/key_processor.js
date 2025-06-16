
//const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
//const { hashArray, merkleTree } = require('./merkle');
import { Buffer } from "buffer"

const ED25519_DEFAULT_KEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1l7RV1UOAMPQlP3Mj9dHZZxhtfWtzhDAVbfIT+fmFb duruozer13@gmail.com
`.trim();
const RSA_DEFAULT_KEY = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCv0UCsoturWdqPe7K82hCN+D/jS8TkFIsmWV2V3WGlkjcbgGEu9TtNW+HUG/oX5LfV5PZeq5pm74T7YfxKV9bQRRhuBJDusHBmbFkPEcverJ6Jy473jKlFNamM2gUeRjU49fNf5nsUkp/Nz299hNkxMP7tQKXa+1trUAopmZjV9grqgm2aybG7llV/rfQU9vLVY7r/4ng1GxfR4+LZsidiTtUDo+ub9NgYCeGWP/3Q+kPPA5zeXt/XJ71Xqb7c8kW+2QVaGLphDxMmecftETHdsfG+B+jE/vjEDWtIdCPwoCrZnDINI6WekvXo2E9lM9a3vVsOfclWuNgKwUE+MihWYAdU8G1Es9WKoeod7+dHM3/XccGy+Stfc0cRepiOdIik5tzsw1WWO6h2F2nXoPECFxsZi3RxFKp7FuDznLSJ5qFDH0uTE6FdmtBrsG+Il9jWNfSnV1kHREj36nbmqknnlb0/IUPtCf2Lbg1YUALJ1o6BmzkOqoDQoCet3lefL8jhMNZuhNHHEb4wr12x+Wyyck20yZh/8zeFfMgnwgA+RfseFUVmzXuptCwzrgnZP1JCDeLMhSJu96+tCymtw3WGvhNe3TxEjFJP39pX3l5BA/AbyRKNGEtLiK9U8vhocuRU+g+YwC40tAKZ9iRozAGg4W7vj0j58qB9zF1NvyRkzQ== duruozer13@gmail.com`;

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
window.ED25519_DEFAULT_KEY  = ED25519_DEFAULT_KEY;
window.RSA_DEFAULT_KEY = RSA_DEFAULT_KEY;