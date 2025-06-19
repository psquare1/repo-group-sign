
//const { parseRSAPublicKey, splitBigIntToChunks } = require('./temporary_rsakey_parser.js');
//const { hashArray, merkleTree } = require('./merkle');
import { Buffer } from "buffer"

const ED25519_DEFAULT_KEY = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAkJkECf2GcebGMzqNQdoyGra0lZ5hVMqwFOvBJLxnq duruozer13@gmail.com`.trim();
const RSA_DEFAULT_KEY = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC4+qD8+FYG62RDVTzMjU5MaDU+FrNs5gzR0SkDQgvF7HGaxGBlNcwWpuFhbfjKyaSDl4AXRlCAEjtVCGmfJdAz0TmmlZ8oQLzdqKucQmCj6mP4absR0nDfODxKlkh4eqluELBpiikl4goIL5ISbIujv8ksKj8CXOyaCSzchDxX8dym4PHuXjKTtX/ZqrScdzBaRlMRH1L/X86rP3PLNmOklB9tqY6zRFXFcvvnsZmi3s8BkbwZW1jqxR46dW+p+XOrj0qtS9rfE8EeU0uiSko6VWsg69LGWzJVIISE+geQPqN4Jdxva1uxyQIS6hjd57edlRxCgrryyin12seCWarStZT2E30o3rTpIK2lDXHb1gTxfTBBVHdUq/yKcRABxYmQV83L+d9ewceBBooCAy9cnNaNcKceoUIi54CsykPkmUcDL2yJJkkL4IU+nKVZEwpuwbl3xlbIDgz/HoYI37ygsXOPHOZOazZ7rpp7pDvypIiWoFefonuhSMVOMJDwPOgl1a7cn0o2TmGkGB7E0uH//niSlgyQ/MPawOuJzk/HUKYWa56q6tH5yyPkHEM3DRTZL0AOMyiIiG4TFrxGC/fPYC7JbUkEp88opg9OgJQR9XaIv81+vAhqLNeqMJellXi2paNpG5tI6L/tZBBUGzGePRLeZRCMODv4Qt9cinIbtQ== duruozer13@gmail.com`;

function processPublicKey(key){
    let parsed = [];
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
    return parsed
}

function processPublicKeyForMsghash(key, message, R){
    let ed25519Parsed = parsePublicEd25519Key(ED25519_DEFAULT_KEY).key;
    if (key.type === 'ED25519') {   
        try{
            ed25519Parsed = parsePublicEd25519Key(key.key).key;
        } catch (error) {
            console.error(`Error parsing ED25519 key: ${error.message}`);
            return null;
        }
    }
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
                //.map(key => key.key)
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
window.processKeysAndBuildMerkleTreeForMsghash = processKeysAndBuildMerkleTreeForMsghash;
window.processPublicKeyForMsghash = processPublicKeyForMsghash;
window.ED25519_DEFAULT_KEY  = ED25519_DEFAULT_KEY;
window.RSA_DEFAULT_KEY = RSA_DEFAULT_KEY;