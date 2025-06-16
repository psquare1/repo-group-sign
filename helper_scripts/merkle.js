import { poseidon2 } from "poseidon-lite/poseidon2";
// Use global poseidon2 from CDN
//const poseidon2 = window.Poseidon2;
// MAX_SIZE should be 2^k - 1 for some k
const MAX_SIZE = 7;

function hashArray(input, size = 35) {
    var hval = "0";
    console.log('Input array:', input);
    for (var i = 0; i < input.length; i++) {
        hval = poseidon2([hval, input[i]]).toString();
    }
    return hval;
}

// Compute and log the hash
// const hash = hashArray(input, 35);
// console.log('Input array length:', input.length);
// console.log('Final hash:', hash);

class MerkleNode {
    constructor(data, l_index, r_index, is_root = false) {
        this.is_root = is_root;
        this.l_index = l_index;
        this.r_index = r_index;
        if (l_index === r_index) {
            this.left = null;
            this.right = null;
            if (l_index < data.length) {
                this.data = data[l_index];
            }
            else {
                this.data = "0";
            }
        }
        else {
            var m_index = Math.floor((l_index + r_index) / 2);
            this.left = new MerkleNode(data, l_index, m_index);
            this.right = new MerkleNode(data, m_index + 1, r_index);
            this.data = poseidon2([this.left.data, this.right.data]).toString();
        }
    }
}

/**
 * Creates a merkle tree from an array of data using the poseidon hash function.
 * Returns the root merkle node.
 */
function merkleTree(data) {
    // Create a merkle tree from the data
    const tree = new MerkleNode(data, 0, MAX_SIZE, true);
    return tree;
}


/**
 * Creates a merkle proof for a given value in the merkle tree.
 * Takes in as input the tree, the value, and the index of the value in the data array.
 * Returns the merkle proof and the directions.
 * 
 * A False direction means that the value is in the left subtree and we must hash val with the right child's data, 
 * a True direction means that the value is in the right subtree and we must hash left child's data with val.
 */
function merkleProof(tree, val, index) {
    //console.log("tree.data: ", tree.data);
    //console.log("tree.l_index: ", tree.l_index, "tree.r_index: ", tree.r_index);
    //console.log("val: ", val);
    if (tree.left === null && tree.right === null) {
        //console.log("val: ", val);
        //console.log("tree.data: ", tree.data);
        if (val === tree.data) {
            return [[], []];
        }
        else {
            throw new Error("Value not found in merkle tree");
        }
    }
    var m_index = Math.floor((tree.l_index + tree.r_index) / 2);
    if (index <= m_index) {
        const [current_proof, current_directions] = merkleProof(tree.left, val, index);
        current_proof.push(tree.right.data);
        current_directions.push(false);
        return [current_proof, current_directions];
    }
    else {
        const [current_proof, current_directions] = merkleProof(tree.right, val, index);
        current_proof.push(tree.left.data);
        current_directions.push(true);
        return [current_proof, current_directions];
    }
}

function editMerkleTree(tree, data, index, new_val) {
    if (tree.left === null && tree.right === null) {
        if (index === tree.l_index) {
            tree.data = new_val;
            data[index] = new_val;
        }
        return;
    }
    const m_index = Math.floor((tree.l_index + tree.r_index) / 2);
    if (index <= m_index) {
        editMerkleTree(tree.left, data, index, new_val);
    }
    else {
        editMerkleTree(tree.right, data, index, new_val);
    }
    tree.data = poseidon2([tree.left.data, tree.right.data]).toString();
}

function verifyMerkleProof(tree, val, proof, directions) {
    var hval = val;
    for (var i = 0; i < proof.length; i++) {
        if (directions[i]) {
            hval = poseidon2([proof[i], hval]).toString();
        }
        else {
            hval = poseidon2([hval, proof[i]]).toString();
        }
    }

    return hval === tree.data;
}

// Make functions available globally
window.hashArray = hashArray;
window.merkleTree = merkleTree;
window.merkleProof = merkleProof;
window.editMerkleTree = editMerkleTree;
window.verifyMerkleProof = verifyMerkleProof;