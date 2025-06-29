pragma circom 2.1.6;

include "bigint_modules/bigint.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/mux1.circom";
include "rsa_circuit.circom";
include "circom-ecdsa/circuits/ecdsa.circom";

// proves that user knows an RSA signature for a message, given l public keys (i.e. values of n)
template GroupSignature(n_rsa, k_rsa, proofSize, n_ed25519, k_ed25519) {
    signal input message[k_rsa];
    signal input signature[k_rsa];
    signal input correctKey[k_rsa];

    signal input pubKeyMerkleRoot;
    signal input pubKeyTreeProofs[proofSize];
    signal input pubKeyTreeDirections[proofSize];

    signal input msghashMerkleRoot;
    signal input msghashTreeProofs[proofSize];
    signal input msghashTreeDirections[proofSize];


    signal input s[k_ed25519];
    signal input R[2][k_ed25519];
    signal input m[k_ed25519];
    signal input A[2][k_ed25519];

    signal rsaValid;
    signal ed25519Works;
    signal ed25519Valid;
    signal pubKeyVal;
    signal msghashVal;
    signal pubKeyInGroup;
    signal msghashInGroup;
    component pubKeyValComp = PoseidonArray(k_rsa + 2 * k_ed25519);
    for (var i = 0; i < k_rsa; i++) {
        pubKeyValComp.in[i] <== correctKey[i];
    }
    for (var i = 0; i < k_ed25519; i++) {
        pubKeyValComp.in[k_rsa + i] <== A[0][i];
    } 
    for (var i = 0; i < k_ed25519; i++) {
        pubKeyValComp.in[k_rsa + k_ed25519 + i] <== A[1][i];
    }

    // check merkle proof
    pubKeyVal <== pubKeyValComp.out;
    pubKeyInGroup <== VerifyMerkleProof(proofSize)(proof <== pubKeyTreeProofs, directions <== pubKeyTreeDirections, root <== pubKeyMerkleRoot, val <== pubKeyVal); 
    pubKeyInGroup === 1;
    //check rsa
    rsaValid <== RSAGroupSignature(n_rsa, k_rsa)(message <== message, signature <== signature, correctKey <== correctKey);
    
    // check ed22519
    ed25519Works <== ed25519SSHVerifyNoPubkeyCheck(n_ed25519, k_ed25519)(s <== s, R <== R, m <== m, A <== A);
    msghashVal <== PoseidonArray(k_ed25519)(in <== m);
    msghashInGroup <== VerifyMerkleProof(proofSize)(proof <== msghashTreeProofs, directions <== msghashTreeDirections, root <== msghashMerkleRoot, val <== msghashVal); 
    ed25519Valid <== ed25519Works * msghashInGroup;
    // take the or of the two validities
    (1 - rsaValid) * (1 - ed25519Valid) === 0; 
}


template justEd25519(proofSize, n_ed25519, k_ed25519) {
    signal input s[k_ed25519];
    signal input R[2][k_ed25519];
    signal input m[k_ed25519];
    signal input A[2][k_ed25519];

    signal ed25519Works;
    signal ed25519Valid;
   // check ed22519
    ed25519Works <== ed25519SSHVerifyNoPubkeyCheck(n_ed25519, k_ed25519)(s <== s, R <== R, m <== m, A <== A);
    // take the or of the two validities
    (1 - ed25519Works) === 0; 
}
// should R be public?
component main {public [message, pubKeyMerkleRoot, msghashMerkleRoot, R]} = GroupSignature(120, 35, 3, 64, 4);
//component main {public [msghashMerkleRoot, R]} = justEd25519(3, 64, 4);