pragma circom 2.1.6;

include "bigint_modules/bigint.circom";

// multiplies an array of r numbers modulo m
template MultiplyArrayModM(n, k, r) {
    signal input a[r][k];
    signal input m[k];
    signal accum[r][k];
    signal output out[k];

    accum[0] <== a[0];
    for (var i = 1; i < r; i++) {
        accum[i] <== BigMultModP(n, k)(a <== accum[i-1], b <== a[i], p <== m);
    }

    out <== accum[r-1];
}

// computes a ** d modulo m
template ExponentiateModM(n, k, d) {
    // compute d in binary
    var l = 0;
    var temp = d;
    while (temp > 0) {
        l += 1;
        temp = (temp - temp % 2) / 2;
    }
    var dBinary[l];
    for (var i = 0; i < l; i++) {
        dBinary[i] = (d & (1 << i)) >> i;
    }

    var totalOnes = 0;
    for (var i = 0; i < l; i++) {
        totalOnes += dBinary[i];
    }
    
    signal input a[k];
    signal input m[k];
    signal powersOfA[l][k];
    signal relaventPowersOfA[totalOnes][k];
    signal output out[k];

    // check that a < m
    component aLessThanM = BigLessThan(n, k);
    aLessThanM.a <== a;
    aLessThanM.b <== m;
    aLessThanM.out === 1;
    
    // compute a ** (2 ** i) for all i < l
    powersOfA[0] <== a;
    for (var i = 1; i < l; i++) {
        powersOfA[i] <== BigMultModP(n, k)(a <== powersOfA[i-1], b <== powersOfA[i-1], p <== m);
    }

    // put all a ** (2 ** i) corresponding to nonzero bits in d into a single array
    var j = 0;
    for (var i = 0; i < l; i++) {
        if (dBinary[i] == 1) {
            relaventPowersOfA[j] <== powersOfA[i];
            j += 1;
        }
    }

    component multArray = MultiplyArrayModM(n, k, totalOnes);
    multArray.a <== relaventPowersOfA;
    multArray.m <== m;
    out <== multArray.out;
}

// proves that user knows an RSA signature for a message, given l public keys (i.e. values of n)
template GroupSignature(n, k, l) {
    var d = 65537;
    signal input message[k];
    signal input keys[l][k];
    signal input signature[k];
    signal input correctKey[k];
    signal equal[l]; // helper to check if correctKey is in the list of keys
    signal accum[l]; // helper to check if correctKey is in the list of keys
    signal keyValid;
    signal power[k];
    signal keyWorks;
    
    // checks that correctKey is in the list of keys
    for (var i = 0; i < l; i++) {
        equal[i] <== BigIsEqual(k)([keys[i], correctKey]);
    }
    accum[0] <== 1 - equal[0];
    for (var i = 1; i < l; i++) {
        accum[i] <== accum[i-1] * (1-equal[i]);
    }
    keyValid <== 1-accum[l-1];
    keyValid === 1;
    
    // checks that correctKey is compatible with the signature and message
    power <== ExponentiateModM(n, k, d)(a <== signature, m <== correctKey);
    keyWorks <== BigIsEqual(k)([power, message]);
    keyWorks === 1;
}


component main {public [message, keys, signature, correctKey]} = GroupSignature(120, 35, 100);