'use strict';
const rustCurve = require('@skidy89/libsignal-plugins');

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function validatePubKey(pubKey) {
    if (pubKey === undefined || pubKey === null) {
        throw new Error("Invalid public key");
    }
    if (!(pubKey instanceof Uint8Array)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey.byteLength == 33) {
        if (pubKey[0] != 5) {
            throw new Error("Invalid public key");
        }
    } else if (pubKey.byteLength == 32) {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
    } else {
        throw new Error("Invalid public key");
    }
}

exports.getPublicFromPrivateKey = function(privKey) {
    if (!(privKey instanceof Uint8Array)) {
        throw new Error(`Invalid private key type: ${privKey === undefined ? 'undefined' : privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
    return rustCurve.keyPair(privKey).pubKey;
};

exports.generateKeyPair = function() {
    return rustCurve.generateKeyPair();
};

exports.createKeyPair = function(privKey) {
    validatePrivKey(privKey);
    return rustCurve.keyPair(privKey);
};

exports.calculateAgreement = function(pubKey, privKey) {
    validatePubKey(pubKey);
    validatePrivKey(privKey);
    return rustCurve.calculateAgreement(pubKey, privKey);
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return rustCurve.curve25519Sign(privKey, message);
};

exports.verifySignature = function(pubKey, msg, sig, isInit = false) {
    validatePubKey(pubKey);
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return rustCurve.verifySignature(pubKey, msg, sig, isInit);
};
