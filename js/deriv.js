import { sha256, sha512 } from "./noble-hashes/sha2.js";
import { sha3_512 } from "./noble-hashes/sha3.js";
import { blake2b, blake2s } from "./noble-hashes/blake2.js";
import { blake3 } from "./noble-hashes/blake3.js";
import { hkdf } from "./noble-hashes/hkdf.js";
import { utf8ToBytes, concatBytes } from "./noble-hashes/utils.js";
import { encodeBase91 } from "./base91.js";


export function derivSingle(
    passw, 
    salt, 
    info = "", 
    outputLength = 64,
    algoForHKDF = sha3_512,
    algoForInfo = blake2b,
) {

    if (
        arguments.length < 2
        || arguments.length > 6
        || !(passw instanceof Uint8Array)
        || !(salt instanceof Uint8Array)
        || typeof info !== "string"
        || !Number.isSafeInteger(outputLength)
        || outputLength < 1
        || outputLength > 64
        || typeof algoForHKDF !== "function"
        || typeof algoForInfo !== "function"
    ) {
        throw new Error(`Incorrect arguments passed to the "derivSingle" function.`);
    }

    const output = hkdf(
        algoForHKDF,
        passw,
        salt,
        algoForInfo(`"derivSingle" — ${outputLength} — ${info}`),
        outputLength,
    );

    return output; 
}


export function doHashing(
    input, 
    info = "", 
    outputLength = 64,
) {
    
    if (
        arguments.length < 1
        || arguments.length > 3
        || typeof info !== "string"
        || !Number.isSafeInteger(outputLength)
        || outputLength < 1
        || outputLength > 64
    ) {
        throw new Error(`Incorrect arguments passed to the "doHashing" function.`);
    }
    
    if (input instanceof Uint8Array) {
        // do nothing
    } else if (typeof input === "string" && input.trim()) {
        input = utf8ToBytes(input);
    } else if (Number.isSafeInteger(input) || typeof input === "bigint") {
        input = utf8ToBytes(String(input));
    } else if (input && typeof input === "object") { 
        input = utf8ToBytes(JSON.stringify(input, null, 0));
    } else {
        throw new Error(`Invalid input! Acceptable input types to the "doHashing" function: Uint8Array, non-empty string, integer, big integer, object or array.`);
    }

    const hash1 = sha256(input);
    const hash2 = sha512(input);
    const hash3 = sha3_512(input);
    const hash4 = blake2b(input);
    const hash5 = blake2s(input);
    const hash6 = blake3(input);

    const passw = concatBytes(hash1, hash2, hash3, hash4, hash5, hash6);
    const salt = concatBytes(hash2, hash3, hash4, hash5, hash6, hash1);

    const output = derivSingle(
        passw,
        salt,
        `"doHashing" — ${outputLength} — ${info}`, 
        outputLength,
    );

    return output; 
}


export function derivMult(
    passw, 
    salt, 
    numberOfElements, 
    info = "", 
    outputLength = 64,
    algoForHKDF = sha3_512,
    algoForInfo = blake2b,
    encodingFunction = encodeBase91,
) {

    if (
        arguments.length < 3
        || arguments.length > 8
        || !(passw instanceof Uint8Array)
        || !(salt instanceof Uint8Array)
        || typeof info !== "string"
        || !Number.isSafeInteger(numberOfElements)
        || numberOfElements < 1
        || !Number.isSafeInteger(outputLength)
        || outputLength < 1
        || outputLength > 64
        || typeof algoForHKDF !== "function"
        || typeof algoForInfo !== "function"
        || typeof encodingFunction !== "function"
    ) {
        throw new Error(`Incorrect arguments passed to the "derivMult" function.`);
    }

    const elements = [];
    for (let i = 1; i <= numberOfElements; i++) {

        passw = doHashing(`—${i}—${encodingFunction(passw)}—`);
        salt = doHashing(`—${i}—${encodingFunction(salt)}—`);

        elements.push(derivSingle(
            passw,
            salt,
            `"derivMult" — ${i} — ${numberOfElements} — ${outputLength} — ${info}`,
            outputLength,
            algoForHKDF,
            algoForInfo,
        ));
    }

    return elements; 
}


export function expandKey(
    passw, 
    salt, 
    expandedKeyLength, 
    info = "", 
    algoForHKDF = sha3_512,
    algoForInfo = blake2b,
    encodingFunction = encodeBase91,
) {
    
    if (
        arguments.length < 3
        || arguments.length > 7
        || !(passw instanceof Uint8Array)
        || !(salt instanceof Uint8Array)
        || typeof info !== "string"
        || !Number.isSafeInteger(expandedKeyLength)
        || expandedKeyLength < 1
        || typeof algoForHKDF !== "function"
        || typeof algoForInfo !== "function"
        || typeof encodingFunction !== "function"
    ) {
        throw new Error(`Incorrect arguments passed to the "expandKey" function.`);
    }

    let expandedKey = doHashing(`—${expandedKeyLength}—${encodingFunction(passw)}—`);

    for (let i = 1; i < Math.ceil(expandedKeyLength / 64); i++) {

        salt = doHashing(`—${i}—${encodingFunction(salt)}—`);

        const tempPassw = doHashing(`—${i}—${encodingFunction(concatBytes(expandedKey.slice(-32), expandedKey.slice(0, 32)))}—`);

        const newPiece = derivSingle(
            tempPassw,
            salt,
            `"expandKey" — ${i} — ${expandedKeyLength} — ${info}`,
            64,
            algoForHKDF,
            algoForInfo,
        );

        expandedKey = i % 2 === 0 ? concatBytes(newPiece, expandedKey) : concatBytes(expandedKey, newPiece);
    }
    
    for (let i = 1; expandedKey.length > expandedKeyLength; i++) {
        expandedKey = i % 2 === 0 ? expandedKey.slice(0, expandedKey.length - 1) : expandedKey.slice(1);
    }
    
    if (!(expandedKey instanceof Uint8Array) || expandedKey.length !== expandedKeyLength) {
        throw new Error(`Function "expandKey" failed.`);
    }

    return expandedKey; 
}
