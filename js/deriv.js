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
    outputLength = 64,
    info = "🔑🗝️",
    algoForHKDF = sha3_512,
    algoForInfo = blake2b,
    encodingFunction = encodeBase91,
) {

    if (!input || typeof input === "boolean") {
        throw new Error(`Input to the "doHashing" function should not be falsy or boolean!`);
    }
    
    if (
        input instanceof Uint8Array
    ) {
        // do nothing
    } else if (
        typeof input === "string" && input.trim()
    ) {
        input = utf8ToBytes(input);
    } else if (
        (typeof input === "number" && input !== Infinity && input !== -Infinity && !(Number.isInteger(input) && !Number.isSafeInteger(input)))
        || typeof input === "bigint"
    ) {
        input = utf8ToBytes(String(input));
    } else if (
        typeof input === "object" 
    ) {
        input = utf8ToBytes(JSON.stringify(input, null, 0));
    } else {
        throw new Error(`Invalid input! Acceptable input types to the "doHashing" function: Uint8Array, string, number, big integer, object or array.`);
    }

    const hash1 = sha256(input); 
    const hash2 = sha512(input); 
    const hash3 = sha3_512(input); 
    const hash4 = blake2b(input); 
    const hash5 = blake2s(input); 
    const hash6 = blake3(input); 

    const passw = utf8ToBytes(`—${encodingFunction(hash1)}—${encodingFunction(hash2)}—${encodingFunction(hash3)}—${encodingFunction(hash4)}—${encodingFunction(hash5)}—${encodingFunction(hash6)}—${info}—`); 
    const salt = concatBytes(hash1, hash2, hash3, hash4, hash5, hash6); 

    const output = derivSingle(
        passw, 
        salt, 
        `"doHashing" — ${outputLength} — ${info}`, 
        outputLength,
        algoForHKDF,
        algoForInfo,
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

    const elements = [];
    for (let i = 1; i <= numberOfElements; i++) {

        passw = doHashing(`—${i}—${encodingFunction(passw)}—${numberOfElements}—${info}—`);
        salt = doHashing(`—${i}—${encodingFunction(salt)}—${numberOfElements}—${info}—`);

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
    
    let expandedKey = doHashing(`—${encodingFunction(passw)}—${expandedKeyLength}—${info}—`);

    for (let i = 1; i < Math.ceil(expandedKeyLength / 64); i++) {

        salt = doHashing(`—${i}—${encodingFunction(salt)}—${expandedKeyLength}—${info}—`);

        const tempConcat = concatBytes(expandedKey.slice(-32), expandedKey.slice(0, 32));
        const tempPassw = doHashing(`—${i}—${encodingFunction(tempConcat)}—${expandedKeyLength}—${info}—`);

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

