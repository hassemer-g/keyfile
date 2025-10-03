import { concatBytes, utf8ToBytes, hexToBytes, bytesToHex } from "./noble-hashes/utils.mjs";
import { sha512, sha3, blake2b, blake3, whirlpool } from "./hash-wasm/hash-wasm.mjs";
import { doArgon2id } from "./argon2id.js";
import { doHKDF } from "./hkdf.js";


export async function doHashing(
    input,
    rounds = 1,
    memCost = 1,
    iterations = 1,
    outputLength = 64,
) {

    // Initial treatment
    const initialHash = hexToBytes(await sha3(concatBytes(utf8ToBytes(`${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`), input)));
    let output = doHKDF(
        concatBytes(initialHash, input),
        initialHash,
        utf8ToBytes(bytesToHex(initialHash)),
    );

    const hashFunctions = {
        sha512,
        sha3,
        blake2b,
        blake3,
        whirlpool,
    };

    for (let i = 1; !(i > rounds); i++) {

        const iterationMark = hexToBytes(await sha3(utf8ToBytes(`${i} ${bytesToHex(output)} ${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`)));
        const markedInput = concatBytes(iterationMark, input); 

        const hashArray = [];
        for (const [name, fn] of Object.entries(hashFunctions)) {
            hashArray.push(hexToBytes(await fn(markedInput)));
        }

        const concatHashes = concatBytes(...hashArray); 

        output = await doArgon2id(
            concatHashes,
            hexToBytes(await whirlpool(concatHashes)),
            utf8ToBytes(`${i} ${bytesToHex(concatHashes)}`),
            memCost,
            iterations,
            i === rounds ? outputLength : 64,
        );
    }

    return output;
}


export async function derivMult(
    passw,
    salt,
    numberOfElements,
    outputLength = 64,
) {

    const elements = [];
    for (let i = 1; !(i > numberOfElements); i++) {

        
        const prevSaltHex = bytesToHex(salt); 
        salt = hexToBytes(await sha3(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${numberOfElements} ${outputLength}`)));

        elements.push(doHKDF(
            concatBytes(salt, passw),
            salt,
            utf8ToBytes(`${i} ${prevSaltHex}`),
            outputLength,
        ));
    }

    return elements; 
}


export async function expandKey(
    passw,
    salt,
    expandedKeyLength,
    pieceLength = 64,
) {

    let expandedKey = await doHashing(utf8ToBytes(`${bytesToHex(passw)} ${bytesToHex(salt)} ${expandedKeyLength} ${pieceLength}`)); 

    const rounds = Math.ceil(expandedKeyLength / pieceLength) - 1;
    for (let i = 1; !(i > rounds); i++) {

        const prevSaltHex = bytesToHex(salt); 
        salt = hexToBytes(await sha3(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${expandedKeyLength} ${pieceLength}`)));

        const tempConcat = concatBytes(expandedKey.slice(-32), expandedKey.slice(0, 32), passw); 

        const newPiece = doHKDF(
            tempConcat, 
            salt, 
            utf8ToBytes(`${i} ${prevSaltHex}`), 
            pieceLength, 
            
        );

        expandedKey = i % 2 === 0 ? concatBytes(newPiece, expandedKey) : i % 2 === 1 ? concatBytes(expandedKey, newPiece) : null;
    }

    return expandedKey; 
}


