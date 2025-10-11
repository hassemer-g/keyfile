import { concatBytes, utf8ToBytes, hexToBytes, bytesToHex } from "./noble-hashes/utils.mjs";
import { createSHA512, createSHA3, createBLAKE2b, createBLAKE3, createWhirlpool } from "./hash-wasm/hash-wasm.mjs";
import { doArgon2id } from "./argon2id.js";
import { doHKDF } from "./hkdf.js";


export async function doHashing(
    input,
    rounds = 1,
    memCost = 1,
    iterations = 1,
    outputLength = 64,
) {

    const hashCs = {
        sha2: await createSHA512(),
        sha3: await createSHA3(),
        blake2b: await createBLAKE2b(),
        blake3: await createBLAKE3(),
        whirlpool: await createWhirlpool(),
    };

    hashCs.sha3.init();
    hashCs.sha3.update(concatBytes(utf8ToBytes(`${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`), input));
    const initialHash = hashCs.sha3.digest("binary");

    let output = doHKDF(
        concatBytes(initialHash, input),
        initialHash,
        utf8ToBytes(bytesToHex(initialHash)),
    );

    for (let i = 1; !(i > rounds); i++) {

        hashCs.sha3.init();
        hashCs.sha3.update(utf8ToBytes(`${i} ${bytesToHex(output)} ${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`));
        const iterationMark = hashCs.sha3.digest("binary");

        const markedInput = concatBytes(iterationMark, input);

        const hashArray = [];
        for (const [name, fn] of Object.entries(hashCs)) {
            fn.init();
            fn.update(markedInput);
            hashArray.push(fn.digest("binary"));
        }

        const concatHashes = concatBytes(...hashArray);

        hashCs.whirlpool.init();
        hashCs.whirlpool.update(concatHashes);
        const salt = hashCs.whirlpool.digest("binary");

        output = await doArgon2id(
            concatHashes,
            salt,
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

    const sha3 = await createSHA3();

    const elements = [];
    for (let i = 1; !(i > numberOfElements); i++) {

        const prevSaltHex = bytesToHex(salt);
        sha3.init();
        sha3.update(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${numberOfElements} ${outputLength}`));
        salt = sha3.digest("binary");

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

    const sha3 = await createSHA3();

    const rounds = Math.ceil(expandedKeyLength / pieceLength) - 1;
    for (let i = 1; !(i > rounds); i++) {

        const prevSaltHex = bytesToHex(salt);
        sha3.init();
        sha3.update(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${expandedKeyLength} ${pieceLength}`));
        salt = sha3.digest("binary");

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

