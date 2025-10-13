import { concatBytes, utf8ToBytes, hexToBytes, bytesToHex } from "./noble-hashes/utils.mjs";
import { blake512 } from "./noble-hashes/blake1.mjs";
import { hkdf } from "./noble-hashes/hkdf.mjs";
import { argon2id } from "./hash-wasm/hash-wasm.mjs";

function doHKDF(
    passw,
    salt,
    info,
    outputLength = 64,
) {

    const output = hkdf(
        blake512,
        passw,
        salt,
        info,
        outputLength,
    );

    return output;
}

async function doArgon2id(
    password,
    salt,
    secret,
    memCost,
    iterations = 1,
    outputLength = 64,
) {

    const output = await argon2id({
        password,
        salt,
        secret,
        iterations,
        parallelism: 1,
        memorySize: 1024 * memCost,
        hashLength: outputLength,
        outputType: "binary",
    });

    return output;
}

export async function doHashing(
    input,
    HCs,
    rounds = 1,
    memCost = 1,
    iterations = 1,
    outputLength = 64,
) {

    HCs.sha3.update(concatBytes(utf8ToBytes(`${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`), input));
    const initialHash = HCs.sha3.digest("binary");
    HCs.sha3.init();

    let output = doHKDF(
        concatBytes(initialHash, input),
        initialHash,
        utf8ToBytes(bytesToHex(initialHash)),
    );

    for (let i = 1; !(i > rounds); i++) {

        HCs.sha3.update(utf8ToBytes(`${i} ${bytesToHex(output)} ${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`));
        const iterationMark = HCs.sha3.digest("binary");
        HCs.sha3.init();

        const markedInput = concatBytes(iterationMark, input);

        const hashArray = [];
        for (const [name, fn] of Object.entries(HCs)) {
            fn.update(markedInput);
            hashArray.push(fn.digest("binary"));
            fn.init();
        }

        const concatHashes = concatBytes(...hashArray);

        HCs.whirlpool.update(concatHashes);
        const salt = HCs.whirlpool.digest("binary");
        HCs.whirlpool.init();

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

export function derivMult(
    passw,
    salt,
    numberOfElements,
    HCs,
    outputLength = 64,
) {

    const elements = [];
    for (let i = 1; !(i > numberOfElements); i++) {

        const prevSaltHex = bytesToHex(salt);

        HCs.sha3.update(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${numberOfElements} ${outputLength}`));
        salt = HCs.sha3.digest("binary");
        HCs.sha3.init();

        elements.push(doHKDF(
            concatBytes(salt, passw),
            salt,
            utf8ToBytes(`${i} ${prevSaltHex}`),
            outputLength,
        ));
    }

    return elements;
}

export function expandKey(
    passw,
    salt,
    expandedKeyLength,
    HCs,
    pieceLength = 64,
) {

    HCs.whirlpool.update(utf8ToBytes(`${bytesToHex(passw)} ${bytesToHex(salt)} ${expandedKeyLength} ${pieceLength}`));
    let expandedKey = HCs.whirlpool.digest("binary");
    HCs.whirlpool.init();

    const rounds = Math.ceil(expandedKeyLength / pieceLength) - 1;
    for (let i = 1; !(i > rounds); i++) {

        const prevSaltHex = bytesToHex(salt);

        HCs.sha3.update(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${expandedKeyLength} ${pieceLength}`));
        salt = HCs.sha3.digest("binary");
        HCs.sha3.init();

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
