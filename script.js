import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import readlineSync from "readline-sync";
import { createSHA512, createSHA3, createBLAKE2b, createBLAKE3, createWhirlpool, argon2id } from "hash-wasm";

function utf8ToBytes(str) {
    if (typeof str !== "string") throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
}

const hasHexBuiltin = (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("bytesToHex expects Uint8Array input");

    if (hasHexBuiltin) return bytes.toHex();

    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}

function concatBytes(...arrs) {
    let len = 0;
    for (const a of arrs) {
        if (!(a instanceof Uint8Array)) throw new Error("concatBytes expects Uint8Array arguments");
        len += a.length;
    }
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrs) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}

const customBase91CharSet = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~";

function encodeBase91(
    data,
) {

    if (!(data instanceof Uint8Array)) {
        throw new Error(`Input to the "encodeBase91" function should be a Uint8Array.`);
    }

    const len = data.length;
    let ret = "";

    let n = 0;
    let b = 0;

    for (let i = 0; i < len; i++) {
        b |= data[i] << n;
        n += 8;

        if (n > 13) {
            let v = b & 8191;

            if (v > 88) {
                b >>= 13;
                n -= 13;

            } else {
                v = b & 16383;
                b >>= 14;
                n -= 14;
            }

            ret += customBase91CharSet[v % 91] + customBase91CharSet[v / 91 | 0];
        }
    }

    if (n) {
        ret += customBase91CharSet[b % 91];

        if (n > 7 || b > 90) ret += customBase91CharSet[b / 91 | 0];
    }

    return ret;
}

function valPassw(
    input,
    minLength = 8,
) {

    if (minLength < 4) {
        throw new Error(`Incorrect parameters passed to the "valPassw" function.`);
    }

    if (typeof input !== "string") return false;

    if (input.length < minLength) return false;

    const hasDigit = /\d/;
    const hasLowerLetter = /[a-z]/;
    const hasUpperLetter = /[A-Z]/;

    const hasNonBasicChar = /[^0-9A-Za-z]/u;

    return hasDigit.test(input) && hasLowerLetter.test(input) && hasUpperLetter.test(input) && hasNonBasicChar.test(input);
}

function formatTime(
    t,
) {
    const hours = Math.floor(t / 3600000);
    const minutes = Math.floor((t % 3600000) / 60000);
    const seconds = Math.floor((t % 60000) / 1000);
    const milliseconds = Math.floor(t % 1000);

    const parts = [];

    if (hours > 0) parts.push(hours + " " + (hours === 1 ? "hour" : "hours"));
    if (minutes > 0) parts.push(minutes + " " + (minutes === 1 ? "minute" : "minutes"));
    if (seconds > 0) parts.push(seconds + " " + (seconds === 1 ? "second" : "seconds"));

    parts.push(milliseconds + " " + (milliseconds === 1 ? "millisecond" : "milliseconds"));

    return parts.length > 1
        ? parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1]
        : parts[0];
}

function clean(...arrays) {
    for (const a of arrays) if (a instanceof Uint8Array) a.fill(0);
}

function hmacSync(
    hasher,
    key,
    msg,
    blockLen,
    outputLen,
) {

    if (key.length > blockLen) {
        hasher.update(key);
        key = hasher.digest("binary");
        hasher.init();
    }

    const keyPadded = new Uint8Array(blockLen);
    keyPadded.set(key.length ? key : new Uint8Array(0));
    const ipad = new Uint8Array(blockLen);
    const opad = new Uint8Array(blockLen);
    for (let i = 0; i < blockLen; i++) {
        const b = keyPadded[i];
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }

    hasher.update(ipad);
    hasher.update(msg);
    const inner = hasher.digest("binary");
    hasher.init();

    hasher.update(opad);
    hasher.update(inner);
    const out = hasher.digest("binary");
    hasher.init();

    clean(keyPadded, ipad, opad, inner);
    return out;
}

function doHKDF(
    hasher,
    ikm,
    salt = undefined,
    info = new Uint8Array(0),
    length = 64,
) {

    const outputLen = hasher.digestSize;
    const blockLen = hasher.blockSize;
    if (salt === undefined) salt = new Uint8Array(outputLen);

    const prk = hmacSync(
        hasher,
        salt,
        ikm,
        blockLen,
        outputLen,
    );

    const blocks = Math.ceil(length / outputLen);
    const okmFull = new Uint8Array(blocks * outputLen);
    let prev = new Uint8Array(0);

    for (let i = 0; i < blocks; i++) {
        const counter = new Uint8Array([i + 1]);
        const msg = concatBytes(prev, info, counter);
        const T = hmacSync(
            hasher,
            prk,
            msg,
            blockLen,
            outputLen,
        );
        okmFull.set(T, i * outputLen);
        prev = T;
    }

    clean(prev, prk);
    return okmFull.slice(0, length);
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

async function doHashing(
    input,
    HCs,
    rounds = 1,
    memCost = 1,
    iterations = 1,
    outputLength = 64,
) {

    HCs.whirlpool.update(concatBytes(utf8ToBytes(`${input.length} ${rounds} ${memCost} ${iterations} ${outputLength}`), input));
    const initialHash = HCs.whirlpool.digest("binary");
    HCs.whirlpool.init();

    let output = doHKDF(
        HCs.sha3,
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

        HCs.whirlpool.update(concatBytes(output, concatHashes));
        const salt = HCs.whirlpool.digest("binary");
        HCs.whirlpool.init();

        output = await doArgon2id(
            concatBytes(concatHashes, input),
            salt,
            utf8ToBytes(`${i} ${bytesToHex(concatHashes)}`),
            memCost,
            iterations,
            i === rounds ? outputLength : 64,
        );
    }

    return output;
}

function derivMult(
    passw,
    salt,
    numberOfElements,
    HCs,
    outputLength = 64,
) {

    const origSaltHex = bytesToHex(salt); // string, hex

    const elements = [];
    for (let i = 1; !(i > numberOfElements); i++) {

        const prevSaltHex = bytesToHex(salt);

        HCs.blake2.update(utf8ToBytes(`${i} ${prevSaltHex} ${origSaltHex} ${passw.length} ${numberOfElements} ${outputLength}`));
        salt = HCs.blake2.digest("binary");
        HCs.blake2.init();

        elements.push(doHKDF(
            HCs.sha3,
            concatBytes(salt, passw),
            salt,
            utf8ToBytes(`${i} ${prevSaltHex}`),
            outputLength,
        ));
    }

    return elements;
}

function expandKey(
    passw,
    salt,
    expandedKeyLength,
    HCs,
    pieceLength = 64,
) {

    const passwHex = bytesToHex(passw);
    const origSaltHex = bytesToHex(salt);

    HCs.whirlpool.update(utf8ToBytes(`${passwHex} ${origSaltHex} ${expandedKeyLength} ${pieceLength}`));
    const wpInit = HCs.whirlpool.digest("binary");
    HCs.whirlpool.init();

    HCs.sha3.update(utf8ToBytes(`${bytesToHex(wpInit)} ${passwHex} ${origSaltHex} ${expandedKeyLength} ${pieceLength}`));
    let expandedKey = HCs.sha3.digest("binary");
    HCs.sha3.init();

    const rounds = Math.ceil(expandedKeyLength / pieceLength) - 1;
    for (let i = 1; !(i > rounds); i++) {

        const prevSalt = salt;
        const prevSaltHex = bytesToHex(prevSalt);

        HCs.blake2.update(concatBytes(utf8ToBytes(`${i} ${prevSaltHex} ${origSaltHex} ${passw.length} ${expandedKeyLength} ${pieceLength}`), expandedKey));
        salt = HCs.blake2.digest("binary");
        HCs.blake2.init();

        const newPiece = doHKDF(
            HCs.sha3,
            concatBytes(salt, passw),
            salt,
            utf8ToBytes(`${i} ${prevSaltHex}`),
            pieceLength,
        );

        const orderLength = Math.min(salt.length, prevSalt.length);
        let order = 0;
        for (let j = 0; j < orderLength; j++) {
            if (salt[j] !== prevSalt[j]) {
                order = salt[j] - prevSalt[j];
                break;
            }
        }
        expandedKey = order < 0 ? concatBytes(newPiece, expandedKey) : concatBytes(expandedKey, newPiece);
    }

    return expandedKey;
}

async function buildKeyfile(
    userPIN,
    userPassw,
    fatherBirthDate,
    motherBirthDate,
    ownBirthDate,
    keyfileLength,
    HCs,
) {

    const salt = await doHashing(
        utf8ToBytes(`${ownBirthDate} ${fatherBirthDate} ${motherBirthDate} ${userPIN} ${userPassw} ${keyfileLength}`),
        HCs,
    );

    const prePassw = await doHashing(
        utf8ToBytes(`${userPIN} ${userPassw} ${ownBirthDate} ${fatherBirthDate} ${motherBirthDate} ${keyfileLength} ${bytesToHex(salt)}`),
        HCs,
    );

    const elements = derivMult(
        prePassw,
        salt,
        3,
        HCs,
    );

    const passw = await doHashing(
        elements[1],
        HCs,
        1000,
        1024,
    );

    const keyfile = expandKey(
        concatBytes(passw, elements[2]),
        elements[0],
        keyfileLength,
        HCs,
    );

    return keyfile;
}

function promptUserInputReadline(
    promptMessage,
    validationFunction,
    hide = false,
    maskType = null,
    repeatInput = 0,
    mustBeDifferentTo = null,
) {

    const options = { hideEchoBack: hide };

    if (maskType !== null) {
        options.mask = maskType;
    }

    do {
        const input = readlineSync.question(promptMessage, options).trim();

        if (!validationFunction(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        if (Array.isArray(mustBeDifferentTo) && mustBeDifferentTo.includes(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        const needsConfirmation = (
            repeatInput === 2
            || (repeatInput === 1 && input !== "")
        );

        if (needsConfirmation) {

            const confirmInput = readlineSync.question(`Confirm (enter again): `, options).trim();

            if (input !== confirmInput) {
                console.error(`Error: Inputs do not match. Try again.`);
                continue;
            }
        }

        return input;

    } while (true);
}

const userPIN = promptUserInputReadline(
    `Enter and confirm your PIN (digits only, minimum length 4): `,
    (input) => /^\d{4,}$/.test(input),
    true,
    "",
    2,
);

const userPassw = promptUserInputReadline(
    `Enter and confirm your password (minimum 20 characters; must include a lowercase letter, an uppercase letter, a digit and a symbol; must not contain the PIN): `,
    (input) => valPassw(input, 20)
        && !input.includes(userPIN),
    true,
    "",
    2,
);

const fatherBirthDate = promptUserInputReadline(
    `Enter your father's birth date (format: DD/MM/YYYY): `,
    (input) => /^\d{2}\/\d{2}\/\d{4}$/.test(input),
);

const motherBirthDate = promptUserInputReadline(
    `Enter your mother's birth date (format: DD/MM/YYYY): `,
    (input) => /^\d{2}\/\d{2}\/\d{4}$/.test(input),
);

const ownBirthDate = promptUserInputReadline(
    `Enter your own birth date (format: DD/MM/YYYY): `,
    (input) => /^\d{2}\/\d{2}\/\d{4}$/.test(input)
        && input !== fatherBirthDate
        && input !== motherBirthDate,
);

const HCs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    whirlpool: await createWhirlpool(),
};

const keyfileLength = 1000000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

try {

    const keyfile = encodeBase91(await buildKeyfile(
        userPIN,
        userPassw,
        fatherBirthDate,
        motherBirthDate,
        ownBirthDate,
        keyfileLength,
        HCs,
    ));

    const keyfileName = "keyfile";
    fs.writeFileSync(path.join(__dirname, keyfileName), keyfile, "utf8");

    console.log(`
    ${keyfileLength} byte long keyfile successfully built and saved to a file named "${keyfileName}" (without extension).

    I recommend you change the file name to make it more discreet.

    Take good care and make good use of your keyfile!
    `);

} catch (err) {
    console.error(`
    Failed to build your keyfile.
    Error: ${err.message}
    `);
}
