import { utf8ToBytes, bytesToHex } from "./noble-hashes/utils.mjs";
import { createSHA512, createSHA3, createBLAKE2b, createBLAKE3, createWhirlpool, argon2id } from "./hash-wasm/hash-wasm.mjs";

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

function isUint8Array(v) {
  return v instanceof Uint8Array;
}

function clean(...arrays) {
  for (const a of arrays) if (isUint8Array(a)) a.fill(0);
}

function concatBytes(...arrs) {
  let len = 0;
  for (const a of arrs) {
    if (!isUint8Array(a)) throw new Error("concatBytes expects Uint8Array arguments");
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

        HCs.whirlpool.update(concatBytes(utf8ToBytes(`${i}`), concatHashes));
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

function derivMult(
    passw,
    salt,
    numberOfElements,
    HCs,
    outputLength = 64,
) {

    const elements = [];
    for (let i = 1; !(i > numberOfElements); i++) {

        const prevSaltHex = bytesToHex(salt);

        HCs.blake2.update(utf8ToBytes(`${i} ${prevSaltHex} ${passw.length} ${numberOfElements} ${outputLength}`));
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
    const saltHex = bytesToHex(salt);

    HCs.whirlpool.update(utf8ToBytes(`${passwHex} ${saltHex} ${expandedKeyLength} ${pieceLength}`));
    const wpInit = HCs.whirlpool.digest("binary");
    HCs.whirlpool.init();

    HCs.sha3.update(utf8ToBytes(`${bytesToHex(wpInit)} ${passwHex} ${saltHex} ${expandedKeyLength} ${pieceLength}`));
    let expandedKey = HCs.sha3.digest("binary");
    HCs.sha3.init();

    const rounds = Math.ceil(expandedKeyLength / pieceLength) - 1;
    let itSalt = salt;
    for (let i = 1; !(i > rounds); i++) {

        const prevItSaltHex = bytesToHex(itSalt);

        HCs.blake2.update(utf8ToBytes(`${i} ${prevItSaltHex} ${saltHex} ${passw.length} ${expandedKeyLength} ${pieceLength}`));
        itSalt = HCs.blake2.digest("binary");
        HCs.blake2.init();

        const itConcat = concatBytes(expandedKey, passw);

        const newPiece = doHKDF(
            HCs.sha3,
            itConcat,
            itSalt,
            utf8ToBytes(`${i} ${prevItSaltHex}`),
            pieceLength,
        );

        const len = Math.min(expandedKey.length, newPiece.length);
        let order = 0;
        for (let j = 0; j < len; j++) {
            if (expandedKey[j] !== newPiece[j]) {
                order = expandedKey[j] - newPiece[j];
                break;
            }
        }
        if (order === 0) order = expandedKey.length - newPiece.length;
        expandedKey = order > 0 ? concatBytes(expandedKey, newPiece) : concatBytes(newPiece, expandedKey);
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

const userInputPIN = document.getElementById("userInputPIN");
const userInputPassw = document.getElementById("userInputPassw");
const userInputFatherBirthDate = document.getElementById("userInputFatherBirthDate");
const userInputMotherBirthDate = document.getElementById("userInputMotherBirthDate");
const userInputOwnBirthDate = document.getElementById("userInputOwnBirthDate");
const doButton = document.getElementById("doButton");
const resultMessage = document.getElementById("resultMessage");
const getButton = document.getElementById("getButton");

const HCs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    whirlpool: await createWhirlpool(),
};

const keyfileLength = 1000000;
let keyfileFinished = false;
let keyfileString = null;

function valPIN(input) {
    return /^\d{4,}$/.test(input);
}

function valPasswInput(input) {
    return valPassw(input, 20)
        && !input.includes(userInputPIN.value.trim());
}

function valBirthDate(input) {
    return /^\d{2}\/\d{2}\/\d{4}$/.test(input);
}

function valOwnBirthDate(input) {
    return /^\d{2}\/\d{2}\/\d{4}$/.test(input)
        && input !== userInputFatherBirthDate.value.trim()
        && input !== userInputMotherBirthDate.value.trim();
}

const validators = {
    userInputPIN: valPIN,
    userInputPassw: valPasswInput,
    userInputFatherBirthDate: valBirthDate,
    userInputMotherBirthDate: valBirthDate,
    userInputOwnBirthDate: valOwnBirthDate,
};

function valButton() {

    if (
        valPIN(userInputPIN.value.trim())
        && valPasswInput(userInputPassw.value.trim())
        && valBirthDate(userInputFatherBirthDate.value.trim())
        && valBirthDate(userInputMotherBirthDate.value.trim())
        && valOwnBirthDate(userInputOwnBirthDate.value.trim())
    ) {
        doButton.disabled = false;
        doButton.style.backgroundColor = "green";
    } else {
        doButton.disabled = true;
        doButton.style.backgroundColor = "";
    }

    if (
        keyfileFinished
    ) {
        getButton.disabled = false;
        getButton.style.backgroundColor = "green";
    } else {
        getButton.disabled = true;
        getButton.style.backgroundColor = "";
    }
}

Object.entries(validators).forEach(([id, fn]) => {

    const field = document.getElementById(id);

    field.addEventListener("input", () => {
        const isValid = fn(field.value.trim());
        field.style.borderColor = isValid ? "green" : "red";
    });

    field.addEventListener("input", valButton);
});

async function saveStringToFile(str, suggestedName = "download") {

    const blob = new Blob([str], { type: "application/octet-stream" });

    if (window.showSaveFilePicker) {

        const handle = await window.showSaveFilePicker({
            suggestedName,
            types: [
                {
                    description: "All Files",
                    accept: {},
                },
            ],
        });

        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();

    } else {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = suggestedName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }
}

doButton.addEventListener("click", async () => {

    const PIN = userInputPIN.value.trim();
    const passw = userInputPassw.value.trim();

    userInputPIN.value = "";
    userInputPIN.style.borderColor = "";
    userInputPassw.value = "";
    userInputPassw.style.borderColor = "";

    doButton.disabled = true;
    doButton.style.backgroundColor = "";

    resultMessage.textContent = `Building your keyfile...`;

    const timeBefore = performance.now();

    const keyfileBytes = await buildKeyfile(
        PIN,
        passw,
        userInputFatherBirthDate.value.trim(),
        userInputMotherBirthDate.value.trim(),
        userInputOwnBirthDate.value.trim(),
        keyfileLength,
        HCs,
    );

    const timeAfter = performance.now();
    const timeSpent = timeAfter - timeBefore;

    if (
        keyfileBytes instanceof Uint8Array
        && keyfileBytes.length === keyfileLength
    ) {
        resultMessage.textContent = `Time spent building the keyfile: ${formatTime(timeSpent)}`;
        keyfileString = encodeBase91(keyfileBytes);
        keyfileFinished = true;
        getButton.disabled = false;
        getButton.style.backgroundColor = "green";
    }
});

getButton.addEventListener("click", async () => {

    try {

        await saveStringToFile(keyfileString, "keyfile");
        console.log(`
    Keyfile successfully built and saved.
        `);

    } catch (err) {

        console.error(`
    Error in save flow!
    ${err.message}
        `);

        alert("Failed to save keyfile: " + (err && err.message ? err.message : err));
    }
});

valButton();
