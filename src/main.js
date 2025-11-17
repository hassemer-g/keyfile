import { createSHA512, createSHA3, createWhirlpool, createBLAKE2b, createBLAKE3, argon2id } from "./hash-wasm/hash-wasm.mjs";

function concatBytes(...arrays) {
    if (arrays.length === 0) return new Uint8Array(0);

    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        if (!(a instanceof Uint8Array)) throw new TypeError(`concatBytes: argument ${i} is not a Uint8Array`);
        totalLength += a.length;
    }

    const result = new Uint8Array(totalLength);
    for (let i = 0, offset = 0; i < arrays.length; i++) {
        const a = arrays[i];
        result.set(a, offset);
        offset += a.length;
    }

    return result;
}

function compareUint8arrays(a, b) {
    const lenA = a.length;
    const lenB = b.length;
    const minLen = lenA < lenB ? lenA : lenB;

    for (let i = 0; i < minLen; i++) {
        const diff = a[i] - b[i];
        if (diff !== 0) return diff;
    }

    return lenA - lenB;
}

function utf8ToBytes(str) {
    if (typeof str !== "string") throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str));
}

function integerToBytes(input) {
    if (typeof input !== "bigint" && typeof input !== "number") {
        throw new Error(`Input to "integerToBytes" must be a number or big integer!`);
    }
    if (typeof input === "number") {
        if (!Number.isSafeInteger(input) || input < 0) {
            throw new Error(`Number input to "integerToBytes" must be a non-negative safe integer!`);
        }
        input = BigInt(input);
    }
    if (input < 0n) {
        throw new Error(`Function "integerToBytes" does not support negative values!`);
    }

    const bytes = [];
    while (input > 0n) {
        bytes.unshift(Number(input & 0xffn));
        input >>= 8n;
    }

    return new Uint8Array(bytes.length ? bytes : [0]);
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

function hmac(
    h,
    msg,
    key,
    blockLen,
) {

    if (key.length > blockLen) {
        h.update(key);
        key = h.digest("binary");
        h.init();
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

    h.update(ipad);
    h.update(msg);
    const inner = h.digest("binary");
    h.init();

    h.update(opad);
    h.update(inner);
    const out = h.digest("binary");
    h.init();

    return out;
}
function doHKDF(
    h,
    ikm,
    info = new Uint8Array(0),
    salt = undefined,
    length = undefined,
) {

    const blockLen = h.blockSize;
    const outputLen = h.digestSize;

    if (length === undefined)
        length = outputLen;

    if (salt === undefined)
        salt = new Uint8Array(blockLen);

    const prk = hmac(
        h,
        ikm,
        salt,
        blockLen,
    );

    const blocks = Math.ceil(length / outputLen);
    const okm = new Uint8Array(blocks * outputLen);

    let prev = new Uint8Array(0);
    let havePrev = false;
    const counter = new Uint8Array(1);

    let prkKey = prk;
    if (prkKey.length > blockLen) {
        h.update(prkKey);
        prkKey = h.digest("binary");
        h.init();
    }

    const keyPadded = new Uint8Array(blockLen);
    keyPadded.set(prkKey);
    const ipad = new Uint8Array(blockLen);
    const opad = new Uint8Array(blockLen);
    for (let i = 0; i < blockLen; i++) {
        const b = keyPadded[i];
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }

    h.update(ipad);
    const innerBaseState = h.save();
    h.init();

    h.update(opad);
    const outerBaseState = h.save();
    h.init();

    for (let i = 0; i < blocks; i++) {
        counter[0] = i + 1;

        h.load(innerBaseState);
        if (havePrev) h.update(prev);
        if (info.length) h.update(info);
        h.update(counter);
        const inner = h.digest("binary");
        h.init();

        h.load(outerBaseState);
        h.update(inner);
        prev = h.digest("binary");
        if (!havePrev) havePrev = true;
        h.init();

        okm.set(prev, i * outputLen);
    }

    return okm.slice(0, length);
}

async function doArgon2id(
    password,
    salt,
    secret,
    memCost,
    iterations = 1,
    outputLength = 64,
) {

    return argon2id({
        password,
        salt,
        secret,
        iterations,
        parallelism: 1,
        memorySize: 1024 * memCost,
        hashLength: outputLength,
        outputType: "binary",
    });
}

function doHashing(
    input,
    Hs,
    outputOutline = [64],
    rounds = 5,
) {

    let hashMat, salt, passwPt1, passwPt2, passwPt3;
    for (let i = 1; !(i > rounds); i++) {

        const itInput = concatBytes(i === 1 ? (integerToBytes(i), utf8ToBytes(`${input.length} ${rounds} ${JSON.stringify(outputOutline, null, 0)}`), input) : (integerToBytes(i), hashMat));

        const hashArray = [];
        for (const [j, [, fn]] of Object.entries(Hs).entries()) {
            fn.update(concatBytes(integerToBytes(j), itInput));
            hashArray.push(fn.digest("binary"));
            fn.init();
        }

        const order1 = compareUint8arrays(hashArray[1], hashArray[2]);
        const order2 = compareUint8arrays(hashArray[0], hashArray[3]);

        hashMat = (order1 < 0 && order2 > 0) ? concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays))) : (order1 > 0 && order2 < 0) ? concatBytes(...(hashArray.sort(compareUint8arrays))).reverse() : (order1 < 0 && order2 < 0) ? concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays))).reverse() : concatBytes(...(hashArray.sort(compareUint8arrays)));

        if (i === rounds - 3) { salt = hashMat.slice(100, 172); }
        else if (i === rounds - 2) { passwPt1 = hashMat; }
        else if (i === rounds - 1) { passwPt2 = hashMat; }
        else if (i === rounds) { passwPt3 = hashMat; }
    }

    const passw = concatBytes(passwPt3, passwPt2, passwPt1);

    const outputs = [];
    let i = 1;
    for (const elementLength of outputOutline) {

        const iBytes = integerToBytes(i);

        outputs.push(doHKDF(
            Hs.sha3,
            concatBytes(iBytes, integerToBytes(elementLength), passw),
            iBytes,
            salt,
            elementLength,
        ));

        i++;
    }

    if (outputs.length === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}

function expandKey(
    input,
    expandedKeyLength,
    Hs,
    doHashingRounds = 5,
    pieceLength = 64,
) {

    let expandedKey, hashedPrevNewPiece;
    const rounds = Math.ceil(expandedKeyLength / pieceLength);
    for (let i = 1; !(i > rounds); i++) {

        const iBytes = integerToBytes(i);

        if (i === 1) {

            const newPiece = doHashing(
                concatBytes(iBytes, utf8ToBytes(`${input.length} ${expandedKeyLength} ${rounds} ${doHashingRounds} ${pieceLength}`), input),
                Hs,
                [pieceLength],
                doHashingRounds,
            );

            expandedKey = newPiece;

            Hs.sha3.update(concatBytes(iBytes, newPiece, input).reverse());
            hashedPrevNewPiece = Hs.sha3.digest("binary");
            Hs.sha3.init();

        } else {

            const currLength = expandedKey.length;
            const midpoint = Math.floor(currLength / 2);

            const newPiece = doHashing(
                i < 5 ? concatBytes(iBytes, integerToBytes(currLength), expandedKey, hashedPrevNewPiece, input).reverse() : concatBytes(iBytes, integerToBytes(currLength), expandedKey.subarray(-pieceLength), expandedKey.subarray(0, pieceLength), expandedKey.subarray(midpoint, midpoint + pieceLength), expandedKey.subarray(midpoint - pieceLength, midpoint), hashedPrevNewPiece),
                Hs,
                [pieceLength],
                doHashingRounds,
            );

            if (i % 3 === 1) {
                Hs.sha3.update(concatBytes(iBytes, newPiece.subarray(0, 1), hashedPrevNewPiece));
                hashedPrevNewPiece = Hs.sha3.digest("binary");
                Hs.sha3.init();
            } else if (i % 3 === 2) {
                Hs.whirlpool.update(concatBytes(iBytes, newPiece.subarray(0, 1), hashedPrevNewPiece));
                hashedPrevNewPiece = Hs.whirlpool.digest("binary");
                Hs.whirlpool.init();
            } else {
                Hs.sha2.update(concatBytes(iBytes, newPiece.subarray(0, 1), hashedPrevNewPiece));
                hashedPrevNewPiece = Hs.sha2.digest("binary");
                Hs.sha2.init();
            }

            const order1 = compareUint8arrays(hashedPrevNewPiece.subarray(0, 32), hashedPrevNewPiece.subarray(32));
            const order2 = compareUint8arrays(hashedPrevNewPiece.subarray(0, 32).reverse(), hashedPrevNewPiece.subarray(32).reverse());

            expandedKey = concatBytes((order1 < 0 && order2 > 0) ? (newPiece, expandedKey) : (order1 > 0 && order2 < 0) ? (expandedKey, newPiece) : (order1 < 0 && order2 < 0) ? (expandedKey.subarray(midpoint), newPiece, expandedKey.subarray(0, midpoint)) : (expandedKey.subarray(0, midpoint), newPiece, expandedKey.subarray(midpoint)));
        }
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
    Hs,
    iterations = 3000,
    pieceLength = 64,
    memCost = 1024,
    hashingRounds = 100000,
    hashingRoundsForExpansion = 10,
) {

    const precursors = doHashing(
        utf8ToBytes(`ჰK0 ${ownBirthDate} ${fatherBirthDate} ${motherBirthDate} ${userPIN} ${userPassw} ${keyfileLength} ${pieceLength} ${iterations} ${memCost} ${hashingRounds} ${hashingRoundsForExpansion}`),
        Hs,
        [256, 256, 256, 448],
        hashingRounds,
    );

    const argon2Output = await doArgon2id(
        precursors[2],
        precursors[0],
        precursors[1],
        memCost,
        iterations,
    );

    return expandKey(
        concatBytes(argon2Output, precursors[3]),
        keyfileLength,
        Hs,
        hashingRoundsForExpansion,
        pieceLength,
    );
}

const userInputFatherBirthDate = document.getElementById("userInputFatherBirthDate");
const userInputMotherBirthDate = document.getElementById("userInputMotherBirthDate");
const userInputOwnBirthDate = document.getElementById("userInputOwnBirthDate");
const userInputPIN = document.getElementById("userInputPIN");
const userInputPassw = document.getElementById("userInputPassw");
const doButton = document.getElementById("doButton");
const resultMessage = document.getElementById("resultMessage");
const getButton = document.getElementById("getButton");

const Hs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    whirlpool: await createWhirlpool(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),

};

const keyfileLength = 1000000;

let keyfileString = null;

function valBirthDate(input) {
    return /^\d{2}\/\d{2}\/\d{4}$/.test(input)
        && input.slice(0, 2) !== "00"
        && input.slice(3, 5) !== "00"
        && input.slice(6, 10) !== "0000";
}

function valOtherBirthDate(input) {
    return input === "00/00/0000" || valBirthDate(input);
}

function valOwnBirthDate(input) {
    const fDate = userInputFatherBirthDate.value.trim();
    const mDate = userInputMotherBirthDate.value.trim();
    return valBirthDate(input)
        && valOtherBirthDate(fDate)
        && valOtherBirthDate(mDate)
        && Number(input.slice(6, 10)) > Number(fDate.slice(6, 10))
        && Number(input.slice(6, 10)) > Number(mDate.slice(6, 10));
}

function valPIN(input) {
    const date = userInputOwnBirthDate.value.trim();
    return /^\d{4,}$/.test(input)
        && valOwnBirthDate(date)
        && !input.includes(date.slice(6, 10))
        && !input.includes(date.slice(0, 2) + date.slice(3, 5));
}

function valPasswInput(input) {
    const pin = userInputPIN.value.trim();
    return valPassw(input, 20)
        && valPIN(pin)
        && !input.includes(pin);
}

function valButton() {

    if (
        valOtherBirthDate(userInputFatherBirthDate.value.trim())
        && valOtherBirthDate(userInputMotherBirthDate.value.trim())
        && valOwnBirthDate(userInputOwnBirthDate.value.trim())
        && valPIN(userInputPIN.value.trim())
        && valPasswInput(userInputPassw.value.trim())
    ) {
        doButton.disabled = false;
        doButton.style.backgroundColor = "green";
    } else {
        doButton.disabled = true;
        doButton.style.backgroundColor = "";
    }

}

userInputFatherBirthDate.addEventListener("input", () => {
    const fDate = userInputFatherBirthDate.value.trim();
    userInputFatherBirthDate.style.borderColor =
        !fDate ? ""
        : valOtherBirthDate(fDate) ? "green"
        : "red";
    const ownD = userInputOwnBirthDate.value.trim();
    userInputOwnBirthDate.style.borderColor =
        (!ownD || !valOtherBirthDate(fDate) || !valOtherBirthDate(userInputMotherBirthDate.value.trim())) ? ""
        : valOwnBirthDate(ownD) ? "green"
        : "red";
    const pin = userInputPIN.value.trim();
    userInputPIN.style.borderColor =
        (!pin || !valOwnBirthDate(ownD)) ? ""
        : valPIN(pin) ? "green"
        : "red";
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valPIN(pin)) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
});

userInputMotherBirthDate.addEventListener("input", () => {
    const mDate = userInputMotherBirthDate.value.trim();
    userInputMotherBirthDate.style.borderColor =
        !mDate ? ""
        : valOtherBirthDate(mDate) ? "green"
        : "red";
    const ownD = userInputOwnBirthDate.value.trim();
    userInputOwnBirthDate.style.borderColor =
        (!ownD || !valOtherBirthDate(userInputFatherBirthDate.value.trim()) || !valOtherBirthDate(mDate)) ? ""
        : valOwnBirthDate(ownD) ? "green"
        : "red";
    const pin = userInputPIN.value.trim();
    userInputPIN.style.borderColor =
        (!pin || !valOwnBirthDate(ownD)) ? ""
        : valPIN(pin) ? "green"
        : "red";
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valPIN(pin)) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
});

userInputOwnBirthDate.addEventListener("input", () => {
    const ownD = userInputOwnBirthDate.value.trim();
    userInputOwnBirthDate.style.borderColor =
        (!ownD || !valOtherBirthDate(userInputFatherBirthDate.value.trim()) || !valOtherBirthDate(userInputMotherBirthDate.value.trim())) ? ""
        : valOwnBirthDate(ownD) ? "green"
        : "red";
    const pin = userInputPIN.value.trim();
    userInputPIN.style.borderColor =
        (!pin || !valOwnBirthDate(ownD)) ? ""
        : valPIN(pin) ? "green"
        : "red";
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valPIN(pin)) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
});

userInputPIN.addEventListener("input", () => {
    const pin = userInputPIN.value.trim();
    userInputPIN.style.borderColor =
        (!pin || !valOwnBirthDate(userInputOwnBirthDate.value.trim())) ? ""
        : valPIN(pin) ? "green"
        : "red";
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valPIN(pin)) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
});

userInputPassw.addEventListener("input", () => {
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valPIN(userInputPIN.value.trim())) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
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

    resultMessage.style.color = "white";
    resultMessage.textContent = `Building your keyfile...`;

    const timeBefore = performance.now();

    const keyfileBytes = await buildKeyfile(
        PIN,
        passw,
        userInputFatherBirthDate.value.trim(),
        userInputMotherBirthDate.value.trim(),
        userInputOwnBirthDate.value.trim(),
        keyfileLength,
        Hs,
    );

    const timeAfter = performance.now();
    const timeSpent = timeAfter - timeBefore;

    if (
        keyfileBytes instanceof Uint8Array
        && keyfileBytes.length === keyfileLength
    ) {
        resultMessage.style.color = "white";
        resultMessage.textContent = `Time spent building the keyfile: ${formatTime(timeSpent)}`;
        keyfileString = `"0K"${encodeBase91(keyfileBytes)}"`;

        getButton.disabled = false;
        getButton.style.backgroundColor = "green";
    } else {
        resultMessage.style.color = "red";
        resultMessage.textContent = `Failed to build keyfile.`;
        keyfileString = null;
        getButton.disabled = true;
        getButton.style.backgroundColor = "";
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
