import { createSHA512, createSHA3, createWhirlpool, createBLAKE2b, createBLAKE3, createSM3, argon2id } from "./hash-wasm/hash-wasm.mjs";

function concatBytes(...arrays) {

    if (arrays.length === 0) return new Uint8Array(0);

    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
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

function buildPatternArr(pattern, times) {

    const plen = pattern.length;
    const result = new Array(plen * times);

    let offset = 0;
    for (let i = 0; i < times; i++) {
        for (let j = 0; j < plen; j++) {
            result[offset++] = pattern[j];
        }
    }

    return result;
}

function wipeUint8() {
    for (let i = 0; i < arguments.length; i++) {
        arguments[i].fill(0);
    }
}

function utf8ToBytes(str) {
    return new Uint8Array(new TextEncoder().encode(str));
}

const customBase91CharSet = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}~";

function encodeBase91(
    data,
) {

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
    wipeUint8(ikm, salt);

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

    let i = 1 >>> 0;
    const iUint8 = new Uint8Array(4);
    const iView = new DataView(iUint8.buffer);

    iView.setUint32(0, i, true);
    const itInput1 = concatBytes(iUint8, utf8ToBytes(`${input.length} ${rounds} ${JSON.stringify(outputOutline)}`), input);
    wipeUint8(input);

    let j = 0 >>> 0;
    const jUint8 = new Uint8Array(4);
    const jView = new DataView(jUint8.buffer);

    const hashArray1 = [];

    for (const [, fn] of Object.entries(Hs)) {
        j = (j + 1) >>> 0;
        jView.setUint32(0, j, true);
        fn.update(jUint8);
        fn.update(itInput1);
        hashArray1.push(fn.digest("binary"));
        fn.init();
    }
    j = 0 >>> 0;

    let hashMat = concatBytes(...(hashArray1.map(u => u.reverse()).sort(compareUint8arrays).reverse())).reverse();

    let salt, passwPt1, passwPt2, passwPt3;

    while (i < rounds) {

        i = (i + 1) >>> 0;
        iView.setUint32(0, i, true);
        const itInput = concatBytes(iUint8, hashMat);

        const hashArray = [];
        for (const [, fn] of Object.entries(Hs)) {
            j = (j + 1) >>> 0;
            jView.setUint32(0, j, true);
            fn.update(jUint8);
            fn.update(itInput);
            hashArray.push(fn.digest("binary"));
            fn.init();
        }
        j = 0 >>> 0;

        const order1 = compareUint8arrays(hashArray[1], hashArray[2]);
        const order2 = compareUint8arrays(hashArray[0], hashArray[3]);
        const order3 = compareUint8arrays(hashArray[4], hashArray[5]);

        if (order1 < 0) {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse())).reverse();
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays))).reverse();
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse()));
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays)));
                }
            }
        } else {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse())).reverse();
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays))).reverse();
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse()));
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays)));
                }
            }
        }

        if (i === rounds - 3) { salt = hashMat.slice(100, 172); }
        else if (i === rounds - 2) { passwPt1 = hashMat; }
        else if (i === rounds - 1) { passwPt2 = hashMat; }
        else if (i === rounds) { passwPt3 = hashMat; }
    }

    const passw = concatBytes(passwPt3, passwPt2, passwPt1);

    const outputs = [];
    i = 0 >>> 0;
    for (const elementLength of outputOutline) {

        i = (i + 1) >>> 0;
        iView.setUint32(0, i, true);
        outputs.push(doHKDF(
            Hs.sha3,
            passw,
            iUint8,
            salt,
            elementLength,
        ));
    }

    if (outputs.length === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}

async function buildKeyfile(
    keyMat,
    keyfileLength,
    argonIts,
    argonMemCost,
    dhRounds1,
    dhRounds2,
    pieceLength,
    Hs,
) {

    const precursors = doHashing(
        keyMat,
        Hs,
        [256, 256, 256, 448],
        dhRounds1,
    );
    wipeUint8(keyMat);

    const argon2Output = await doArgon2id(
        precursors[2],
        precursors[0],
        precursors[1],
        argonMemCost,
        argonIts,
    );

    return concatBytes(...(doHashing(
        concatBytes(argon2Output, precursors[3]),
        Hs,
        buildPatternArr([pieceLength], Math.ceil(keyfileLength / pieceLength)),
        dhRounds2,
    ).map(u => u.reverse()).sort(compareUint8arrays)));
}

const userInputFatherBirthDate = document.getElementById("userInputFatherBirthDate");
const userInputMotherBirthDate = document.getElementById("userInputMotherBirthDate");
const userInputOwnBirthDate = document.getElementById("userInputOwnBirthDate");

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
    sm3: await createSM3(),
};

let KEYFILE_STRING = null;

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

function valPasswInput(input) {
    const date = userInputOwnBirthDate.value.trim();
    return valPassw(input, 20)

        && valOwnBirthDate(date)
        && !input.includes(date.slice(0, 2) + date.slice(3, 5))
        && !input.includes(date.slice(6, 10));
}

function valButton() {

    if (
        valOtherBirthDate(userInputFatherBirthDate.value.trim())
        && valOtherBirthDate(userInputMotherBirthDate.value.trim())
        && valOwnBirthDate(userInputOwnBirthDate.value.trim())

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

    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valOwnBirthDate(ownD)) ? ""
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

    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valOwnBirthDate(ownD)) ? ""
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

    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valOwnBirthDate(ownD)) ? ""
        : valPasswInput(passw) ? "green"
        : "red";
    valButton();
});

userInputPassw.addEventListener("input", () => {
    const passw = userInputPassw.value.trim();
    userInputPassw.style.borderColor =
        (!passw || !valOwnBirthDate(userInputOwnBirthDate.value.trim())) ? ""
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

    const passw = userInputPassw.value.trim();
    userInputPassw.value = "";
    userInputPassw.style.borderColor = "";

    doButton.disabled = true;
    doButton.style.backgroundColor = "";

    resultMessage.style.color = "white";
    resultMessage.textContent = `Building your keyfile...`;

    const timeBefore = performance.now();

    const keyfileLength = 1000000;
    const argonIts = 3000;
    const argonMemCost = 1024;
    const dhRounds = 500000;
    const dhRoundsForExp = 500000;
    const pieceLength = 64;

    const keyfileBytes = await buildKeyfile(
        utf8ToBytes(`ჰK0 ${passw.length} ${keyfileLength} ${argonIts} ${argonMemCost} ${dhRounds} ${dhRoundsForExp} ${pieceLength} ${userInputFatherBirthDate.value.trim()} ${userInputMotherBirthDate.value.trim()} ${userInputOwnBirthDate.value.trim()} ${passw} ჰ`).reverse(),
        keyfileLength,
        argonIts,
        argonMemCost,
        dhRounds,
        dhRoundsForExp,
        pieceLength,
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
        KEYFILE_STRING = `"0K"${encodeBase91(keyfileBytes)}"`;
        wipeUint8(keyfileBytes);
        getButton.disabled = false;
        getButton.style.backgroundColor = "green";
    } else {
        resultMessage.style.color = "red";
        resultMessage.textContent = `Failed to build keyfile.`;
        KEYFILE_STRING = null;
        getButton.disabled = true;
        getButton.style.backgroundColor = "";
    }
});

getButton.addEventListener("click", async () => {

    try {

        await saveStringToFile(KEYFILE_STRING, "keyfile");
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
