import { createSHA512, createSHA3, createBLAKE2b, createBLAKE3, createWhirlpool } from "./hash-wasm/hash-wasm.mjs";
import { valPassw } from "./val.js";
import { buildKeyfile } from "./build_keyfile.js";
import { encodeBase91 } from "./base91.js";
import { formatTime } from "./time.js";

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

