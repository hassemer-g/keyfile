import { validatePassw } from "./validate_password.js";
import { buildKeyfile } from "./build_keyfile.js";
import { encodeBase91 } from "./base91.js";


const userInputPIN = document.getElementById("userInputPIN");
const userInputPassw = document.getElementById("userInputPassw");
const userInputFatherBirthDate = document.getElementById("userInputFatherBirthDate");
const userInputMotherBirthDate = document.getElementById("userInputMotherBirthDate");
const userInputOwnBirthDate = document.getElementById("userInputOwnBirthDate");
const doButton = document.getElementById("doButton");
const getButton = document.getElementById("getButton");


const keyfileLength = 800000;
let keyfileFinished = false;
let keyfileString = null;


function validatePIN(input) {
    return /^\d{4,}$/.test(input);
}

function validatePasswInput(input) {
    return validatePassw(input, 20)
        && !input.includes(userInputPIN.value.trim());
}

function validateBirthDate(input) {
    return /^\d{2}\/\d{2}\/\d{4}$/.test(input);
}

function validateOwnBirthDate(input) {
    return /^\d{2}\/\d{2}\/\d{4}$/.test(input)
        && input !== userInputFatherBirthDate.value.trim()
        && input !== userInputMotherBirthDate.value.trim();
}

const validators = {
    userInputPIN: validatePIN,
    userInputPassw: validatePasswInput,
    userInputFatherBirthDate: validateBirthDate,
    userInputMotherBirthDate: validateBirthDate,
    userInputOwnBirthDate: validateOwnBirthDate,
};


function validateButton() {

    if (
        validatePIN(userInputPIN.value.trim())
        && validatePasswInput(userInputPassw.value.trim())
        && validateBirthDate(userInputFatherBirthDate.value.trim())
        && validateBirthDate(userInputMotherBirthDate.value.trim())
        && validateOwnBirthDate(userInputOwnBirthDate.value.trim())
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

    field.addEventListener("input", validateButton);
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

    const keyfileBytes = buildKeyfile(
        PIN, 
        passw, 
        userInputFatherBirthDate.value.trim(), 
        userInputMotherBirthDate.value.trim(), 
        userInputOwnBirthDate.value.trim(), 
        keyfileLength, 
    );

    if (
        keyfileBytes instanceof Uint8Array
        && keyfileBytes.length === 800000
    ) {
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


validateButton();



