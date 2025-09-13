import { encodeBase91 } from "./base91.js";
import { doHashing, derivMult, expandKey } from "./deriv.js";
import { multScrypt } from "./scrypt_sync.js";






export function buildKeyfile(
    userPIN, 
    userPassw, 
    fatherBirthDate, 
    motherBirthDate, 
    ownBirthDate, 
    keyfileLength, 
    encodingFunction = encodeBase91,
) {

    
    console.time("Keyfile derivation");

    
    const stringInputs = [userPIN, userPassw, fatherBirthDate, motherBirthDate, ownBirthDate];
    if (
        arguments.length < 6
        || arguments.length > 7
        || !stringInputs.every(v => typeof v === "string" && v.trim())
        || !Number.isSafeInteger(keyfileLength)
        || keyfileLength < 1
        || typeof encodingFunction !== "function"
    ) {
        throw new Error(`Incorrect arguments passed to the "buildKeyfile" function.`);
    }

    console.log(`
    Starting now to derive your keyfile.
    Be patient, this can take up to 10 minutes, depending on your device.
    `);

    
    const salt = doHashing(`—${ownBirthDate.slice(0, 5)}—${fatherBirthDate.slice(0, 5)}—${motherBirthDate.slice(0, 5)}—${userPIN.slice(0, 3)}—${userPassw.slice(0, 8)}—`);

    
    const prePassw = doHashing(`—${userPIN}—${userPassw}—${ownBirthDate}—${fatherBirthDate}—${motherBirthDate}—${encodingFunction(salt)}—`);

    
    const salts = derivMult(
        prePassw,
        salt,
        2,
        `"buildKeyfile" — 2 salts — ${keyfileLength} — ${ownBirthDate}`, 
    );

    
    const passw = multScrypt(
        prePassw, 
        salts[0], 
        200,
    );

    
    const keyfile = expandKey(
        passw, 
        salts[1], 
        keyfileLength, 
        `"buildKeyfile" — key expansion — ${keyfileLength} — ${ownBirthDate}`, 
    );

    
    const byteOutputs = [salt, prePassw, salts[0], salts[1], passw, keyfile];
    if (
        !byteOutputs.every(v => v instanceof Uint8Array)
    ) {
        throw new Error(`Function "buildKeyfile" failed.`);
    }

    console.timeEnd("Keyfile derivation");

    return keyfile; 
}


