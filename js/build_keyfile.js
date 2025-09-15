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
    
    const stringInputs = [userPIN, userPassw, fatherBirthDate, motherBirthDate, ownBirthDate];
    if (
        arguments.length < 6
        || arguments.length > 7
        || stringInputs.some(v => typeof v !== "string" || !v.trim())
        || !Number.isSafeInteger(keyfileLength)
        || keyfileLength < 1
        || typeof encodingFunction !== "function"
    ) {
        throw new Error(`Incorrect arguments passed to the "buildKeyfile" function.`);
    }

    const salt = doHashing(`—${ownBirthDate}—${fatherBirthDate}—${motherBirthDate}—${userPIN}—${userPassw}—`);

    const prePassw = doHashing(`—${userPIN}—${userPassw}—${ownBirthDate}—${fatherBirthDate}—${motherBirthDate}—${encodingFunction(salt)}—`);

    const salts = derivMult(
        prePassw,
        salt,
        2,
        `"buildKeyfile" — 2 salts — ${keyfileLength} — ${ownBirthDate} — ${fatherBirthDate} — ${motherBirthDate}`,
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
        `"buildKeyfile" — key expansion — ${keyfileLength} — ${ownBirthDate} — ${fatherBirthDate} — ${motherBirthDate}`,
    );

    return keyfile; 
}

