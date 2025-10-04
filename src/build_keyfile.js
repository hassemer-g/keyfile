import { utf8ToBytes, bytesToHex, concatBytes } from "./noble-hashes/utils.mjs";
import { doHashing, derivMult, expandKey } from "./deriv.js";

export async function buildKeyfile(
    userPIN,
    userPassw,
    fatherBirthDate,
    motherBirthDate,
    ownBirthDate,
    keyfileLength,
) {

    const salt = await doHashing(utf8ToBytes(`${ownBirthDate} ${fatherBirthDate} ${motherBirthDate} ${userPIN} ${userPassw} ${keyfileLength}`));

    const prePassw = await doHashing(utf8ToBytes(`${userPIN} ${userPassw} ${ownBirthDate} ${fatherBirthDate} ${motherBirthDate} ${keyfileLength} ${bytesToHex(salt)}`));

    const elements = await derivMult(
        prePassw,
        salt,
        3,
    );

    const passw = await doHashing(
        elements[1],
        1000,
        1024,
    );

    const keyfile = await expandKey(
        concatBytes(passw, elements[2]),
        elements[0],
        keyfileLength,

    );

    return keyfile;
}

