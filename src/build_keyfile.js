import { utf8ToBytes, bytesToHex, concatBytes } from "./noble-hashes/utils.mjs";
import { doHashing, derivMult, expandKey } from "./deriv.js";

export async function buildKeyfile(
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
