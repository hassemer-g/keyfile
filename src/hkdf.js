import { blake512 } from "./noble-hashes/blake1.mjs";
import { hkdf } from "./noble-hashes/hkdf.mjs";

export function doHKDF(
    passw,
    salt,
    info,
    outputLength = 64,
) {

    const output = hkdf(
        blake512,
        passw,
        salt,
        info,
        outputLength,
    );

    return output;
}
