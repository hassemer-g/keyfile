import { scrypt } from "./noble-hashes/scrypt.js";
import { doHashing } from "./deriv.js";
import { encodeBase91 } from "./base91.js";


export function multScrypt(
    passw, 
    salt, 
    iterations, 
    cost = 19, 
    outputLength = 64, 
    encodingFunction = encodeBase91,
) {

    let output = doHashing(`—${encodingFunction(passw)}—${iterations}—${cost}—${outputLength}—`);

    let counter = 1;
    do {

        salt = doHashing(`—${counter}—${encodingFunction(salt)}—${iterations}—${cost}—${outputLength}—`);

        output = scrypt(
            output,
            salt,
            {
                N: 2 ** cost,
                r: 8,
                p: 1,
                dkLen: counter === iterations ? outputLength : 64,
            },
        );

        counter++;

    } while (!(counter > iterations));

    return output;
}

