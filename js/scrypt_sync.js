import { scrypt } from "./noble-hashes/scrypt.js";
import { doHashing } from "./deriv.js";
import { encodeBase91 } from "./base91.js";






function doScrypt(
    passw, 
    salt, 
    cost = 19, 
    outputLength = 64, 
) {

    
    if (
        arguments.length < 2
        || arguments.length > 4
        || !(passw instanceof Uint8Array)
        || !(salt instanceof Uint8Array)
        || !Number.isSafeInteger(cost)
        || cost < 1
        || cost > 20
        || !Number.isSafeInteger(outputLength)
        || outputLength < 1
        || outputLength > 64
    ) {
        throw new Error(`Incorrect arguments passed to the "doScrypt" function.`);
    }

    
    const output = scrypt(
        passw,
        salt,
        {
            N: 2 ** cost, 
            r: 8, 
            p: 1, 
            dkLen: outputLength, 
        },
    );

    return output; 
}



export function multScrypt(
    passw, 
    salt, 
    iterations, 
    cost = 19, 
    outputLength = 64, 
    encodingFunction = encodeBase91,
) {

    
    if (
        arguments.length < 3
        || arguments.length > 6
        || !(passw instanceof Uint8Array)
        || !(salt instanceof Uint8Array)
        || !Number.isSafeInteger(iterations)
        || iterations < 1
        || !Number.isSafeInteger(cost)
        || cost < 1
        || cost > 20
        || !Number.isSafeInteger(outputLength)
        || outputLength < 1
        || outputLength > 64
        || typeof encodingFunction !== "function"
    ) {
        throw new Error(`Invalid inputs received by the "multScrypt" function!`);
    }

    
    let output = doHashing(`—${encodingFunction(passw)}—${iterations}—${cost}—${outputLength}—`);

    
    let counter = 1;
    do {

        console.log(`Scrypt rounds: ${counter}/${iterations}`);

        salt = doHashing(`—${counter}—${encodingFunction(salt)}—${iterations}—${cost}—${outputLength}—`);

        output = doScrypt(
            output, 
            salt,
            cost,
            counter === iterations ? outputLength : 64,
        );

        counter++;

    } while (!(counter > iterations));

    
    if (
        !(output instanceof Uint8Array)
        || output.length !== outputLength
        || !(salt instanceof Uint8Array)
        || salt.length !== 64
    ) {
        throw new Error(`Function "multScrypt" failed.`);
    }

    return output;
}


