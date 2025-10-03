import { argon2id } from "./hash-wasm/hash-wasm.mjs";


export async function doArgon2id(
    password,
    salt,
    secret,
    memCost,
    iterations,
    outputLength = 64,
) {

    const output = await argon2id({
        password,
        salt,
        secret,
        iterations,
        parallelism: 1,
        memorySize: 1024 * memCost,
        hashLength: outputLength,
        outputType: "binary",
    });

    return output;
}


