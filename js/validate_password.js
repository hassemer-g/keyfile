






export function validatePassw(
    input, 
    minLength = 8, 
) {

    if (typeof input !== "string") return false;

    if (minLength < 4) {
        throw new Error(`Incorrect parameters passed to the "validatePassw" function.`);
    }

    if (input.length < minLength) return false;

    const hasDigit = /\d/; 
    const hasLetter = /[A-Za-z]/; 

    
    
    const hasNonBasicChar = /[^0-9A-Za-z]/u;

    return hasDigit.test(input) && hasLetter.test(input) && hasNonBasicChar.test(input);
}



