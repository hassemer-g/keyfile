import readlineSync from "readline-sync";

export function promptUserInputReadline(
    promptMessage,
    validationFunction,
    hide = false,
    maskType = null,
    repeatInput = 0,
    mustBeDifferentTo = null,
) {

    const options = { hideEchoBack: hide };

    if (maskType !== null) {
        options.mask = maskType;
    }

    do {
        const input = readlineSync.question(promptMessage, options).trim();

        if (!validationFunction(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        if (Array.isArray(mustBeDifferentTo) && mustBeDifferentTo.includes(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        const needsConfirmation = (
            repeatInput === 2
            || (repeatInput === 1 && input !== "")
        );

        if (needsConfirmation) {

            const confirmInput = readlineSync.question(`Confirm (enter again): `, options).trim();

            if (input !== confirmInput) {
                console.error(`Error: Inputs do not match. Try again.`);
                continue;
            }
        }

        return input;

    } while (true);
}
