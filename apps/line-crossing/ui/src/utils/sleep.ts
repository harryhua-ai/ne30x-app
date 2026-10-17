export const sleep = (milliseconds: number): Promise<void> => new Promise((resolve) => {
    window.setTimeout(resolve, milliseconds);
});
