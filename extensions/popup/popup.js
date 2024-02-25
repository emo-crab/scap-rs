browser.action.onClicked.addListener(async (tab) => {
    try {
        await browser.scripting.executeScript({
            target: {
                tabId: tab.id,
            },
            func: () => {
                alert("XSS");
            },
        });
    } catch (err) {
        console.error(`failed to execute script: ${err}`);
    }
});
