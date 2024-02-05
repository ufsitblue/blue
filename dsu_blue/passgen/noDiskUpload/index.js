function setFileInput(fileInput, contents, name) {
    // Assume the fileInput is an ID if it is a string instead of an element
    if(typeof fileInput === "string")
        fileInput = document.getElementById(fileInput);

    // Do the deed by abusing DataTransfer objects' ability to create a FileList
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(new File([contents], name));
    fileInput.files = dataTransfer.files;
}

// Wraps the tabs.query function in a promise so it's easier to work with
function tabPromise(q) {
    return (new Promise(resolve => {
        chrome.tabs.query(q, tabs => {
            resolve(tabs);
        });
    }));
}

function generateInputList(node) {
    // Assume the node is document if it isn't supplied
    if(!node) node = document;
    // Generate a list of options from the name of the input element and the element ID
    // Hopefully everything has an ID (Otherwise it gets disregarded)
    const options = Array.from(
        node.querySelectorAll("input[type=file]")
    ).filter(e => e.id).map(e => ({
        name: document.querySelector(`label[for=${JSON.stringify(e.id)}]`).textContent || e.id,
        id: e.id
    }));

    return options;
}

(async function() {
    const tabs = await tabPromise({ currentWindow: true, active: true });
    const fileInputSelect = document.getElementById("fileInputSelect");
    const nameInput = document.getElementById("nameInput");
    const contentsInput = document.getElementById("contentsInput");
    const updateFileButton = document.getElementById("updateFileButton");
    
    // Generate the list of file inputs
    const frameInputList = (await chrome.scripting.executeScript({
        target: {
            tabId: tabs[0].id,
            allFrames: true
        },
        func: generateInputList
    }));

    // console.error("LOG", JSON.stringify(frameInputList));
    for (let frame in frameInputList) {
        for(let input in frameInputList[frame].result) {
            const fileInput = frameInputList[frame].result[input];
            fileInputSelect.appendChild(new Option(
                fileInput.name,
                JSON.stringify({
                    id: fileInput.id,
                    frameID: frameInputList[frame].frameId
                })
            ));
        }
    }

    // Register event listener
    updateFileButton.onclick = e => {
        const fileInputData = JSON.parse(fileInputSelect.value);
        // console.error("LOG", JSON.stringify(fileInputData));
        chrome.scripting.executeScript({
            target: {
                tabId: tabs[0].id, 
                frameIds: [fileInputData.frameID]
            },
            func: setFileInput,
            args: [fileInputData.id, contentsInput.value, nameInput.value]
        });
    };
})();