url = 'ws://localhost/ws/web';
var socket = new WebSocket(url);

socket.onmessage = function(event) {
    var message = event.data;
    var data = JSON.parse(message);
    if (typeof data.ID !== 'undefined') {
        if (data.Status === "Alive") {
            if (document.getElementById(data.ID) === null) {
                GetAgents();
            }
            AgentUp(data.ID);
        } else if (data.Status === "Dead") {
            AgentDown(data.ID);
        } else {
            console.log("Unknown status: ", data);
        }
    } else {
        console.log("Unknown message: ", data);
    }
};

socket.onopen = function(event) {
    console.log("Connection established!");
};

socket.onerror = function(error) {
    console.log("WebSocket Error: ", error);
};

socket.onclose = function(event) {
    console.log("Connection closed!");
};

