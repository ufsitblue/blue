url = 'ws://localhost/ws/web';
var socket = new WebSocket(url);

socket.onopen = function(event) {
    console.log("Connection established!");
};

socket.onerror = function(error) {
    console.log("WebSocket Error: ", error);
};

socket.onclose = function(event) {
    console.log("Connection closed!");
};

