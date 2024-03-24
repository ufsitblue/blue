
url = 'ws://localhost/ws/web';
var socket = new WebSocket(url);

socket.onmessage = function(event) {
    var message = event.data;
    var data = JSON.parse(message);
    if (typeof data.Port !== 'undefined') {
        if (myDiagram.model.findNodeDataForKey(data.Src) === null) {
            AddHost(data.Src);
        }
        if (myDiagram.model.findNodeDataForKey(data.Dst) === null) {
            AddHost(data.Dst);
        }
        myDiagram.model.addLinkData({ from: data.Src, to: data.Dst, text: data.Port});
    } else if (typeof data.IP !== 'undefined') {
        myDiagram.model.addNodeData({ key: data.IP, text: data.IP });
    } else if (data.Status) {

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

function AddHost(ip) {
    myDiagram.model.addNodeData({ key: ip, text: ip });
}
