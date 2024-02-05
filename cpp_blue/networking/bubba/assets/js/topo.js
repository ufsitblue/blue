var nodeDataArray = [];
var linkDataArray = [];
var ips = [];
const highlightColor = "red";
function init() {
    const $ = go.GraphObject.make;
    myDiagram = new go.Diagram("myDiagramDiv",
        {
            initialAutoScale: go.Diagram.Uniform,
            contentAlignment: go.Spot.Center,
            layout:
            $(go.ForceDirectedLayout,
                { maxIterations: 500, defaultSpringLength: 50, defaultElectricalCharge: 1000 })
        });

    myDiagram.nodeTemplate =
        $(go.Node, "Auto",
            {
                locationSpot: go.Spot.Center,
                locationObjectName: "SHAPE",
                mouseEnter: (e, node) => {
                    node.diagram.clearHighlighteds();
                    node.linksConnected.each(l => highlightLink(l, true));
                    node.isHighlighted = true;
                    const tb = node.findObject("TEXTBLOCK");
                    if (tb !== null) tb.stroke = highlightColor;
                },
                mouseLeave: (e, node) => {
                    node.diagram.clearHighlighteds();
                    const tb = node.findObject("TEXTBLOCK");
                    if (tb !== null) tb.stroke = "black";
                }
            },
            $(go.Shape, "Circle",
                {
                    fill: $(go.Brush, "Linear", { 0: "rgb(255, 255, 255)", 1: "rgb(255, 255, 255)" }),
                    stroke: "black"
                }),
            $(go.TextBlock,
                { name: "TEXTBLOCK", font: "bold 10pt helvetica, bold arial, sans-serif", margin: 1 },
                new go.Binding("text", "text"))
        );

    myDiagram.linkTemplate =
        $(go.Link,
            {
                curve: go.Link.Bezier,
                adjusting: go.Link.Stretch,
                reshapable: true, relinkableFrom: true, relinkableTo: true,
                toShortLength: 3,
                mouseEnter: (e, link) => highlightLink(link, true),
                mouseLeave: (e, link) => highlightLink(link, false)
            },
            new go.Binding("points").makeTwoWay(),
            new go.Binding("curviness"),
            $(go.Shape,
                { strokeWidth: 1.5 },
                new go.Binding("stroke", "isHighlighted", (h, shape) => h ? highlightColor : 'black').ofObject(),
                new go.Binding("strokeWidth", "isHighlighted", h => h ? 4 : 1).ofObject(),
                new go.Binding('stroke', 'progress', progress => progress ? "#ffffff" : 'white'),
                new go.Binding('strokeWidth', 'progress', progress => progress ? 2.5 : 1.5)),
            $(go.Shape,
                { toArrow: "triangle", stroke: null },
                new go.Binding("stroke", "isHighlighted", (h, shape) => h ? highlightColor : 'black').ofObject(),
                new go.Binding("strokeWidth", "isHighlighted", h => h ? 4 : 1).ofObject(),
                new go.Binding('fill', 'progress', progress => progress ? "#ffffff" : 'white')),
            $(go.Panel, "Auto",
                $(go.Shape,
                    {
                        fill: $(go.Brush, "Radial", { 0: "rgb(245, 245, 245)", 0.7: "rgb(245, 245, 245)", 1: "rgba(245, 245, 245, 0)" }),
                        stroke: null
                    }),
                $(go.TextBlock, "transition",
                    {
                        textAlign: "center",
                        font: "12pt helvetica, arial, sans-serif",
                        margin: 4,
                        editable: true
                    },
                    new go.Binding("stroke", "isHighlighted", (h, shape) => h ? highlightColor : 'black').ofObject(),
                    new go.Binding("font", "isHighlighted", h => h ? "16pt helvetica, arial, sans-serif" : "12pt helvetica, arial, sans-serif").ofObject(),
                    new go.Binding("text", "text")
                )
            ));

    GetConnections();
    myDiagram.model = new go.GraphLinksModel(nodeDataArray, linkDataArray);
}
window.addEventListener('DOMContentLoaded', init);

function AddHost(ip) {
    myDiagram.model.addNodeData({ key: ip, text: ip });
}
function GetConnections() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            var connections = JSON.parse(this.responseText);
            var i = 1;
            Object.keys(connections).forEach(key => {
                var src = connections[key][0];
                var dst = connections[key][1];
                var port = connections[key][2];
                if (myDiagram.model.findNodeDataForKey(src) === null) {
                    AddHost(src);
                }
                if (myDiagram.model.findNodeDataForKey(dst) === null) {
                    AddHost(dst);
                }
                linkDataArray.push({ from: src, to: dst, text: port });
                i++;
            });
            myDiagram.model = new go.GraphLinksModel(nodeDataArray, linkDataArray);
        }
    };
    xhttp.open("GET", "http://localhost/api/connections/get", true);
    xhttp.send();
}

function highlightLink(link, show) {
    link.isHighlighted = show;
    link.fromNode.isHighlighted = show;
    link.toNode.isHighlighted = show;
}
