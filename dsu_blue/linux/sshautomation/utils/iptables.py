# Competition Configuration

# list of subnets that are unrestricted (VPN, white team, etc.)
UNRESTRICTED_SUBNETS = [
    "10.128.XXX.0/24"
]

# EXTERNAL_SUBNET = "10.120.XXX.0/24"  # UNUSED

# list of DNS server IPs
DNS_SERVERS = [
    "192.168.XXX.1",
    "192.168.XXX.2"
]

# Script Configuration
IPTABLES_CMD = "iptables"
DEFAULT_INPUT_CHAIN = "INPUT"
DEFAULT_OUTPUT_CHAIN = "OUTPUT"

# list of inbound connection types
# Default: "LISTEN" for TCP and "UNCONN" for UDP
INBOUND_CONNECTION_TYPES = [
    "LISTEN"
]

# list of outbound connection types
# Default: "ESTAB" for TCP and UDP
OUTBOUND_CONNECTION_TYPES = [
  "ESTAB"
]

def genFirewall(ssOutput):
    import re
    INPUT_RULES = set()
    OUTPUT_RULES = set()

    outputScript = ''

    outputScript += f'''
{IPTABLES_CMD} -F {DEFAULT_INPUT_CHAIN}
{IPTABLES_CMD} -F {DEFAULT_OUTPUT_CHAIN}

{IPTABLES_CMD} -A {DEFAULT_INPUT_CHAIN} -i lo -j ACCEPT
{IPTABLES_CMD} -A {DEFAULT_OUTPUT_CHAIN} -o lo -j ACCEPT

{IPTABLES_CMD} -A {DEFAULT_INPUT_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
{IPTABLES_CMD} -A {DEFAULT_OUTPUT_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

{IPTABLES_CMD} -A {DEFAULT_INPUT_CHAIN} -p icmp -j ACCEPT

'''

    for server in DNS_SERVERS:
        outputScript += f'{IPTABLES_CMD} -A {DEFAULT_OUTPUT_CHAIN} -p udp -m udp --dport 53 -d {server} -j ACCEPT\n'

    for subnet in UNRESTRICTED_SUBNETS:
        outputScript += f'{IPTABLES_CMD} -A {DEFAULT_INPUT_CHAIN} -d {subnet} -j ACCEPT\n'

    def extractAddress(addr: str):
        remoteIPMatch = re.match('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)%?[a-z0-9]*:([0-9]+|\*)', addr)
        if remoteIPMatch:
            remoteIP = remoteIPMatch.group(1)
            remotePort = remoteIPMatch.group(2)
        else:
            raise Exception(f"Invalid address: {addr}")
        return remoteIP, remotePort

    for line in ssOutput.split('\n'):
        lineData = line.split()
        if len(lineData) < 6: continue

        if len(lineData) >= 7: 
            nameMatch = re.search('"([^"]+)"', lineData[6])
            if nameMatch:
                name = nameMatch.group(1)
        else:
            name = ''

        remoteIP,remotePort = extractAddress(lineData[5])
        localIP, localPort  = extractAddress(lineData[4])

        if lineData[1] in INBOUND_CONNECTION_TYPES and f'{localPort}/{lineData[0]}' not in INPUT_RULES:
            if name: comment = f'-m comment --comment "{name}"'
            else:    comment = ''

            outputScript += f'{IPTABLES_CMD} -A {DEFAULT_INPUT_CHAIN} -p {lineData[0]} -m {lineData[0]} --dport {localPort} {comment} -j ACCEPT\n'
            INPUT_RULES.add(f'{localPort}/{lineData[0]}')

        if lineData[1] in OUTBOUND_CONNECTION_TYPES and f'{remoteIP}:{remotePort}/{lineData[0]}' not in OUTPUT_RULES:
            if name: comment = f'-m comment --comment "{name}"'
            else:    comment = ''

            outputScript += f'{IPTABLES_CMD} -A {DEFAULT_OUTPUT_CHAIN} -p {lineData[0]} -m {lineData[0]} --dport {remotePort} -d {remoteIP} {comment} -j ACCEPT\n'

            OUTPUT_RULES.add(f'{localPort}/{lineData[0]}')
        
    outputScript += f'''
{IPTABLES_CMD} -P {DEFAULT_INPUT_CHAIN} DROP
{IPTABLES_CMD} -P {DEFAULT_OUTPUT_CHAIN} DROP
'''
        
    return outputScript