import sys
import time

import paramiko
from paramiko.client import AutoAddPolicy

if len(sys.argv) == 1 or sys.argv[1] == "all":
    mode = 0b11111
elif sys.argv[1].startswith("i"):
    mode = 0b00001
elif sys.argv[1].startswith("u"):
    mode = 0b00010
elif sys.argv[1].startswith("d"):
    mode = 0b00100
elif sys.argv[1].startswith("r"):
    mode = 0b01000
else:
    print("init up def rules")
    exit(69)

INTERNAL_BASE = "192.168.0."

LOOKUP = {"21": "ftp", "22": "ssh", "25": "smtp", "53": "dns", "80": "web-browsing", "443": "ssl", "3389": "ms-rdp"}


def sl(svc: [int, str]) -> str:
    if isinstance(svc, int) or svc in LOOKUP:
        return LOOKUP[str(svc)]
    return svc


def quote(name: str) -> str:
    if " " in name and '"' not in name:
        return '"' + name + '"'
    return name


def list_str(data) -> str:
    if isinstance(data, str):
        return quote(data)
    if len(data) == 1:
        return quote(data[0])
    return "[ " + (" ".join([quote(a) for a in data])) + " ]"


log = open("palo.log", "wb")


def out(prompt: str) -> str:
    ret = b""
    while prompt.encode("UTF8") not in ret or shell.recv_ready():
        new = shell.recv(4096)
        ret += new
        log.write(new)
        log.flush()
        time.sleep(0.01)
    return ret.decode()


def c(com: str, valid: str = "", prompt: str = "admin@"):
    # print(f"{com}")
    print(f">{com}")
    shell.send(com.encode("UTF8") + b"\n")
    resp = out(prompt)
    if valid not in resp:
        print("Error with command:" + com)
        print(resp)
        print()
    time.sleep(1)
    while shell.recv_ready():
        print("Clearing garbage: {}".format(shell.recv(4096)))


client = paramiko.SSHClient()
client.set_missing_host_key_policy(AutoAddPolicy())
INITIAL = input("Initial:")
client.connect("10.20.222.1", username="admin", password=INITIAL, timeout=5, look_for_keys=False)
del INITIAL
shell = client.invoke_shell()
print("Logged in!")
out("admin@")

ERRORS = ["Unknown command", "Invalid syntax."]

c("set cli scripting-mode on")

if mode & 2:
    print()
    c("request system software check")
    c("request system software download version 10.1.4", "Download job enqueued with jobid")
    c("request anti-virus upgrade download latest", "Download job enqueued with jobid")
    c("request wildfire upgrade download latest", "Download job enqueued with jobid")
    print()

if mode & 1:
    print()
    A2 = input("U2:")
    PASSWORD = input("Pass:")
    print()
    c("save config to initial.xml")
    c("configure", "Entering configuration mode")
    c("set mgt-config users {} permissions role-based superuser yes".format(A2), "[edit]")
    c("set mgt-config users {} password".format(A2), prompt="Enter password")
    time.sleep(0.1)
    c(PASSWORD, prompt="Confirm password")
    time.sleep(0.1)
    c(PASSWORD)
    c("set mgt-config users admin password", prompt="Enter password")
    time.sleep(0.1)
    c(PASSWORD, prompt="Confirm password")
    time.sleep(0.1)
    c(PASSWORD)
    c("set deviceconfig system device-telemetry device-health-performance no product-usage no threat-prevention no")
    if mode == 1: c("commit", "committed")

c("")

if mode & 4:
    for i in range(1, 10):
        c("set network interface ethernet ethernet1/{} layer2 lldp enable no".format(i))
    c("set zone WAN network layer2 ethernet1/1")
    c("set zone DMZ network layer2 [ ethernet1/2 ethernet1/3 ethernet1/4 ethernet1/5 ethernet1/6 ethernet1/7 ethernet1/8 ]")
    c("set zone LAN network layer2 ethernet1/9")
    c("set network vlan Net interface [ ethernet1/1 ethernet1/2 ethernet1/3 ethernet1/4 ethernet1/5 ethernet1/6 ethernet1/7 ethernet1/8 ethernet1/9 ]")

    for t in ["ftp", "http", "http2", "imap", "pop3", "smb", "smtp"]:
        c("set profiles virus Max decoder {} action reset-both mlav-action reset-both wildfire-action reset-both".format(t))

    for t in ["Executable Linked Format", "PowerShell Script 1", "PowerShell Script 2", "Windows Executables", "MSOffice"]:
        c("set profiles virus Max mlav-engine-filebased-enabled \"{}\" mlav-policy-action enable".format(t))

    c("set profiles data-objects pii pattern-type predefined pattern credit-card-numbers file-type any")
    c("set profiles data-objects pii pattern-type predefined pattern social-security-numbers file-type any")
    c("set profiles data-objects pii pattern-type predefined pattern social-security-numbers-without-dash file-type any")
    c("set profiles data-filtering PII data-capture yes rules R1 alert-threshold 0 block-threshold 0 data-object pii direction both log-severity high application any file-type any")
    c("set profile-group Main virus Max spyware strict vulnerability strict data-filtering PII url-filtering default file-blocking \"strict file blocking\" wildfire-analysis default")

    if mode == 4: c("commit", "committed")

c("")

if mode & 8:
    def fw_rule(name: str, from_zone: str = "any", to_zone: str = "any", application: list = "any", source: list = "any", destination: list = "any", service: list = "application-default", action: str = "allow", profile_group: str = "Main"):
        c("set rulebase security rules \"{}\" from {} source {} to {} destination {} application {} service {} action {} log-end yes profile-setting group {}".format(
            name, from_zone, list_str(source), to_zone, list_str(destination), list_str(application), list_str(service), action, profile_group
        ))


    cfg = open("config.csv")
    dc = []
    for box_data in cfg.readlines():
        box_data = box_data.replace("\t", "").replace("\n", "").split(";")
        box_mode = box_data[1].replace(" ", "")
        box_name = box_data[2]
        box_ip = box_data[0].replace(" ", "")
        box_svc = [sl(svc) for svc in box_data[3].replace(" ", "").split(",")]
        box_alias = "{} - {}".format(box_name, box_ip)

        c("set address \"{}\" ip-netmask {}{}".format(box_alias, INTERNAL_BASE, box_ip))
        if box_mode == "D": dc.append(box_alias)
        for svc in box_svc:
            rule = "{} - {}".format(box_name, svc.upper())
            fw_rule(
                name=rule,
                to_zone="DMZ",
                destination=[box_alias],
                application=[svc]
            )

    fw_rule(
        name="Windows Domain",
        from_zone="LAN",
        to_zone="DMZ",
        destination=dc,
        application=["active-directory", "dns", "kerberos", "ldap", "ms-ds-smb", "ms-netlogon", "msrpc"]
    )
    fw_rule(
        name="Outbound LAN",
        to_zone="WAN",
        application=["web-browsing", "ssl"],
        service=["service-http", "service-https"]
    )
    fw_rule(
        name="Ping",
        application=["ping"],
    )
    fw_rule(
        name="AllowAll",
        service=["any"]
    )
    c("set rulebase default-security-rules rules intrazone-default action allow log-end yes profile-setting group Main")
    c("set rulebase default-security-rules rules interzone-default action drop log-end yes")
    c("commit", "committed")

    c("exit")

print()

if mode & 2:
    c("request system software check")
    c("request system software download version 10.1.4", "Download job enqueued with jobid")
    c("request anti-virus upgrade download latest", "Download job enqueued with jobid")
    c("request wildfire upgrade download latest", "Download job enqueued with jobid")
    c("request anti-virus upgrade install version latest", "Content install job enqueued with jobid")
    c("request wildfire upgrade install version latest", "Content install job enqueued with jobid")
    c("request system software install version 10.1.4", "Software install job enqueued with jobid")
    c("y")
    c("")
