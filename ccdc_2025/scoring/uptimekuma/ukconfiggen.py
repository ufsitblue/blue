"""
Generates a configuration for Uptime Kuma from a CSV file.

Reads into `services.csv`, outputs into `uptimekumabackup.json`.

Allows for quickly getting set up before a competition.

```
Copyright (C) 2025 Yuliang Huang <https://github.com/yhuang3-uf>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the copyright holder shall not be used in advertising or otherwise to promote the sale, use or other dealings in this Software without prior written authorization from the copyright holder.
```
"""

import csv
import json
import sys
import typing

def main(argv: list[str]) -> int:
    monitor_list: list[dict] = []
    """The list of services to monitor"""
    with open("services.csv") as inputcsvfile:
        inputcsvreader: csv.DictReader = csv.DictReader(inputcsvfile)
        for i, row in enumerate(inputcsvreader):
            port_number: typing.Optional[int] = None
            is_icmp: bool = False
            try:
                if row["port"].strip().lower() in ("ping", "icmp"):
                    is_icmp = True
                port_number = int(row["port"])
            except ValueError:
                pass
            if port_number is None and not is_icmp:
                # Failed to parse port number
                continue
            monitor_list.append({
                "id": i+1, "name": row["description"], "description": None,
                "pathName": row["description"], "parent": None,
                "childrenIDs": [], "url": "https://", "method": "GET",
                "hostname": row["host"], "port": port_number, "maxretries": 0,
                "weight": 2000, "active": True, "forceInactive": False, 
                "type": ("ping" if is_icmp else "port"), "timeout": 48,
                "interval": 60, "retryInterval": 60, "resendInterval": 0,
                "keyword": None, "invertKeyword": False, 
                "expiryNotification": False, "ignoreTls": False, 
                "upsideDown": False, "packetSize": 56, "maxredirects": 10,
                "accepted_statuscodes": ["200-299"], "dns_resolve_type": "A",
                "dns_resolve_server": "1.1.1.1", "dns_last_result": None,
                "docker_container": "", "docker_host": None, "proxyId": None,
                "proxyId": None, "notificationIDList": {}, "tags": [],
                "maintenance": False, 
                'mqttTopic': '', 'mqttSuccessMessage': '', 'databaseQuery': None, 'authMethod': None, 'grpcUrl': None, 'grpcProtobuf': None, 'grpcMethod': None, 'grpcServiceName': None, 'grpcEnableTls': False, 'radiusCalledStationId': None, 'radiusCallingStationId': None, 'game': None, 'gamedigGivenPortOnly': True, 'httpBodyEncoding': None, 'jsonPath': None, 'expectedValue': None, 'kafkaProducerTopic': None, 'kafkaProducerBrokers': [], 'kafkaProducerSsl': False, 'kafkaProducerAllowAutoTopicCreation': False, 'kafkaProducerMessage': None, 'screenshot': None, 'headers': None, 'body': None, 'grpcBody': None, 'grpcMetadata': None, 'basic_auth_user': None, 'basic_auth_pass': None, 'oauth_client_id': None, 'oauth_client_secret': None, 'oauth_token_url': None, 'oauth_scopes': None, 'oauth_auth_method': 'client_secret_basic', 'pushToken': None, 'databaseConnectionString': None, 'radiusUsername': None, 'radiusPassword': None, 'radiusSecret': None, 'mqttUsername': '', 'mqttPassword': '', 'authWorkstation': None, 'authDomain': None, 'tlsCa': None, 'tlsCert': None, 'tlsKey': None, 'kafkaProducerSaslOptions': {'mechanism': 'None'}, 'includeSensitiveData': True,
            })
        output_json_dict: dict = {"version": "1.23.16", "notificationList": [], "monitorList": monitor_list}
        with open("uptimekumabackup.json", 'w') as outputjsonfile:
            outputjsonfile.write(json.dumps(output_json_dict))
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
