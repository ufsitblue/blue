#!/bin/bash

curl -sO https://packages.wazuh.com/4.4/wazuh-install.sh && bash ./wazuh-install.sh -a -i
/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh  -u admin -p ''

mkdir /var/ossec/etc/shared/{windows,linux}
cp -r /var/ossec/etc/shared/default/*.txt /var/ossec/etc/shared/windows/ && cp -r /var/ossec/etc/shared/default/*.txt /var/ossec/etc/shared/linux/
chown -R wazuh:wazuh /var/ossec/etc/shared/{windows,linux}
echo "
<agent_config>

        <localfile>
                <location>Microsoft-Windows-Sysmon/Operational</location>
                <log_format>eventchannel</log_format>
        </localfile>

        <localfile>
                <location>Microsoft-Windows-Windows Defender /Operational</location>
                <log_format>eventchannel</log_format>
        </localfile>

        <localfile>
                <location>Security</location>
                <log_format>eventchannel</log_format>
        </localfile>

        <localfile>
                <location>System</location>
                <log_format>eventchannel</log_format>
        </localfile>

        <syscheck>
                <directories check_all="yes" whodata="yes">C:/Users/*/Appdata</directories>
                <windows_registry arch="both" check_all="yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule</windows_registry>
                <windows_registry arch="both" check_all"yes">HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</windows_registry>
                <windows_registry arch="both" check_all="yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC</windows_registry>
                <windows_registry arch="both" check_all"yes">HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS</windows_registry>
        </syscheck>

</agent_config>
" > /var/ossec/etc/shared/windows/agent.conf

echo "
<agent_config>
        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/auth.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/secure</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/apache2/access.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/httpd/access.log</location>
        </localfile>

        <localfile>
                <log_format>audit</log_format>
                <location>/var/log/audit/audit.log</location>
        </localfile>

        <localfile>
                <log_format>syslog</log_format>
                <location>/var/log/remote/rsyslog.log</location>
        </localfile>
        <syscheck>
                <directories check_all="yes" whodata="yes">/etc</directories> 
                <directories check_all="yes" whodata="yes">/var/www</directories>
                <directories check_all="yes" whodata="yes">/root</directories>
                <directories check_all="yes" whodata="yes">/tmp</directories>   
        </syscheck>
</agent_config>
" > /var/ossec/etc/shared/linux/agent.conf


curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh

systemctl restart wazuh-manager