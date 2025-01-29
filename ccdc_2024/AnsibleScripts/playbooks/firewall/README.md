# Using the Playbook
This playbook has multiple functions.  It has a network blackout function that cuts the network off and only allows in certain ip addresses specifically to ssh/RDP/wirnm.  It also has a function to add custom rules that only open ports necessary for services and closes all others.  

Before you run the playbook, you will want to update the group_vars/all.yaml file to contain all the ip addresses to allow into a network.  This is very important as, if you skip this step, the playbook will either not run or you will lock yourself out of the network. To do a network blackout run the following command from this directory ```ansible-playbook firewall.yaml -t network_blackout```.

To add custom rules, simply run the following command: ```ansible-playbook firewall.yaml -t setup_firewall```
