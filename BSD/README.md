# Setting up BSD firewall
The first thing you want to do is make sure that pf is loaded into the kernel.  You do that by running the following command: ```kldload pf```.  Now that you have pf loaded, you need to edit /etc/rc.conf to enable pf and tell it where to find the rules.  you can do that by directly editing the file or running these commands: ```sysrc pf_enable="yes"``` and ```sysrc pf_rules="/path/to/.conf"```

## Choosing which .conf file to use
Now that pf is enabled and set up, you must choose a .conf file to copy to the bsd machine.  All of the conf files in this directory are standalone rules files.  You can only have one loaded at a time.  If you choose one of the blackout conf files, then remember to replace the <> tags with the ip addresses you want to whitelist.  If you use one to the standard files remember to fill out the required_services and team_ips variables like in the blackout conf file.  Also, if the bsd machine is part of the AD domain, make sure to pick a conf file with dc at the start.

## Starting the firewall
After placing your chosen conf file at the location specified in the pf_rules variable, simply run the command ```service pf start``` and the firewall will activate.  Do not be alarmed, your shell will become unresponive.  This is because pf cuts off all active connections when started.  Just close that terminal and open a new one and you will be able to connect to bsd with a functional firewall.

## Future proofing the firewall
After placing the conf file and starting the firewall, it would be a good idea to make it hard for red team to mess with the firewall.  One way we can do this is by making our conf file immutable.  This keeps red team from overwriting or deleting our conf file.  To do this simply run the command ```chattr +i /path/to/.conf```.  If you ever want to modify the firewall, you can do that by running ```chattr -i /path/to/file```, editing the file, and making it immutable again.  If you suspect the firewall is not running, run the command ```service pf status``` and make sure it says enabled at the top and not disabled.
