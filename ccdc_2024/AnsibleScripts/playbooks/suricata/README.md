# Using the Playbook
Before you run the playbook, you need to update some variables.  In group_vars/all.yaml, replace the subnet with your networks subnet in CIDR notation (i.e. 10.10.0.0/16).

Now, to run the playbook, just run the command ```ansible-playbook suricata.yaml``` from the current directory and the playbook will run.

# Understanding the Playbook
## Suricata.yaml
This yaml file is the main file that calls all of the roles.  It is pretty simple and is currently divided into linux hosts and windows hosts.

## group_vars
This directory holds the variables for the groups (all, linux, windows, manager, etc.).  all.yaml simply holds the subnet of the network which is needed for suricata configuration.

## Roles
Each main task is separated into roles.  In this case, Linux Setup, Linux Configuration, Windows, and Rust Installation.  I will go through each role and explain its purpose

### Linux Setup
This role is responsible for installing suricata onto Linux based systems.  The tasks directory holds all of the tasks for this role.  Inside the tasks directory, main.yaml is the entrypoint for ansible.  It runs through main.yaml and calls the different tasks based on the Linux distribution.  The rest of the yaml files in tasks are for the specific setup related to that distribution.

The vars directory holds the variables for this role.  Inside the all.yaml file you will find variables relating to linux setup such as repositories, dependencies, and versions.

The files folder holds the files that the tasks can use.  The only file currently is suricata.service that lets ansible setup the source install as a service that starts when the machine boots up.

### Linux Configuration
This role is responsible for putting the correct suricata configuration file on the machine depending on the version that was installed.  It fills out the configuration file using a jinga2 template that allows for host specific configuration such as the default network interface.  Finally, it finishes by starting the suricata service

### Rust Installation
This role is responsible for installing rust on machines that require a source install of suricata.

### Windows
This role is responsible for installing suricata on windows and configuring it.  It pulls the latest rules from Emerging Threats to use and makes sure that suricata is started as a service that starts on boot.
