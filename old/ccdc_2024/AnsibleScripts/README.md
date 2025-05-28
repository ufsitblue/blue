# Getting Started
Before you start running these ansible playbooks, there are a few things you need to make sure of.  The first thing is to install the correct version of Ansible on your machine.  Unfortunately, Ansible only has installs for Linux based systems. So, if you are running a windows machine, you may want to install WSL and get that set up first.
# Installing Ansible
Follow this link [here](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-and-upgrading-ansible-with-pipx) for installing using pip/pipx.

Follow this link [here](https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html#installing-ansible-on-specific-operating-systems) for installing using the package manager on your system

Make sure that you are installing ansible and not ansible-core.  The playbooks in this github use community made packages that are not installed with ansible-core.  Once you have installed ansible using your method of choice run: ``` ansible -v ```.  

If you are not running ansible version >= 2.10 and you used the package manager to install, then make sure you have the most up to date repository for ansible and reinstall.  These playbooks are built with >= 2.10 compatibility in mind and will not work with earlier versions.
# Ansible Setup
If you already have an inventory hosts.yaml file, then just run the command ```ansible-config init --disabled > ~/.ansible.cfg``` as the user you will run ansible with.  Then replace the line ```;inventory=...``` with ```inventory=<Host_File_Path>```.  Ansible is now fully configured and you can move on to the next step.

If you do not have a hosts file yet, run anisble_setup.sh as the user you will run ansible with and follow the instructions in the script.

## Windows Node Setup
If any of the machines you want to remotely control run windows, then you must have python installed.  I am currently working on a setup playbook that will go in and optimize the environment for ansible to make it easier and quicker to use.  In the meantime, you will need to log on to each of the windows machines and run python_install.ps1 in powershell.  This installs both python and npcap (needed for suricata). 

You are now ready to run the ansible playbooks!
Specific documentation for each playbook is in the playbook directory :)
