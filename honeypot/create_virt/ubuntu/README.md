This directory contains the automated scripts and init files necessary to 
create a ubuntu VM.

There are two files in this directory: create\_ubuntu.sh and preseed.cfg

create\_ubuntu.sh:
create\_ubuntu.sh is a shell script that creates an ubuntu VM using 
virt-install. It defines environment variables that can be configured to 
give the VM different parameters, such as CPUs, Memory, what VM 
iso to use, etc. Additionally, the script inserts a preseed file to 
the installation. Preseed files are used to initialize ubuntu machines 
and so we use it here to completely automate the OS installation process 
(so there are no click-through steps). The MAC address of the 
honeypot is randomized, but starts with 00:1e:c9 per Alex's guidelines.
Make sure that a new name is chosen for each new VM or there will be 
conflicts. 
The install script will work when run on either centos or ubuntu bare-metal 
machines. The script also needs to be run as root.

preseed.cfg:
preseed.cfg is the preseed file for the ubuntu VM. It currently creates 
a root user and a user named 'ubuntu'. I believe that the initialized 
password for the 'ubuntu' user is currently set to "ubuntu", 
but I'm not 100% on that. To 
initialize a different password, you will have to create its hash and 
replace the current one in this preseed file before installation. 
Networking is also setup assuming that this VM is being run on the 
external network on NCSA (Dow). If the networking is different in a 
different environment, these values will need to be changed. The IP address 
of each VM needs to be changed so that it does not conflict with other 
VMs. This can be seen in the line 
'netcf/get\_ipaddress string 143.219.0.14'. 
