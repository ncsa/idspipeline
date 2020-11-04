This directory contains the automated scripts and init files necessary to 
create a centos VM.

There are two files in this directory: create\_centos.sh and centos.ks 

create\_centos.sh:
create\_centos.sh is a shell script that creates a centos VM using 
virt-install. It defines environment variables that can be configured to 
give the VM different parameters, such as CPUs, Memory, what VM 
iso to use, etc. Additionally, the script inserts a kickstart file to 
the installation. Kickstart files are used to initialize centos machines 
and so we use it here to completely automate the OS installation process 
(so there are no click-through steps). The MAC address of the 
honeypot is randomized, but starts with 00:1e:c9 per Alex's guidelines.
Make sure that a new name is chosen for each new VM or there will be 
conflicts. 
The install script will work when run on either centos or ubuntu bare-metal 
machines. The script also needs to be run as root.

centos.ks:
centos.ks is the kickstart file for the centos VM. It currently creates 
a single root user and none others. I believe that the initialized root 
password is currently set to "password", but I'm not 100% on that. To 
initialize a different password, you will have to create its hash and 
replace the current one in this kickstart file before installation. 
Networking is also setup assuming that this VM is being run on the 
external network on NCSA (Dow). If the networking is different in a 
different environment, these values will need to be changed. The IP address 
of each VM needs to be changed so that it does not conflict with other 
VMs. This can be seen in the line 'network (other args) --ip=143.219.0.13'. 
