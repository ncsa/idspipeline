#platform=x86, AMD64, or Intel EM64T
#version=DEVEL
# Install OS instead of upgrade
install
# Keyboard layouts
keyboard 'us'# Reboot after installation
reboot
# Root password
rootpw --iscrypted $1$VmhXMCdy$NCsiVvVxpJymnP5hEHyup/
# System timezone
timezone America/Chicago
# System language
lang en_US
# Firewall configuration
firewall --disabled
# Network information
network  --bootproto=static --device=eth0 --gateway=143.219.0.1 --ip=143.219.0.13 --nameserver=208.67.222.222,208.67.220.220 --netmask=255.255.255.0
# System authorization information
auth  --useshadow  --passalgo=sha512
# Use CDROM installation media
cdrom
# Use text mode install
text
# SELinux configuration
selinux --enforcing
# Do not configure the X Window System
skipx

# System bootloader configuration
bootloader --location=mbr
# Clear the Master Boot Record
zerombr
# Partition clearing information
clearpart --all --initlabel 
# Disk partitioning information
part /boot --fstype=ext4 --size=500
part / --fstype=ext4 --size=7500
part swap --size=1000
part /home --fstype=ext4 --size=1000
