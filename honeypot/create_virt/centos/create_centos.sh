#!/bin/sh

if hash lsb_release 2>/dev/null; then
    echo "foo"
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
else
    echo "bar"
    yum install -y redhat-lsb-core
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
fi

##################
#Ubuntu Install
##################
if [ $OS == 'Ubuntu' ]; then
  echo "Running Ubuntu Install";
  apt-get install -y apt-get install kvm libvirt-bin virt-manager virt-viewer virt-top virt-what virt-install
##################
#CentOS Install
##################
elif [ $OS == 'CentOS' ]; then
  echo "Running CentOS Install";
  yum install -y qemu libvirt-client virt-manager \
  virt-viewer guestfish libguestfs-tools virt-top virt-install
  yum groupinstall -y "Virtualisation Tools" "Virtualization Platform"
else 
  echo "Don't recognize Linux Distro '$OS'. Not Ubuntu or CentOS";
  exit 1;
fi

service libvirtd restart
mkdir -p /home/VMs

# Choose a name for the guest:
Name="Centos_Server1"

# Select an OS variant, run "osinfo-query os" for a list
OS="--os-variant=rhel6"

# Select a network option, replacing the MAC address if needed:
#Net="--network bridge=br0"
#Net="--network model=virtio,bridge=br0"
#Net="--network model=virtio,mac=52:54:00:00:00:00"

RANGE=255
MAC1=$RANDOM
MAC2=$RANDOM
MAC3=$RANDOM

let "MAC1 %=$RANGE"
let "MAC2 %=$RANGE"
let "MAC3 %=$RANGE"

OCTET='00:1e:c9'

OCTET1=$(printf "%02x" "$MAC1")
OCTET2=$(printf "%02x" "$MAC2")
OCTET3=$(printf "%02x" "$MAC3")

MACADDR="${OCTET}:${OCTET1}:${OCTET2}:${OCTET3}"

Net="--network model=virtio,bridge=br0,mac=$MACADDR"

# Select a disk option, replacing the filename and size with desired values:
#Disk="--disk /vm/Name.img,size=8"
#Disk="--disk /var/lib/libvirt/images/Name.img,size=8"
#Disk="--disk /var/lib/libvirt/images/Name.img,sparse=false,size=8"
#Disk="--disk /var/lib/libvirt/images/Name.qcow2,sparse=false,bus=virtio,size=8"
#Disk="--disk vol=pool/volume"
#Disk="--livecd --nodisks"
#Disk="--disk /dev/mapper/vg_..."
Disk="--disk /home/VMs/$Name.img,sparse=false,bus=virtio,size=10"

# Select a source (live cd iso, pxe or url):
#Src="--cdrom=/home/isos/ubuntu-12.04.5-server-amd64.iso"
#Src="--pxe"
#Src="-l http://alt.fedoraproject.org/pub/fedora/linux/releases/20/Fedora/x86_64/os/"
#Src="-l http://download.fedoraproject.org/pub/fedora/linux/releases/20/Fedora/x86_64/os/"
#Src="-l http://ftp.us.debian.org/debian/dists/stable/main/installer-amd64/
#Src="-l http://ftp.ubuntu.com/ubuntu/dists/trusty/main/installer-amd64/"
#Src="-l http://download.opensuse.org/distribution/openSUSE-stable/repo/oss/"
#Src="-l http://archive.ubuntu.com/ubuntu/dists/precise/main/installer-amd64/"
Src="-l http://mirror.i3d.net/pub/centos/6/os/x86_64/"
#Src="--location=http://mirror.centos.org/centos/6/os/x86_64"

KSfile="--initrd-inject=./centos.ks"

# Optionally add a URL for a kickstart file:
#KS=""
KS="--extra-args 'ks=file:/centos.ks'"
#KS="-x ks=http://ks.example.com/kickstart/c6-64.ks"

# Optionally select a graphics option:
Gr="--graphics vnc,password=foobar"
#Gr="--nographics"

# Select number of cpus:
Cpu="--vcpus=1"

# Select amount of ram:
Ram="--ram=1024"

Serial="--serial pty"

Console="--console pty"
#Console="-x 'console=ttyS0,115200'"



# Create the guest:

echo virt-install $OS $Net $KSfile $KS $Disk $Src $Gr $Cpu $Ram $Serial $Console --name=$Name --noautoconsole
virt-install $OS $Net $KSfile $KS $Disk $Src $Gr $Cpu $Ram $Serial $Console --name=$Name --video=vga --noautoconsole
