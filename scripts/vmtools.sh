
major_version=$(rpm -q --queryformat '%{RELEASE}' rpm | grep -o [[:digit:]]*\$)

if [[ $PACKER_BUILDER_TYPE =~ vmware ]]; then

# open-vm-tools is what we want to use on v7 and above. 
# older releases use the normal vmware esxi supported vmware tools.

if [[ $major_version -ge '7' ]]; then
	yum -y install open-vm-tools
	rm -rf /home/ea/linux.iso
else

yum -y install fuse fuse-libs
mount -o loop /home/ea/linux.iso /mnt
tar zxf /mnt/VMwareTools-*.tar.gz -C /tmp
umount /mnt


/tmp/vmware-tools-distrib/vmware-install.pl -d default

rm -rf /tmp/vmware-tools-distrib
rm -rf /home/ea/linux.iso
fi
fi
