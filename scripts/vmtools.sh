if [[ $PACKER_BUILDER_TYPE =~ vmware ]]; then
yum -y install fuse fuse-libs
mount -o loop /home/ea/linux.iso /mnt
cd /tmp
tar zxf /mnt/VMwareTools-*.tar.gz
umount /mnt
/tmp/vmware-tools-distrib/vmware-install.pl --default
rm -rf /tmp/vmware-tools-distrib
rm -rf /home/ea/linux.iso
fi
