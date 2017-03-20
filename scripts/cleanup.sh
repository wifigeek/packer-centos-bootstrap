service salt-minion stop
rm /etc/salt/pki/minion/minion.pem
rm /etc/salt/pki/minion/minion.pub
cat /dev/null > /etc/salt/minion_id
chkconfig salt-minion on

sed -i '/HWADDR/d' /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i "/^UUID/d" /etc/sysconfig/network-scripts/ifcfg-eth0

rm /etc/sysconfig/selinux
ln -s /etc/selinux/config /etc/sysconfig/selinux
# 1.6.1.2
#sed -i "s/^\(SELINUX=\).*/\1enabled/g" /etc/selinux/config

rm -f /etc/ssh/ssh_host_*
rm -f /etc/udev/rules.d/70-persistent-net.rules
rm -f /var/lib/dhclient/dhclient-eth0.leases
rm -rf /tmp/*
yum -y clean all
