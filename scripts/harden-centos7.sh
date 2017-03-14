echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
echo "install vfat /bin/true" > /etc/modprobe.d/vfat.conf
echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf

echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf

yum install -y ntp ntpdate
systemctl enable ntpd
ntpdate pool.ntp.org
systemctl start ntpd

systemctl enable crond
systemctl enable irqbalance
systemctl enable psacct
systemctl disable kdump
systemctl disable messagebus
systemctl disable netconsole
systemctl disable nfs
systemctl disable nfslock
systemctl disable ntpdate
systemctl disable rdisc
systemctl disable rpcbind
systemctl disable rsyncd
systemctl disable sysstat

yum remove -y bind
yum remove -y dovecot
yum remove -y httpd
yum remove -y net-snmp
yum remove -y rsh
yum remove -y rsh-server
yum remove -y squid
yum remove -y telnet
yum remove -y telnet-server
yum remove -y tftp
yum remove -y tftp-server
yum remove -y vsftpd
yum remove -y xinetd
yum remove -y ypbind
yum remove -y ypserv

yum install -y aide && \
  /usr/sbin/aide --init && \
  cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && \
  /usr/sbin/aide --check

echo "0 3 * * * root /usr/sbin/aide --check" >> /etc/crontab
systemctl restart crond.service

mv files/tmp.mount /usr/lib/systemd/system/tmp.mount

systemctl unmask tmp.mount
systemctl enable tmp.mount

TMPFS="tmpfs   /var/tmp    tmpfs  size=1024M,rw,nosuid,nodev,noexec,relatime   0  0"
echo $TMPFS >> /etc/fstab

SHMFS="shmfs  /dev/shm  tmpfs rw,nosuid,nodev,noexec,relatime 0 0"
echo $SHMFS >> /etc/fstab


##### remember to bindmount /var/tmp to /tmp
##### and mount /tmp as noexec,nodev,nosuid

setenforce 1
sed -i 's/SELINUX=enabled/SELINUX=enforcing/g' /etc/selinux/config
rpm -e openldap-clients
yum install tcp_wrappers tcp_wrappers-libs

### configure hosts.allow and hosts.deny ####
##### do not overwrite files as they remove security context. modify in place ####

chown root:root /etc/hosts.allow
chmod 0644 /etc/hosts.allow

systemctl disable firewalld
yum install -y iptables-services
systemctl enable iptables
cat <<- EOF | iptables-restore

# Generated by iptables-save v1.4.21 on Fri Mar 10 13:05:40 2017
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j DROP
-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
COMMIT
# Completed on Fri Mar 10 13:05:40 2017
EOF

service iptables save

### this should be fixed in the orher script. missing 's' off the end of replaced file #####

cat <<- EOF > /etc/issue
This is a private computer system which is restricted to authorized individuals.

Actual or attempted unauthorized use of this computer system will result in
criminal and/or civil prosecution.

We reserve the right to view, monitor and record activity on the system without
notice or permission. Any information obtained by monitoring, reviewing or
recording is subject to review by law enforcement organizations in connection
with the investigation or prosecution of possible criminal activity on this system.

If you are not an authorized user of this system or do not consent to continued
monitoring, disconnect at this time.
EOF

cp /etc/issue /etc/issue.net

chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

cat <<- EOF > /etc/ntp/ntp.conf
# For more information about this file, see the man pages
# ntp.conf(5), ntp_acc(5), ntp_auth(5), ntp_clock(5), ntp_misc(5), ntp_mon(5).

driftfile /var/lib/ntp/drift

# Permit time synchronization with our time source, but do not
# permit the source to query or modify the service on this system.
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery

# Permit all access over the loopback interface.  This could
# be tightened as well, but to do so would effect some of
# the administrative functions.
restrict 127.0.0.1 
restrict ::1

# Hosts on local network are less restricted.
#restrict 192.168.1.0 mask 255.255.255.0 nomodify notrap

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
server 0.pool.ntp.org iburst
server 1.pool.ntp.org iburst
server 2.pool.ntp.org iburst
server 3.pool.ntp.org iburst

#broadcast 192.168.1.255 autokey	# broadcast server
#broadcastclient			# broadcast client
#broadcast 224.0.1.1 autokey		# multicast server
#multicastclient 224.0.1.1		# multicast client
#manycastserver 239.255.254.254		# manycast server
#manycastclient 239.255.254.254 autokey # manycast client

# Enable public key cryptography.
#crypto

includefile /etc/ntp/crypto/pw

# Key file containing the keys and key identifiers used when operating
# with symmetric key cryptography. 
keys /etc/ntp/keys

# Specify the key identifiers which are trusted.
#trustedkey 4 8 42

# Specify the key identifier to use with the ntpdc utility.
#requestkey 8

# Specify the key identifier to use with the ntpq utility.
#controlkey 8

# Enable writing of statistics records.
#statistics clockstats cryptostats loopstats peerstats

# Disable the monitoring facility to prevent amplification attacks using ntpdc
# monlist command when default restrict does not include the noquery flag. See
# CVE-2013-5211 for more details.
# Note: Monitoring will not be disabled with the limited restriction flag.
disable monitor
EOF


cat <<- EOF > /etc/sysctl.conf
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF

sysctl -p

sysctl -w fs.suid_dumpable=0
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

yum install -y libnet
yum --disablerepo="*" --enablerepo="epel" install -y syslog-ng

yum install audit -y
sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
sed -i 's/space_left_action = SYSLOG/space_left_action = email/g' /etc/audit/auditd.conf 
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/g' /etc/audit/auditd.conf 


sed -i 's/GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=vg_system\/root rhgb quiet"/GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=vg_system\/root rhgb quiet audit=1"/g' /etc/default/grub


grub2-mkconfig > /boot/grub2/grub.cfg

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

cat <<- EOF > /etc/audit/rules.d/audit.rules
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale  
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale  
-w /etc/issue -p wa -k system-locale  
-w /etc/issue.net -p wa -k system-locale  
-w /etc/hosts -p wa -k system-locale  
-w /etc/sysconfig/network -p wa -k system-locale  
-w /etc/selinux/ -p wa -k MAC-policy  
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins 
-w /var/run/utmp -p wa -k session  
-w /var/log/wtmp -p wa -k session  
-w /var/log/btmp -p wa -k session  
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod  
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod  
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod  
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod  
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access  
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access  
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access  
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access  
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules
-e 2
EOF

service auditd restart

touch /etc/cron.allow
chmod 0600 /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.allow
chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.allow

sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin no/PermitRootLogin no/g' /etc/ssh/sshd_config 
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config

echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g' /etc/ssh/sshd_config

echo "AllowGroups root ea" >> /etc/ssh/sshd_config
sed -i 's/#Banner none/Banner \/etc\/issue.net/g' /etc/ssh/sshd_config
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config

restorecon /etc/security/limits.conf

rm /etc/cron.deny
rm /etc/at.deny

sed -i '6s/\#auth/auth/' /etc/pam.d/su

usermod ea -G wheel

echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

chown -R root:root /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-
chmod -R 0600 /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-

chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod og-rwx /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

sed -i 's/# dcredit = -1/dcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# lcredit = -1/lcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# ocredit = -1/ocredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# ucredit = -1/ucredit = -1/g' /etc/security/pwquality.conf


grub2-setpassword
 grub2-mkconfig > /boot/grub2/grub.cfg


sed -ie '/^\/dev\/mapper\/vg_system-tmp/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
mount -o remount /tmp

setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config

chmod 600 /etc/cron.d
chown root:root /etc/cron.d

echo "* hard core 0" >> /etc/security/limits.conf

find /var/log -type f -exec chmod g-wx,o-rwx {} +

#sed -i 's/PASS_MIN_DAYS   0/PASS_MIN_DAYS   7/g' /etc/login.defs
#sed -i 's/PASS_MAX_DAYS   99999/PASS_MAX_DAYS   90/g' /etc/login.defs
#sed -i '26s/\PASS_MIN_DAYS/PASS_MIN_DAYS 7/g' /etc/login.defs

sed -i '15 s/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/password-auth
sed -i '15 s/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/system-auth

sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   7' /etc/login.defs

find /var/log -type f -exec chmod g-wx,o-rwx {} +

echo 'OPTIONS="-u chrony"' > /etc/sysconfig/chronyd
