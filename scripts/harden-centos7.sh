# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled - Level 1 Server (Scored)
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled - Level 1 Server (Scored)
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled - Level 1 Server (Scored)
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
# 1.1.1.4 Ensure mounting of hfs filesystems is disabled - Level 1 Server (Scored)
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled - Level 1 Server (Scored):
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
# 1.1.1.6 Ensure mounting of squashfs filesystems is disabled - Level 1 Server (Scored)
echo "install squashfs /bin/true" > /etc/modprobe.d/squashfs.conf
# 1.1.1.7 Ensure mounting of udf filesystems is disabled - Level 1 Server (Scored):
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
# 1.1.1.8 Ensure mounting of FAT filesystems is disabled - Level 1 Server (Scored):
echo "install vfat /bin/true" > /etc/modprobe.d/vfat.conf


# 3.5.1 Ensure DCCP is disabled - Level 1 Server (Not Scored):
echo "install dccp /bin/true" > /etc/modprobe.d/dccp.conf
# 3.5.3 Ensure RDS is disabled - Level 1 Server (Not Scored):
echo "install rds /bin/true" > /etc/modprobe.d/rds.conf
# 3.5.2 Ensure SCTP is disabled - Level 1 Server (Not Scored):
echo "install sctp /bin/true" > /etc/modprobe.d/sctp.conf
# 3.5.4 Ensure TIPC is disabled - Level 1 Server (Not Scored):
echo "install tipc /bin/true" > /etc/modprobe.d/tipc.conf

# 2.2.1.1 Ensure time synchronization is in use - Level 1 Server (Not Scored)
yum install -y ntp ntpdate
systemctl enable ntpd
ntpdate pool.ntp.org
systemctl start ntpd

# 5.1.1 Ensure cron daemon is enabled - Level 1 Server (Scored):
systemctl enable crond

# hardening (non CIS) #
systemctl enable irqbalance
systemctl enable psacct
systemctl disable kdump
systemctl disable messagebus
systemctl disable netconsole

# 2.2.7 Ensure NFS and RPC are not enabled - Level 1 Server (Scored):
systemctl disable nfs
systemctl disable nfslock
systemctl disable rpcbind

# Hardening (non CIS) #
systemctl disable ntpdate
systemctl disable rdisc
systemctl disable rsyncd
systemctl disable sysstat

# 2.2.8 Ensure DNS Server is not enabled - Level 1 Server (Scored):
yum remove -y bind

# 2.2.11 Ensure IMAP and POP3 server is not enabled - Level 1 Server (Scored):
yum remove -y dovecot

# 2.2.10 Ensure HTTP server is not enabled - Level 1 Server (Scored):
yum remove -y httpd

# 2.2.14 Ensure SNMP Server is not enabled - Level 1 Server (Scored):
yum remove -y net-snmp

# Ensure rsh client is not installed - Level 1 Server (Scored):
yum remove -y rsh
yum remove -y rsh-server

yum remove -y squid

# 2.3.4 Ensure telnet client is not installed - Level 1 Server (Scored):
yum remove -y telnet
yum remove -y telnet-server

# 2.2.19 Ensure tftp server is not enabled - Level 1 Server (Scored):
yum remove -y tftp
yum remove -y tftp-server

# 2.2.9 Ensure FTP Server is not enabled - Level 1 Server (Scored):
yum remove -y vsftpd

yum remove -y xinetd

# 2.3.1 Ensure NIS Client is not installed - Level 1 Server (Scored):
yum remove -y ypbind

# 2.2.16 Ensure NIS Server is not enabled - Level 1 Server (Scored):
yum remove -y ypserv

# 1.3.1 Ensure AIDE is installed - Level 1 Server (Scored):
yum install -y aide && \
  /usr/sbin/aide --init && \
  cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz && \
  /usr/sbin/aide --check

# 1.3.2 Ensure filesystem integrity is regularly checked - Level 1 Server (Scored):
echo "0 3 * * * root /usr/sbin/aide --check" >> /etc/crontab
systemctl restart crond.service

# 1.1.2 Ensure separate partition exists for /tmp - Level 2 Server (Scored):
mv files/tmp.mount /usr/lib/systemd/system/tmp.mount

systemctl unmask tmp.mount
systemctl enable tmp.mount

TMPFS="tmpfs   /var/tmp    tmpfs  size=1024M,rw,nosuid,nodev,noexec,relatime   0  0"
echo $TMPFS >> /etc/fstab

# 1.1.15 Ensure nodev option set on /dev/shm partition - Level 1 Server (Scored):
# 1.1.16 Ensure nosuid option set on /dev/shm partition - Level 1 Server (Scored):
# 1.1.17 Ensure noexec option set on /dev/shm partition - Level 1 Server (Scored):

SHMFS="shmfs  /dev/shm  tmpfs rw,nosuid,nodev,noexec,relatime 0 0"
echo $SHMFS >> /etc/fstab


##### remember to bindmount /var/tmp to /tmp
##### and mount /tmp as noexec,nodev,nosuid

#setenforce 1
#sed -i 's/SELINUX=enabled/SELINUX=enforcing/g' /etc/selinux/config

# 2.3.5 Ensure LDAP client is not installed - Level 1 Server (Scored):
rpm -e openldap-clients

# 3.4.1 Ensure TCP Wrappers is installed - Level 1 Server (Scored):
yum install tcp_wrappers tcp_wrappers-libs

# 3.4.2 Ensure /etc/hosts.allow is configured - Level 1 Server (Scored):
chown root:root /etc/hosts.allow
# 3.4.4 Ensure permissions on /etc/hosts.allow are 644 - Level 1 Server (Scored):
chmod 0644 /etc/hosts.allow

# 3.6.1 Ensure iptables is installed - Level 1 Server (Scored):
systemctl disable firewalld
yum install -y iptables-services
systemctl enable iptables

# 3.6.2 Ensure default deny firewall policy - Level 1 Server (Scored)
# 3.6.3 Ensure loopback traffic is configured - Level 1 Server (Scored):
# 3.6.5 Ensure firewall rules exist for all open ports - Level 1 Server (Scored):

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

cat <<- EOF > /etc/ntp.conf
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
# 4.2.2.1 Ensure syslog-ng service is enabled - Level 1 Server (Scored)
# 4.2.3 Ensure rsyslog or syslog-ng is installed - Level 1 Server (Scored)
yum --disablerepo="*" --enablerepo="epel" install -y syslog-ng

# 4.1.1.2 Ensure system is disabled when audit logs are full - Level 2 Server (Scored):
yum install audit -y
# 4.1.1.3 Ensure audit logs are not automatically deleted - Level 2 Server (Scored):
sed -i 's/max_log_file_action = ROTATE/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf
sed -i 's/space_left_action = SYSLOG/space_left_action = email/g' /etc/audit/auditd.conf
sed -i 's/admin_space_left_action = SUSPEND/admin_space_left_action = halt/g' /etc/audit/auditd.conf

# 4.1.3 Ensure auditing for processes that start prior to auditd is enabled - Level 2 Server (Scored):
sed -i 's/GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=vg_system\/root rhgb quiet"/GRUB_CMDLINE_LINUX="crashkernel=auto rd.lvm.lv=vg_system\/root rhgb quiet audit=1"/g' /etc/default/grub


grub2-mkconfig > /boot/grub2/grub.cfg

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

cat <<- EOF > /etc/audit/rules.d/audit.rules
# 4.1.4 Ensure events that modify date and time information are collected - Level 2 Server (Scored)
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
# 4.1.5 Ensure events that modify user/group information are collected - Level 2 Server (Scored)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
# 4.1.6 Ensure events that modify the system's network environment are collected - Level 2 Server (Scored):
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
# 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected - Level 2 Server (Scored)
-w /etc/selinux/ -p wa -k MAC-policy
# 4.1.8 Ensure login and logout events are collected - Level 2 Server (Scored)
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
# 4.1.9 Ensure session initiation information is collected - Level 2 Server (Scored):
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
# 4.1.10 Ensure discretionary access control permission modification events are collected - Level 2 Server (Scored):
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
# 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected - Level 2 Server (Scored):
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
# 4.1.13 Ensure successful file system mounts are collected - Level 2 Server (Scored)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
# 4.1.14 Ensure file deletion events by users are collected - Level 2 Server (Scored)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
# 4.1.15 Ensure changes to system administration scope (sudoers) is collected - Level 2 Server (Scored):
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
# 4.1.16 Ensure system administrator actions (sudolog) are collected - Level 2 Server (Scored):
-w /var/log/sudo.log -p wa -k actions
# 4.1.17 Ensure kernel module loading and unloading is collected - Level 2 Server (Scored)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit arch=b64 -S init_module -S delete_module -k modules
# 4.1.18 Ensure the audit configuration is immutable - Level 2 Server (Scored):
-e 2
EOF

service auditd restart

# 5.1.1 Ensure cron daemon is enabled - Level 1 Server (Scored):
# 5.1.2 Ensure permissions on /etc/crontab are configured - Level 1 Server (Scored)
# 5.1.3 Ensure permissions on /etc/cron.hourly are configured - Level 1 Server (Scored):
# 5.1.4 Ensure permissions on /etc/cron.daily are configured - Level 1 Server (Scored):
# 5.1.5 Ensure permissions on /etc/cron.weekly are configured - Level 1 Server (Scored):
# 5.1.6 Ensure permissions on /etc/cron.monthly are configured - Level 1 Server (Scored):
# 5.1.7 Ensure permissions on /etc/cron.d are configured - Level 1 Server (Scored):
#5.1.8 Ensure at/cron is restricted to authorized users - Level 1 Server (Scored):

touch /etc/cron.allow
chmod 0600 /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.allow
chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.allow

# 5.2.2 Ensure SSH Protocol is set to 2 - Level 1 Server (Scored)
sed -i 's/#Protocol 2/Protocol 2/g' /etc/ssh/sshd_config
# 5.2.3 Ensure SSH LogLevel is set to INFO - Level 1 Server (Scored):
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
# 5.2.4 Ensure SSH X11 forwarding is disabled - Level 1 Server (Scored):
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
# 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less - Level 1 Server (Scored):
sed -i 's/#MaxAuthTries 6/MaxAuthTries 4/g' /etc/ssh/sshd_config
# 5.2.6 Ensure SSH IgnoreRhosts is enabled - Level 1 Server (Scored):
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
# 5.2.7 Ensure SSH HostbasedAuthentication is disabled - Level 1 Server (Scored)
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
# 5.2.8 Ensure SSH root login is disabled - Level 1 Server (Scored):
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled - Level 1 Server (Scored):
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
# 5.2.10 Ensure SSH PermitUserEnvironment is disabled - Level 1 Server (Scored):
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config

# 5.2.11 Ensure only approved ciphers are used - Level 1 Server (Scored):
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

# 5.2.13 Ensure SSH Idle Timeout Interval is configured - Level 1 Server (Scored)
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 3/g' /etc/ssh/sshd_config

# 5.2.15 Ensure SSH access is limited - Level 1 Server (Scored):
echo "AllowGroups root ea" >> /etc/ssh/sshd_config

# 5.2.16 Ensure SSH warning banner is configured - Level 1 Server (Scored)
sed -i 's/#Banner none/Banner \/etc\/issue.net/g' /etc/ssh/sshd_config

# 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less - Level 1 Server (Scored):
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config

# 5.1.8 Ensure at/cron is restricted to authorized users - Level 1 Server (Scored):
rm /etc/cron.deny
rm /etc/at.deny

# 5.6 Ensure access to the su command is restricted - Level 1 Server (Scored):
sed -i '6s/\#auth/auth/' /etc/pam.d/su
usermod ea -G wheel

# 5.2.12 Ensure only approved MAC algorithms are used - Level 1 Server (Scored):
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config

# 6.1.5 Ensure permissions on /etc/gshadow are configured - Level 1 Server (Scored):
# 6.1.6 Ensure permissions on /etc/passwd- are configured - Level 1 Server (Scored):
# 6.1.7 Ensure permissions on /etc/shadow- are configured - Level 1 Server (Scored):
# 6.1.8 Ensure permissions on /etc/group- are configured - Level 1 Server (Scored):
# 6.1.9 Ensure permissions on /etc/gshadow- are configured - Level 1 Server (Scored):
chown -R root:root /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-
chmod -R 0600 /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured - Level 1 Server (Scored):
# 5.1.4 Ensure permissions on /etc/cron.daily are configured - Level 1 Server (Scored):
# 5.1.5 Ensure permissions on /etc/cron.weekly are configured - Level 1 Server (Scored):
# 5.1.6 Ensure permissions on /etc/cron.monthly are configured - Level 1 Server (Scored):
# 5.1.7 Ensure permissions on /etc/cron.d are configured - Level 1 Server (Scored):

chown root:root /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod og-rwx /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# 5.3.1 Ensure password creation requirements are configured - Level 1 Server (Scored):
sed -i 's/# dcredit = 1/dcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# lcredit = 1/lcredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# ocredit = 1/ocredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# ucredit = 1/ucredit = -1/g' /etc/security/pwquality.conf
sed -i 's/# minlen = 9/minlen = 14/g' /etc/security/pwquality.conf

# 1.4.2 Ensure bootloader password is set - Level 1 Server (Scored):
#### FAILING - NEEDS FIXED ####
#grub2-setpassword
# grub2-mkconfig > /boot/grub2/grub.cfg

# 1.1.14 Ensure nodev option set on /home partition - Level 1 Server (Scored):
# 1.1.13 Ensure separate partition exists for /home - Level 2 Server (Scored)

sed -ie '/^\/dev\/mapper\/vg_system-tmp/ s/defaults/defaults,nodev,nosuid,noexec/' /etc/fstab
sed -ie '/^\/dev\/mapper\/vg_home-home/ s/defaults/defaults,nodev/' /etc/fstab

mount -o remount /tmp

# Ensure the SELinux state is enforcing - Level 2 Server (Scored):
setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config

# 5.1.4 Ensure permissions on /etc/cron.daily are configured - Level 1 Server (Scored):
chmod 600 /etc/cron.d
chown root:root /etc/cron.d

# .5.1 Ensure core dumps are restricted - Level 1 Server (Scored):
echo "* hard core 0" >> /etc/security/limits.conf

# 4.2.4 Ensure permissions on all logfiles are configured - Level 1 Server (Scored):
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# 5.3.3 Ensure password reuse is limited - Level 1 Server (Scored):
sed -i '15 s/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/password-auth
sed -i '15 s/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok/password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5/g' /etc/pam.d/system-auth

# 5.4.1.1 Ensure password expiration is 90 days or less - Level 1 Server (Scored):
# 5.4.1.2 Ensure minimum days between password changes is 7 or more - Level 1 Server (Scored):
sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   7' /etc/login.defs
chage -m 7 -M 90 root
chage -m 7 -M 90 ea

# 4.2.4 Ensure permissions on all logfiles are configured - Level 1 Server (Scored):
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# 2.2.1.3 Ensure chrony is configured - Level 1 Server (Scored):
echo 'OPTIONS="-u chrony"' > /etc/sysconfig/chronyd
