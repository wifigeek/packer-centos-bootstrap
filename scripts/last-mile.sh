# 1.6.1.2 Ensure the SELinux state is enforcing - Level 2 Server (Scored)
# REF harden-centos7 122
# change SELINUX to a valid value
# FIXME should be already ok, somehow it gets reset to enabled..
setenforce 1
sed -i 's/SELINUX=enabled/SELINUX=enforcing/g' /etc/selinux/config

# disable syslog and syslog-ng because CIS is stupid
systemctl disable syslog-ng
systemctl disable syslog

# 4.2.1.3 Ensure rsyslog default file permissions configured - Level 1 Server (Scored)
echo "#4.2.1.3 configure default permission for files" >> /etc/rsyslog.conf
echo "\$FileCreateMode 0640" >> /etc/rsyslog.conf
echo "#4.2.1.3 END" >> /etc/rsyslog.conf

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host - Level 1 Server (Scored)
echo "#4.2.1.4 remote log host configuration" >> /etc/rsyslog.conf
echo "*.* @10.102.156.149" >> /etc/rsyslog.conf
echo "#4.2.1.4 END" >> /etc/rsyslog.conf

# 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts - Level 1 Server (Not Scored)
echo "#4.2.1.5 verify log host identity" >> /etc/rsyslog.conf
echo "\$ModLoad imtcp.so" >> /etc/rsyslog.conf
echo "\$InputTCPServerRun 514" >> /etc/rsyslog.conf
echo "#4.2.1.5 END" >> /etc/rsyslog.conf

# 4.2.2.3 Ensure syslog-ng default file permissions configured - Level 1 Server (Scored)
sed -i 's/options {/&\n    # 4.2.2.3 END/' /etc/syslog-ng/syslog-ng.conf
sed -i 's/options {/&\n    perm (0640);/' /etc/syslog-ng/syslog-ng.conf
sed -i 's/options {/&\n    stats_freq (3600);/' /etc/syslog-ng/syslog-ng.conf
sed -i 's/options {/&\n    threaded (yes);/' /etc/syslog-ng/syslog-ng.conf
sed -i 's/options {/&\n    # 4.2.2.3 file permissions/' /etc/syslog-ng/syslog-ng.conf

# 4.2.4 Ensure permissions on all logfiles are configured - Level 1 Server (Scored)
# FIXME wtmp permission are set at boot or at rotation
chmod 640 /var/log/wtmp
sed -i 's/    create 0664 root utmp/    # 4.2.4 logfiles permissions\n&/' /etc/logrotate.conf
sed -i 's/    create 0664 root utmp/    create 0640 root utmp/' /etc/logrotate.conf
sed -i 's/    create 0640 root utmp/&\n    # 4.2.4 END/' /etc/logrotate.conf

# 6.1.7 Ensure permissions on /etc/shadow- are configured - Level 1 Server (Scored)
chmod 600 /etc/shadow-

# 5.4.4 Ensure default user umask is 027 or more restrictive - Level 1 Server (Scored)
sed -i 's/umask 022/# 5.4.4 default user umask -GE 027\n&/' /etc/profile
sed -i 's/umask 022/    umask 027/' /etc/profile
sed -i 's/umask 027/&\n    # 5.4.4 END/' /etc/profile

sed -i 's/umask 022/# 5.4.4 default user umask -GE 027\n&/' /etc/bashrc
sed -i 's/umask 022/    umask 027/' /etc/bashrc
sed -i 's/umask 027/&\n    # 5.4.4 END/' /etc/bashrc

sed -i 's/umask 022/# 5.4.4 default user umask -GE 027\n&/' /etc/csh.cshrc
sed -i 's/umask 022/    umask 027/' /etc/csh.cshrc
sed -i 's/umask 027/&\n    # 5.4.4 END/' /etc/csh.cshrc

#5.3.2 Ensure lockout for failed password attempts is configured - Level 1 Server (Scored)
sed -i 's/auth        required      pam_deny.so/&\n#5.3.2 lockout on failed login/' /etc/pam.d/password-auth
sed -i 's/#5.3.2 lockout on failed login/&\n#5.3.2 END/' /etc/pam.d/password-auth
sed -i 's/#5.3.2 END/auth        required      pam_faillock.so audit silent preauth deny=5 unlock_time=900\n&/' /etc/pam.d/password-auth
sed -i 's/#5.3.2 END/auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900\n&/' /etc/pam.d/password-auth
sed -i 's/#5.3.2 END/auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900\n&/' /etc/pam.d/password-auth
sed -i 's/auth        required      pam_deny.so/&\n#5.3.2 lockout on failed login/' /etc/pam.d/system-auth
sed -i 's/#5.3.2 lockout on failed login/&\n#5.3.2 END/' /etc/pam.d/system-auth
sed -i 's/#5.3.2 END/auth        required      pam_faillock.so audit silent preauth deny=5 unlock_time=900\n&/' /etc/pam.d/system-auth
sed -i 's/#5.3.2 END/auth        [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900\n&/' /etc/pam.d/system-auth
sed -i 's/#5.3.2 END/auth        sufficient    pam_faillock.so authsucc audit deny=5 unlock_time=900\n&/' /etc/pam.d/system-auth

#1.4.2 Ensure bootloader password is set - Level 1 Server (Scored)
echo '#1.4.2 bootloader password' >> /etc/grub.d/40_custom
echo 'set superusers="root"' >> /etc/grub.d/40_custom
echo 'password_pbkdf2 root grub.pbkdf2.sha512.10000.676E76908B951F01CB1E0F856D29ADA743BD9344C68448CEB08823011E569CF0251046CD765D111146BFBBD0B5F37665148D405D2FF7056C10A9723571C8354F.2FCBA29F4AA1D64447C0D5A024DD586E65FABE33BCED803CF6F87F3B7026B9EAF516226E07A3C4C5F48A5DA267D9C024B4CFDFDD69910022041F5E6441D85FF0' >> /etc/grub.d/40_custom
echo '#1.4.2 END' >> /etc/grub.d/40_custom
grub2-mkconfig -o /boot/grub2/grub.cfg
