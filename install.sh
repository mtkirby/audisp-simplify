#!/bin/bash
################################################################################
# 20161007 Kirby
################################################################################


# This will only run on RedHat, CentOS, and Scientific Linux systems

umask 077

if ! id |grep -q uid=0; then
    echo "FAILURE: you need to be root"
    exit 1
fi

if [ ! -f "audisp-simplify" ]; then
    echo "FAILURE: you need to have audisp-simplify in this directory"
    exit 1
fi

echo ""
echo "Installing perl, audit, and audispd-plugins."
echo "This may take a couple minutes."
echo ""
if which dnf >/dev/null 2>&1; then
    dnf install -y perl audit audispd-plugins >/dev/null 2>&1
elif which yum >/dev/null 2>&1; then
    yum install -y perl audit audispd-plugins >/dev/null 2>&1
else
    echo "FAILURE: could not find dnf or yum"
    exit 1
fi

cp -f audisp-simplify /bin/
chown root:root /bin/audisp-simplify
chmod 750 /bin/audisp-simplify

if ! perl -c /bin/audisp-simplify >/dev/null 2>&1; then
    echo "FAILURE: perl check failed on /bin/audisp-simplify"
    echo "Please run 'perl -c /bin/audisp-simplify' to diagnose"
    exit 1
fi

which systemctl >/dev/null 2>&1 && systemctl enable auditd >/dev/null 2>&1
which chkconfig >/dev/null 2>&1 && chkconfig auditd on >/dev/null 2>&1

if [ ! -d "/etc/audisp/plugins.d" ]; then
    echo "FAILURE: /etc/audisp/plugins.d does not exist"
    exit 1
fi

cat >/etc/audisp/plugins.d/simplify.conf <<EOF
active = yes
direction = out
path = /bin/audisp-simplify
type = always
format = string
EOF
chmod 640 /etc/audisp/plugins.d/simplify.conf


cat /etc/audisp/audispd.conf |egrep -v "^q_depth |^overflow_action " >/tmp/audispd.conf
echo "q_depth = 65536" >>/tmp/audispd.conf
echo "overflow_action = ignore" >>/tmp/audispd.conf
cat /tmp/audispd.conf >/etc/audisp/audispd.conf

cat >/tmp/audit.rules <<EOF
# delete all existing rules
-D
# disable auditing during load
-e 0
# fail silently
-f 0
# 65k buffer
-b 65536
# no rate
-r 0
# continue loading if bad rule and report
-c
#
# Add any other dirs you want monitored for file writes
# These can be noisy during patching.  Enable at your own risk
-w /etc/ -p w -k FILE
-w /root/.ssh/ -p w -k FILE
-w /var/spool/at/ -p w -k FILE
-w /var/spool/cron/ -p w -k FILE
#-w /usr/ -p w -k FILE
#-w /boot/ -p w -k FILE
#
# Monitor commands
-a exit,always -F arch=b32 -F exit=0 -S execve -k EXECVE
-a exit,always -F arch=b64 -F exit=0 -S execve -k EXECVE
#
# Monitor network connections.
# These are VERY noisy.  Enable at your own risk
#-a exit,always -F arch=b32 -F exit=0 -S socketcall -k SOCKETCALL
#-a exit,always -F arch=b64 -F exit=0 -S bind -k BIND
#-a exit,always -F arch=b64 -F exit=0 -S connect -k CONNECT
#
# activate auditing
-e 1
EOF


if [ -d "/etc/audit/rules.d" ]; then
    cat /tmp/audit.rules >/etc/audit/rules.d/audit.rules
else
    cat /tmp/audit.rules >/etc/audit/audit.rules
fi


if [ -d "/etc/logrotate.d" ]; then
    cat >/etc/logrotate.d/audisp-simplify <<EOF
/var/log/audisp-simplify
{
    rotate 30
    daily
    create
    compress
    dateext
    dateyesterday
    shred
    sharedscripts
    create 0600 root root
    postrotate
        /sbin/service auditd restart >/dev/null 2>&1 || true
        /bin/systemctl reload auditd.service >/dev/null 2>&1 || true
    endscript
}
EOF
fi

service auditd restart >/dev/null 2>&1
systemctl reload auditd >/dev/null 2>&1


cat >/etc/audisp/simplify.ignores <<EOF
saddr=netlink.*
saddr=public
saddr=private
saddr=/dev/log
saddr=:::::::
name=.*swx$
name=.*swp$
name=.*swpx$
exe=/var/ossec/bin/ossec-syscheckd
exe=/opt/splunk/bin/splunkd
exe=/opt/splunkforwarder/bin/splunkd
EOF
echo ""
echo "##################################################"
echo "I have setup the /etc/audisp/simplify.ingnores file with my settings."
echo "You may want to modify the file."
echo "##################################################"
echo ""


if getenforce 2>/dev/null |grep -q Enforcing; then
    echo '
##################################################
WARNING WARNING WARNING WARNING WARNING WARNING
##################################################
        SELINUX INSTRUCTIONS
##################################################
WARNING: You have SELinux enabled. Either turn it off or create a local policy.
If you do not have a local policy, you will need to create one.

1) First create the directory /etc/selinux/targeted/modules/active/src/.

2) Add these lines to /etc/selinux/targeted/modules/active/src/local.te
module local 1.0;
require {
	class dir { open getattr search write read remove_name add_name };
	class file { create open read write execute execute_no_trans getattr };
	type audisp_t;
	type auditd_t;
	type auditd_etc_t;
	type auditd_log_t;
	type urandom_device_t;
	type var_log_t;
}  
allow audisp_t var_log_t:file { create open read write execute execute_no_trans getattr };
allow audisp_t var_log_t:dir { write add_name };
allow audisp_t auditd_etc_t:dir { read search open };
allow audisp_t auditd_etc_t:file { read open getattr };
allow audisp_t auditd_log_t:dir { read search open };
allow audisp_t auditd_log_t:file { read open getattr };
allow audisp_t urandom_device_t:chr_file { read open getattr };

3) Then run
    cd /etc/selinux/targeted/modules/active/src/
    checkmodule -M -m -o local.mod local.te
    semodule_package -o local.pp -m local.mod
    semodule -i local.pp
##################################################
        SELINUX INSTRUCTIONS
##################################################
'
fi

# sleep 5 seconds to wait for audit/audisp to start
sleep 5
echo ''
echo '##################################################'
if ps -efwww |grep -v grep |grep -q audisp-simplify; then
    echo 'Checking for audisp-simplify process: SUCCESS'
else
    echo 'Checking for audisp-simplify process: FAILURE'
    echo '    Try rebooting'
fi
if [ -f "/var/log/audisp-simplify" ]; then
    echo 'Checking for /var/log/audisp-simplify: SUCCESS'
else
    echo 'Checking for /var/log/audisp-simplify: FAILURE'
    if getenforce 2>/dev/null |grep -q Enforcing; then
        echo '    This is caused by SELinux.'
        echo '    Please follow the SELinux instructions'
        echo '    OR run setenforce 0 ; systemctl reload auditd'
    fi
fi
echo '##################################################'
echo ''
