# audisp-simplify

This program is an audisp plugin that will make audit events from the Linux Audit daemon human readable.
It will look for execve, socketcall, bind, and connect system calls as well as filesystem changes (if you setup audit rules) and consolidate the events into a simple log format.
The log is in key=value format for easy consumption from Splunk or other log analytic software.
Here is a Splunk query that I run: source="/var/log/audisp-simplify"  |table time key tty ppid origuser user cwd exe name saddr command |sort _time desc 
The logs include the origuser, which is the original login id.  This is beneficial for seeing who made the syscalls after su'ing to another user such as root.

Here is an execve syscall example of a shell command, uname -a, executed as myself after su'ing to root:
type=EXECVE key=EXECVE auditid=143600 date="2013-09-29" time="13:33:08-0500" node="goemon.lunari.net" tty=pts1 ppid=2437 pid=8189 exe="/usr/bin/uname" origuser=mkirby user=root cwd="/var/log" command="uname -a"


Here is an example of /etc/hosts being edited:
type= key=FILE auditid=143645 date="2013-09-29" time="13:36:19-0500" node="goemon.lunari.net" tty=pts1 ppid=2437 pid=8208 exe="/usr/bin/vi" name="/etc/hosts~" user=root origuser=mkirby cwd="/var/log"

    
Here is a connect syscall example of an egress connection to mkirby.org:
type=SOCKADDR key=CONNECT auditid=143682 date="2013-09-29" time="13:38:49-0500" node="goemon.lunari.net" tty=pts1 ppid=2437 pid=8229 origuser=mkirby user=root saddr="184.82.178.105 port 443" exe="/usr/bin/telnet"
    
Here is a bind syscall example of httpd binding to port 443:
type=SOCKADDR key=BIND auditid=143745 date="2013-09-29" time="13:39:31-0500" node="goemon.lunari.net" tty=(none) ppid=1 pid=8252 origuser=4294967295 user=root saddr="0.0.0.0 port 443" exe="/usr/sbin/httpd"
    
    
    
```
INSTALLATION for RedHat, Centos, Scientific Linux, and Fedora

1) Place this script file in /bin/ and chmod this file to 750.  Then run a perl check on the file like so, 'perl -c /bin/audisp-simplify'.   If perl reports any errors, then check your perl installation.

2) Install the audit and audispd-plugins packages
    Example: yum install -y audit audispd-plugins

3) Enable auditd  on bootup and start the service
    Example: systemctl enable auditd (on CentOS 7+) or chkconfig auditd on (on CentOS6-)

4) Create a new file, /etc/audisp/plugins.d/simplify.conf and add the following:
    active = yes
    direction = out
    path = /bin/audisp-simplify
    type = always
    format = string

5) Increase queue in /etc/audisp/audispd.conf and set overflow_action to ignore
    q_depth = 65536
    overflow_action = ignore

6) Replace /etc/audit/audit.rules and/or /etc/audit/rules.d/audit.rules with the following: (you may want to add/del to dir monitoring).  YOU NEED A KEY DEFINED ( -k ) for audisp-simplify to log the event.
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
    #-w /etc/ -p w -k FILE
    #-w /root/ -p w -k FILE
    #-w /var/spool/at/ -p w -k FILE
    #-w /var/spool/cron/ -p w -k FILE
    #-w /usr/lib/ -p w -k FILE
    #-w /usr/lib64/ -p w -k FILE
    #-w /usr/libexec/ -p w -k FILE
    #-w /usr/bin/ -p w -k FILE
    #-w /usr/sbin/ -p w -k FILE
    #-w /usr/local/ -p w -k FILE
    #-w /boot/ -p w -k FILE
    #
    # Monitor commands
    -a exit,always -F arch=b32 -S execve -k EXECVE
    -a exit,always -F arch=b64 -S execve -k EXECVE
    #
    # Monitor network connections.
    # These are VERY noisy.  Enable at your own risk
    #-a exit,always -F arch=b32 -S socketcall -k SOCKETCALL -F exit!=-2
    #-a exit,always -F arch=b64 -S bind -k BIND -F exit!=-2
    #-a exit,always -F arch=b64 -S connect -k CONNECT -F exit!=-2
    #
    # activate auditing
    -e 1


7) Setup log rotation by creating /etc/logrotate.d/audisp-simplify 
   Add the following:
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

8) [OPTIONAL] Setup an ignores file for strings that you don't want logged.
    Create a new file /etc/audisp/simplify.ignores and use key=value pairs to specify what you don't want logged.
    The string values can be in Perl regex format.
    Here is an example of my file:
        saddr=netlink.*
        saddr=public
        saddr=private
        saddr=/dev/log
        saddr=.*port 53
        saddr=.*:53
        saddr=::::::: port
        name=.*swx"$
        name=.*swp"$
        name=.*swpx"$
        exe="/var/ossec/bin/ossec-syscheckd"
        exe="/opt/splunk/bin/splunkd"
        exe="/opt/splunkforwarder/bin/splunkd"
        
9) Restart the auditd service.  If you are running systemd (CentOS 7+), then you will need to reboot.

10) If you are seeing audit logs in journald, you can disable it with systemctl mask systemd-journald-audit.socket

11) Done.  Now you can watch the simple audit logs in /var/log/audisp-simplify





AFTER INSTALL
1) Keep an eye on the audit queue with 'auditctl -s'.  You may need to tune audit if the lost and backlog events increase

2) Keep an eye on your syslog for errors from audispd.  You may need to increase the q_depth and priority_boost in /etc/audisp/audispd.conf

3) If you have an insanely busy uid, you can add "-F uid!=<uid>" to execve in audit.rules





INSTALLATION ADDENDUM FOR SELINUX
If you are running SELinux, you may want to add the following to your local policy.
1) Add these lines to /etc/selinux/targeted/modules/active/src/local.te
    
    module local 1.0;
    require {
        class dir { open getattr search write read remove_name add_name };
        class file { create open read write execute execute_no_trans getattr };
        type audisp_t;
        type auditd_t;
        type auditd_etc_t;
        type auditd_log_t;
        type var_log_t;
    }  
    allow audisp_t var_log_t:file { create open read write execute execute_no_trans getattr };
    allow audisp_t var_log_t:dir { write add_name };
    allow audisp_t auditd_etc_t:dir { read search open };
    allow audisp_t auditd_etc_t:file { read open getattr };
    allow audisp_t auditd_log_t:dir { read search open };
    allow audisp_t auditd_log_t:file { read open getattr };

2) and then run
    cd /etc/selinux/targeted/modules/active/src/
    checkmodule -M -m -o local.mod local.te
    semodule_package -o local.pp -m local.mod
    semodule -i local.pp
```
