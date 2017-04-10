# audisp-simplify
```
README
This program is an audisp plugin that will make audit events from the Linux Audit daemon human readable.
It will look for execve, socketcall, bind, and connect system calls as well as filesystem changes (if you setup audit rules) and consolidate the events into a simple log format.
The log is in key=value format for easy consumption from Splunk or other log analytic software.
Here is a Splunk query that I run: source="/var/log/audisp-simplify"  |table time key tty ppid auid_user uid_user cwd exe command |sort _time desc 
The logs include the auid_user, which is the original login id.  This is beneficial for seeing who made the syscalls after su'ing to another user such as root.

Here is an execve syscall example of a shell command, ps -efww, executed as myself after su'ing to root:
auditid="213706" auid="1000" auid_user="mkirby" command="ps -efww" cwd="/root" date="2017-02-02" euid="0" euid_user="root" exe="/usr/bin/ps" exit="0" key="EXECVE" node="goemon.mkirby.org" pid="4644" ppid="4572" proctitle="ps -efww" ses="814" subj="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023" time="01:28:19+0000" tty="pts3" types="SYSCALL,EXECVE,CWD,PATH,PROCTITLE,EOE" uid="0" uid_user="root" 


Here is an example of /etc/hosts being modified.  Error code ESRCH means someone echo'd into the file.
auditid="8688" auid="1000" auid_user="mkirby" cwd="/root" date="2017-02-02" errcode="ESRCH" errdesc="No such process" euid="0" euid_user="root" exe="/usr/bin/bash" exit="3" key="FILE" name="/etc/hosts" node="goemon.mkirby.org" pid="5884" ppid="5883" proctitle="-bash" ses="4" subj="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023" time="02:12:14+0000" tty="pts2" types="SYSCALL,CWD,PATH,PROCTITLE,EOE" uid="0" uid_user="root"

Here is a connect syscall example of an egress connection to mkirby.org:
auditid="9845" auid="1000" auid_user="mkirby" date="2017-02-02" euid="0" euid_user="root" exe="/usr/bin/telnet" exit="0" key="CONNECT" node="goemon.mkirby.org" pid="14649" port="80" ppid="5884" proctitle="telnet localhost 80" saddr="127.0.0.1" ses="4" subj="unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023" time="02:14:29+0000" tty="pts2" types="SYSCALL,SOCKADDR,PROCTITLE,EOE" uid="0" uid_user="root"

Here is a bind syscall example of httpd binding to port 80.
auditid="1165" auid="4294967295" date="2017-02-01" euid="0" euid_user="root" exe="/usr/sbin/httpd" exit="0" key="BIND" node="goemon.mkirby.org" pid="3037" port="80" ppid="1" proctitle="(httpd)" saddr=":::::::" ses="4294967295" time="16:47:49+0000" tty="(none)" type="EOE" uid="0" uid_user="root"




INSTALLATION for RedHat, Centos, Scientific Linux, and Fedora

1) Place this script file in /bin/ and chmod this file to 750

2) Install the audit and audispd-plugins packages

3) Enable auditd  on bootup and start the service

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
    -w /etc/                 -p w  -k FILE-etc
    -w /var/spool/cron/      -p w  -k FILE-cron
    -w /var/www/             -p w  -k FILE-www
    -w /var/named/chroot/    -p w  -k FILE-named
    -w /boot/                -p w  -k FILE-boot
    -w /root/.ssh/           -p rw -k FILE-ssh
    -w /etc/pki/tls/private/ -p r  -k FILE-pki
    -w /etc/pki/tls/certs/   -p r  -k FILE-pki
    #-w /usr/                 -p w  -k FILE-usr
    #
    # Monitor commands.  I add "-F uid!=setroubleshoot" to mine to avoid selinux junk.
    -a exit,always -F arch=b32 -F exit=0 -S execve -k EXECVE
    -a exit,always -F arch=b64 -F exit=0 -S execve -k EXECVE
    #
    # Monitor network connections.
    # These are VERY noisy.  Enable at your own risk
    #-a exit,always -F arch=b32 -F exit=0 -S socketcall -k SOCKETCALL
    #-a exit,always -F arch=b64 -F exit=0 -S bind -k BIND
    #-a exit,always -F arch=b64 -F exit=0 -S connect -k CONNECT
    #
    ## This rule suppresses the time-change event when chrony does time updates
    -a never,exit -F arch=b64 -S adjtimex -F auid=unset -Fuid=chrony
    -a never,exit -F arch=b32 -S adjtimex -F auid=unset -Fuid=chrony
    -a never,exit -F arch=b64 -S adjtimex -F auid=unset -Fuid=ntp
    -a never,exit -F arch=b32 -S adjtimex -F auid=unset -Fuid=ntp
    #
    #Record Attempts to Alter Logon and Logout Events
    -w /var/log/faillog -p w -k LOGINS-log
    -w /var/log/lastlog -p w -k LOGINS-log
    #
    #Record Attempts to Alter Process and Session Initiation Information
    -w /var/run/utmp -p w -k SESSION-log
    -w /var/log/btmp -p w -k SESSION-log
    -w /var/log/wtmp -p w -k SESSION-log
    #
    #Ensure auditd Collects Information on Kernel Module Loading and Unloading
    -w /sbin/insmod -p x -k MODULES
    -w /sbin/rmmod -p x -k MODULES
    -w /sbin/modprobe -p x -k MODULES
    -a always,exit -F arch=b32 -S init_module,finit_module -k MODULES
    -a always,exit -F arch=b64 -S init_module,finit_module -k MODULES
    -a always,exit -F arch=b32 -S delete_module -k MODULES
    -a always,exit -F arch=b64 -S delete_module -k MODULES
    #
    ## These rules watch for code injection by the ptrace facility.
    ## This could indicate someone trying to do something bad or
    ## just debugging
    #-a always,exit -F arch=b32 -S ptrace -k PTRACE-tracing
    #-a always,exit -F arch=b64 -S ptrace -k PTRACE-tracing
    #-a always,exit -F arch=b32 -S ptrace -F a0=0x4 -k PTRACE-code-injection
    #-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k PTRACE-code-injection
    #-a always,exit -F arch=b32 -S ptrace -F a0=0x5 -k PTRACE-data-injection
    #-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k PTRACE-data-injection
    #-a always,exit -F arch=b32 -S ptrace -F a0=0x6 -k PTRACE-register-injection
    #-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k PTRACE-register-injection
    #
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
        saddr=:::::::
        name=.*swx$
        name=.*swp$
        name=.*swpx$
        exe=/var/ossec/bin/ossec-syscheckd
        exe=/opt/splunk/bin/splunkd
        exe=/opt/splunkforwarder/bin/splunkd
        
9) Restart the auditd service

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


2) and then run
    cd /etc/selinux/targeted/modules/active/src/
    checkmodule -M -m -o local.mod local.te
    semodule_package -o local.pp -m local.mod
    semodule -i local.pp

```
