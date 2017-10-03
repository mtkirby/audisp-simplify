Name:           audisp-simplify
Version:        2.07
Release:        1
Summary:        audisp-simplify
Source0:        %{name}-%{version}.tar.gz
License:        GPL
Group:          Security
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-buildroot
Vendor:         Matt Kirby
Requires:       audit audispd-plugins

%description
Audisp-simplify is an audispd plugin to log auditd data in key=value pairs

%prep
%setup -q

%build

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/bin
mkdir -p ${RPM_BUILD_ROOT}/etc/audisp/plugins.d
mkdir -p ${RPM_BUILD_ROOT}/etc/audit
mkdir -p ${RPM_BUILD_ROOT}/etc/logrotate.d
install -m 750 -o root -g root bin/audisp-simplify $RPM_BUILD_ROOT/bin/
install -m 640 -o root -g root etc/audisp/audispd.conf.new $RPM_BUILD_ROOT/etc/audisp/
install -m 600 -o root -g root etc/audit/audit.rules.new $RPM_BUILD_ROOT/etc/audit/
install -m 600 -o root -g root etc/logrotate.d/audisp-simplify $RPM_BUILD_ROOT/etc/logrotate.d/
install -m 600 -o root -g root etc/audisp/plugins.d/simplify.conf $RPM_BUILD_ROOT/etc/audisp/plugins.d/
install -m 600 -o root -g root etc/audisp/simplify.ignores $RPM_BUILD_ROOT/etc/audisp/

%clean
rm -rf $RPM_BUILD_ROOT

%post
mv -fp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.bak >/dev/null 2>&1
cp -fp /etc/audit/audit.rules.new /etc/audit/rules.d/audit.rules >/dev/null 2>&1
cp -fp /etc/audit/audit.rules.new /etc/audit/audit.rules >/dev/null 2>&1
mv -fp /etc/audisp/audispd.conf /etc/audisp/audispd.conf.bak >/dev/null 2>&1
cp -fp /etc/audisp/audispd.conf.new /etc/audisp/audispd.conf >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1
service auditd restart >/dev/null 2>&1
auditctl -R /etc/audit/audit.rules >/dev/null 2>&1

%files
/bin/audisp-simplify
/etc/audisp/audispd.conf.new
/etc/audit/audit.rules.new
/etc/logrotate.d/audisp-simplify
/etc/audisp/plugins.d/simplify.conf
/etc/audisp/simplify.ignores


%changelog
* Mon May 22 2017 Matt Kirby
- 2.0.7 tuning
* Thu Feb 16 2017 Matt Kirby
- 2.0.5 rewrite
* Tue Jul 28 2015 Matt Kirby
- 1.0.7 cleanup
* Fri Jul 24 2015 Matt Kirby
- 1.0.6 Added timezone awareness
* Mon Jul 6 2015 Matt Kirby
- 1.0.5 First release
