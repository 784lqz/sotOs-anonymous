cat /etc/alpine-release
cat /proc/loadavg
cat /proc/uptime
cat /proc/cmdline
cat /proc/filesystems
cat /proc/sys/kernel/osrelease
ulimit -n
type ls
kill -l
seq 1 3
expr 6 + 7
basename /usr/bin/foo
dirname /usr/bin/foo
realpath /etc/../etc/passwd
md5sum /etc/passwd
base64 /etc/hostname
file /bin/busybox
getconf LONG_BIT
nproc
groups
id -Gn
busybox 2>&1 | head -1
apk info 2>&1 | head -1
vi --version 2>&1 | head -1
which curl wget nc openssl python3 vi
