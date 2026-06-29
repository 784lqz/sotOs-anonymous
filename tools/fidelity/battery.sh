id
whoami
uname -a
uname -r
uname -m
hostname
cat /etc/os-release
ls /
ls -la /etc/passwd
cat /etc/passwd
cat /etc/shadow
ps
cat /proc/version
cat /proc/cpuinfo
cat /proc/meminfo
cat /proc/mounts
free
df -h
uptime
mount
echo PATH=$PATH
echo SHELL=$SHELL HOME=$HOME
echo ARG0=$0
which sh
command -v ls
date +%Y
echo SUB=$(uname -s)
echo ARITH=$((6 * 7))
for i in 1 2 3; do echo LOOP$i; done
true && echo AND_OK || echo AND_NO
ls /etc/*.conf
grep root /etc/passwd | cut -d: -f1
touch /tmp/fid_t && echo TOUCH_OK || echo TOUCH_NO
ln -s /etc/passwd /tmp/fid_ln && readlink /tmp/fid_ln
stat /etc/passwd
sed -n 1p /etc/passwd
awk -F: '{print $1}' /etc/passwd
head -2 /etc/passwd | tr a-z A-Z
ifconfig 2>/dev/null | head -2 || echo NO_IFCONFIG
netstat -tln 2>/dev/null | head -2 || echo NO_NETSTAT
cat /proc/1/cmdline; echo
ls /root 2>&1
cd /; cd ..; pwd
nonexistent_cmd_xyz
