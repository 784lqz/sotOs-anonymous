# fidelity battery 4 · the next suspected TELLs after iter-2 (applets + persona).
# Each line is one command; fidelity-diff.sh runs it on real Alpine 3.20 AND on
# the sotOs honey shell over SSH and flags structural divergences.
realpath /etc/passwd
realpath .
getconf PAGESIZE
getconf -a
apk --version
apk info busybox
busybox 2>&1 | head -1
ulimit -n
nproc
ln -s /etc/passwd /tmp/lnk
readlink /tmp/lnk
ls -l /tmp/lnk
cat /proc/1/cmdline
df -h /
mount
free -m
ps -o pid,comm
stat -c '%s %n' /etc/passwd
