# fidelity battery 5 · persona DEPTH for the prod-db-01 server persona.
# The differential vs a minimal alpine container is weak here (a container has
# ~1 process / no listeners / no users) — the real bar is "does this look like a
# believable production database server to an attacker who just landed?".  This
# battery MEASURES the current sotOs recon surface so we know what to deepen.
ps aux
ps -ef
netstat -tlnp
ss -tlnp
ip addr
ip route
w
who
last
cat /root/.bash_history
crontab -l
ls -la /etc/cron.d
cat /etc/ssh/sshd_config
rc-status
free -h
lscpu
getent passwd
