@echo off
netsh advfirewall firewall add rule name="Block Spyware IP" dir=in action=block remoteip=1.2.3.4 protocol=tcp