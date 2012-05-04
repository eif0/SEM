#!/usr/bin/python

# Dependencias: tcpdump, python-scapy
#


import os
import subprocess



# Levanto los parametros

target = raw_input('Enter the target device [192.168.1.71]: ')
passwd = raw_input('Enter the password key for the communication [20121357]: ')
interface = raw_input('Enter the interface used for the communication (listening) [eth0]: ')

if target == '':
	target = '192.168.1.71'
if passwd == '':
	passwd = '20121357'
if interface == '':
	interface = 'eth0'
	


# Dejo monitoreando en background
rec_p = subprocess.Popen(['python', 'recivecovert.py',' -i '+interface+' -p '+passwd+' &'])
rec_pid = rec_p.pid


# Loop para chatear
print 'To exit write \':q!\''
txt=raw_input('texto ')
while txt.strip()!=':q!':
	os.system('python sendcovert.py -t '+target+' -d \''+txt+'\' -p '+passwd+' &')
	txt=raw_input('> ')

# Mato el proceso que escucha
os.system('kill -9 '+rec_pid)

