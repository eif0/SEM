#!/usr/bin/python

# Dependencias: tcpdump, python-scapy
#


import os
import subprocess

# Levanto los parametros

target = raw_input('Enter the target device: ')
passwd = raw_input('Enter the password key for the communication: ')
interface = raw_input('Enter the interface used for the communication (listening): ')

# Dejo monitoreando en background
#os.system('python recivecovert.py -i '+interface+' -p '+passwd+' &')
rec_p = subprocess.Popen(['python', 'recivecovert.py',' -i '+interface+' -p '+passwd+' &'])
rec_pid = rec_p.pid
# Loop para chatear
print 'To exit write \':q!\''
txt=raw_input('> ')
while txt.strip()!=':q!':
	send_p = subprocess.Popen(['python', 'sendcovert.py',' -t '+target+' -d '+txt+' -p '+passwd+' &'])
#	os.system('python sendcovert.py -t '+target+' -d '+txt+' -p '+passwd+' &')
	txt=raw_input('> ')




