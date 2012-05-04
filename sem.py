#!/usr/bin/python

# Dependencias: tcpdump, python-scapy
#


import os

# Levanto los parametros

target = raw_input('Enter the target device: ')
passwd = raw_input('Enter the password key for the communication: ')
interface = raw_input('Enter the interface used for the communication (listening): ')

# Dejo monitoreando en background
os.system('python recivecovert.py -i '+interface+' -p '+passwd+' &')


# Loop para chatear
print 'To exit write \':q!\''
txt=raw_input('> ')
while txt.strip()!=':q!':
	os.system('python sendcovert.py -t '+target+' -d '+txt+' -p '+passwd+' &')
	txt=raw_input('> ')




