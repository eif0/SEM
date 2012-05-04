#!/usr/bin/python

# Dependencias: tcpdump, python-scapy
#


import os
import subprocess
import time
import sys
import getopt
import logging

# definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


from scapy.all import *




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
rec_p = subprocess.Popen(['python', 'recivecovert.py','--interface='+interface,'--password='+passwd,'&'])
rec_pid = rec_p.pid


# Loop para chatear
print 'To exit write: \':q!\''
txt=raw_input('>> ')
while txt.strip()!=':q!':
	
	txt=txt+'\n'
	# construimos la capa 3 del paquete (IP)
	l3 = IP()
	l3.dst = target
	# construimos la capa 4 del paquete (ICMP)
	l4 = ICMP()

	# definimos el resto de las variables
	msgsize = 12 # como vamos a dividir el mensaje en partes, aqui definimos el tamano de cada parte
	#payload = "" # declaramos la variable 'payload' que vamos a utilizar mas adelante
	# las variables 'first', 'last' y 'count' las vamos a utilizar para el proceso de cada parte del mensaje
	first = 0
	last = (msgsize)
	count = (len(txt)/msgsize)+1
	# entramos en un bucle en el cual vamos a enviar un paquete para cada trozo de datos
	print "							[ %s : " %(count),
	for a in range(0, count):
		print "%s " %(a + 1),
		payload = passwd + txt[first:last]
		# ensamblamos el paquete (las capas que no definimos son definidas automaticamente por scapy)
		pkt = l3/l4/payload
		# enviamos el paquete
		a = sr(pkt, verbose = 0, retry = 0, timeout = 1)
		first += msgsize
		last += msgsize
	print ']'
	
	
	#send_p = subprocess.Popen(['python', 'sendcovert.py','--target='+target,'--data='+txt,'--password='+passwd+' &'])	
	
	
	txt=raw_input('>> ')

# Mato el proceso que escucha
os.system('kill -9 '+str(rec_pid))
print '\n\nGood Bye!\n\n'

