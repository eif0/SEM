#!/usr/bin/python

#  
# SEM (Security Enhanced Messaging) is a collaborative PoC for implementing Cover Channels over ICMP protocol.
# by renateitor
#
# Last release available in:
# https://github.com/renateitor/SEM
#
# Debe ejecutarse como root ya que es la unica forma de crear paquete de red a medida
# Dependencias: tcpdump, python-scapy
#

# Importamos librerias
import os
import subprocess
import time
import sys
import getopt
import logging

# Definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


# Levantamos lo que se pasa por parametro
opts, extra = getopt.getopt(sys.argv[1:], 'h', ['help'])

for code,param in opts:
	if code in ['-h','--help']:
		print '''
SEM (Security Enhanced Messaging) is a collaborative PoC for implementing Cover Channels over ICMP protocol.
Last release available in: https://github.com/renateitor/SEM

*** Must run as root ***

Deps: tcpdump, python-scapy


 -h  --help 
      Show this message
			
'''
		exit()

# Levanto los parametros necesarios para la comunicacion
name = raw_input('Name(4-char) [test]: ')
target = raw_input('Target device [192.168.1.71]: ')
passwd = raw_input('Key for the communication(8-char) [20121357]: ')
interface = raw_input('Interface for the communication (listening) [eth0]: ')

# Seteo los defaults en caso de que el usuario no complete algun parametro
if name == '':
	name = 'test'
if target == '':
	target = '192.168.1.71'
if passwd == '':
	passwd = '20121357'
if interface == '':
	interface = 'eth0'

# Trunco las variables en caso de que excedan el tamanio max
name = name[0:4]
passwd = passwd[0:8]

# Completo las variables en caso de que sean mas cortas que el min
while name.__len__() < 4:
	name = name+'_'
while passwd.__len__() < 8:
	passwd = passwd+'_'
	
# Dejo monitoreando en background para la recepcion de mensajes
rec_p = subprocess.Popen(['python', 'recive.py','--name='+name,'--interface='+interface,'--password='+passwd,'&'])
rec_pid = rec_p.pid

# Loop para chatear
print 'To exit write: \':q!\''
txt='void'
while True:
	txt=raw_input('') # mostramos el prompt al usuario indicando que puede mandar un mensaje
	
	# Parametros internos (menos el de quit que esta en el while)
	if txt.strip() ==':c!':
		os.system('clear')
		continue
	if txt.strip() ==':h!':
		print '''
		
 :h!   Show this help
 :q!   Exit Program
 :c!   Clear screen
		
		'''
		continue
	if txt.strip()!=':q!':
		break
		
	
	txt=txt+'\n'
	# a partir de aca empieza el armado del paquete y el envio

	# construimos la capa 3 del paquete (IP) 
	l3 = IP()
	l3.dst = target

	# construimos la capa 4 del paquete (ICMP)
	l4 = ICMP()

	# definimos el resto de las variables
	msgsize = 12 # como vamos a dividir el mensaje en partes, aca definimos el tamano de cada parte
	# las variables (first) (last) (count) las utilizamos para el proceso de corte y envio del paquete
	first = 0
	last = (msgsize)
	count = (len(txt)/msgsize)+1
	# entramos en un bucle en el cual vamos a enviar un paquete para cada parte de los datos
	print "							[ %s : " %(count),
	for a in range(0, count):
		print "%s " %(a + 1),
		# si es la primer parte del envio pongo el bit 13 en '0'
		if a == 0:
			payload = passwd + name +'0'+ txt[first:last]
		# si es la ultima parte del envio pongo el bit 13 en '9'
		elif a+1 == count:
			payload = passwd + name +'9'+ txt[first:last]
		# si no es la primer parte ni la ultima pongo el bit 13 en '1'
		else:
			payload = passwd + name +'1'+ txt[first:last]

		# armamos el paquete (las capas que no definimos son definidas automaticamente por scapy)
		pkt = l3/l4/payload
		# enviamos el paquete
		a = sr(pkt, verbose = 0, retry = 0, timeout = 1)
		first += msgsize
		last += msgsize
	print ']'
	
	
	

# Mato el proceso que escucha
os.system('kill -9 '+str(rec_pid))
print '\n\nGood Bye!\n\n'

