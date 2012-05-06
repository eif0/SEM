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

# Por defecto se ejecuta en modo simple
verbose = False

# Levantamos lo que se pasa por parametro
opts, extra = getopt.getopt(sys.argv[1:], 'hv', ['help','verbose'])

for code,param in opts:
	if code in ['-h','--help']:
		print '''
SEM (Security Enhanced Messaging) is a collaborative PoC for implementing Cover Channels over ICMP protocol.
Last release available in: https://github.com/renateitor/SEM

*** Must run as root ***

Deps: tcpdump, python-scapy


EXTERNAL PARAMS:
      
 -h  --help 
      Show this message
      
 -v  --verbose
      Show inside app information about the number of ICMP packages sent     
      
      
      
INSIDE APP PARAMS:

 :q!
      Exit Program

 :c!
      Clear Screen
      
 :h!
      Show Help
      
 :v!
      Start Verbose Mode 
      
 :s!
      Start Simple Mode (Stop Verbose)
             
			
'''
		exit()

	if code in ['-v','--verbose']:
		verbose = True



def encoder(source,dest):
	code = os.system('base64 '+source+' > '+dest)

def decoder(source,dest):
	code = os.system('base64 -d '+source+' > '+dest)

def sendtxt(txt):

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
	
	if verbose:
		print "							[ %s : " %(count),
	
	for a in range(0, count):
		
		if verbose:
			print "%s " %(a + 1),

		# si es la primer parte del envio, y NO es la unica pongo el bit 13 en '0'
		if (a == 0) and (a+1 != count):
			payload = passwd + name +'0'+ txt[first:last]

		# si es la primer parte del envio, y SI es la unica pongo el bit 13 en '5'
		elif (a == 0) and (a+1 == count):
			payload = passwd + name +'5'+ txt[first:last]

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
	
	if verbose:
		print ']'

def showhelp()
	print '''
		
 :h!   Show this help
 :q!   Exit Program
 :c!   Clear Screen
 :v!   Start Verbose Mode
 :s!   Start Simple Mode (Stop Verbose)
		
		'''






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
print '\nTo exit write: \':q!\''
print 'To have help write: \':h!\'\n\n'
txt='void'
while True:

	# Leemos el texto del usuario
	txt=raw_input('')
	
	# Parametros internos
	
	if txt.strip() ==':c!':		# Clear Screen
		os.system('clear')
		continue
		
		
	elif txt.strip() ==':send!':		# Send File
		source = raw_input('File Path (no spaces): ')
		dest = '/tmp/SemSharedFile'
		encoder(source,dest)
		continue
		
		
		
	elif txt.strip() ==':h!':		# Show Help
		showhelp()
		continue
		
	elif txt.strip()==':q!':		# Exit
		break
	
	elif txt.strip() ==':v!':		# Verbose Mode
		verbose = True
		continue
		
	elif txt.strip() ==':s!':		# Simple Mode
		verbose = False
		continue
	else:
		sendtxt(txt)				# Send User Text
	
	
	

# Mato el proceso que escucha
os.system('kill -9 '+str(rec_pid))
print '\n\nGood Bye!\n\n'

