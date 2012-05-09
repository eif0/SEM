#!/usr/bin/python

#  
# SEM (Security Enhanced Messaging) is a PoC for implementing Cover Channels over ICMP protocol.
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
import random
import math

# Definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Por defecto se ejecuta en modo simple
verbose = False

# Levantamos lo que se pasa por parametro
opts, extra = getopt.getopt(sys.argv[1:], 't:e:hvb', ['target=','encode=','help','verbose','background'])

# Variables que van a ser globales
global targetfromparam
global target
global encodefromparam
global encodetype

encodefromparam = False
targetfromparam = False

for code,param in opts:
	if code in ['-h','--help']:
		print '''
SEM (Security Enhanced Messaging) is a PoC for implementing Cover Channels over ICMP protocol.
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
      
 :send!
      Send a File
      
 :save!
      Save a Recived a File      
             
			
'''
		exit()

	elif code in ['-b','--background']:
		backgroundmode()
		
	else:
		if code in ['-v','--verbose']:
			verbose = True
		if code in ['-t','--target']:
			targetfromparam = True
			target = param
		if code in ['-e','--encode']:
			encodefromparam = True
			encodetype = param



# Comenzamos a definir las funciones que van a hacer todo el trabajo

# Funcion que encodea en base64 los archivos para enviarlos

def backgroundmode():
	encodetype = raw_input('Encode Type [0]: ')
	passwd = raw_input('Key for the communication(8-char) [20121357]: ')
	interface = raw_input('Interface for the communication (listening) [eth0]: ')
	logtime = str(int(time.time()))
	logsfile = raw_input('Log File [./semlogfile_'+logtime+']: ')
	
	if encodetype == '':
		encodetype = '0'
	if passwd == '':
		passwd = '20121357'
	if interface == '':
		interface = 'eth0'
	if logsfile == '':
		logsfile = './semlogfile_'+logtime

	# Trunco las variables en caso de que excedan el tamanio max
	passwd = passwd[0:8]
	encodetype = encodetype[0:1]
	
	# Completo las variables en caso de que sean mas cortas que el min
	while passwd.__len__() < 8:
		passwd = passwd+'_'
	
	os.system('echo \'\' > '+logsfile)

	rec_p = subprocess.Popen(['python', 'recive.py','--interface='+interface,'--file='+logsfile,'--password='+passwd,'--encode='+encodetype,'--background','&'])
	rec_pid = rec_p.pid
	
	print 'Starting SEM...'
	time.sleep(1)
	print 'To watch the log file while it grows run: tail -f '+logsfile
	time.sleep(1)
	print 'PID: '+str(rec_pid)
	print 'To stop recording run: kill -9 '+str(rec_pid)
	
	exit()
	
	
	

def encoder(source,dest): 
	os.system('base64 '+source+' > '+dest)

# Funcion que decodea base64 para poder volver a convertirlo en el archivo original
def decoder(source,dest):
	os.system('base64 -d '+source+' > '+dest)

# Funcion que manda el texto que se le pasa por parametro
# Si (tipo) es 'f' estamos mandando un archivo, si es 't' estamos mandando un string (chat)
def sendtxt(txt,tipo):

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

		# Me fijo si se esta enviando un chat (texto)
		if tipo == 't':
		
			# si es la primer parte del envio, y NO es la unica pongo el bit 13 en '0'
			if (a == 0) and (a+1 != count):
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'0' + encodetype + cypher(txt[first:last],encodetype)

			# si es la primer parte del envio, y SI es la unica pongo el bit 13 en '5'
			elif (a == 0) and (a+1 == count):
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'5' + encodetype + cypher(txt[first:last],encodetype)

			# si es la ultima parte del envio pongo el bit 13 en '9'
			elif a+1 == count:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'9' + encodetype + cypher(txt[first:last],encodetype)

			# si no es la primer parte ni la ultima pongo el bit 13 en '1'
			else:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'1' + encodetype + cypher(txt[first:last],encodetype)
		
		# Me fijo si lo que se manda es un archivo
		elif tipo == 'f':
			
			# Me fijo que sea el primer paquete correspondiente al archivo
			if a == 0:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'4' + encodetype + cypher(txt[first:last],encodetype)
			
			# Me fijo que no sea el primer ni el ultimo paquete correspondiente al archivo
			elif (a+1 != count) and (a != 0):
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'2' + encodetype + cypher(txt[first:last],encodetype)
			
			# Si es la ultima parte de un archivo
			else:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'3' + encodetype + cypher(txt[first:last],encodetype)
		
		# Me fijo si lo que se manda es un md5sum
		elif tipo == 's':
			
			# Me fijo que no sea la ultima parte del sum
			if a+1 != count:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'7' + encodetype + cypher(txt[first:last],encodetype)
			else:
				payload = cypher(passwd,encodetype) + cypher(name,encodetype) +'8' + encodetype + cypher(txt[first:last],encodetype)
			
			
			
			
		
		# armamos el paquete (las capas que no definimos son definidas automaticamente por scapy)
		pkt = l3/l4/payload
		# enviamos el paquete
		a = sr(pkt, verbose = 0, retry = 0, timeout = 1)
		first += msgsize
		last += msgsize
	
	if verbose:
		print ']'

# Funcion que muestra la ayuda
def showhelp():
	print '''
		
 :h!       Show this help
 :q!       Exit Program
 :c!       Clear Screen
 :v!       Start Verbose Mode
 :s!       Start Simple Mode (Stop Verbose)
 :send!    Send a File
 :save!    Save a Recived File
		
		'''

def getmd5(file_sum):
	os.system('md5sum '+file_sum+' > '+file_sum+'.sum')
	fsum = open(file_sum+'.sum', "r")
	md5 = fsum.read()
	fsum.close()
	os.system('rm -f '+file_sum+'.sum')
	return md5

def cypher(txt,tipocifrado):
	
	if tipocifrado == '0': # No se aplica ninguna codificacion
		return txt
	
	if tipocifrado == '1': # Se incrementa el valor decimal (ord) de los ASCII en 5
		charnum = 0
		listatxt = list(txt)
		while charnum < txt.__len__():
			
			if (ord(txt[charnum]) <= 245) and (ord(txt[charnum]) >= 20):
				listatxt[charnum] = chr(ord(txt[charnum])+5)
			charnum += 1
		txt = ''.join(listatxt)
		return txt
	
	if tipocifrado == '2': # Las posiciones pares son aumentadas en 7 y las impares disminuidas en 3 (valores decimales de los ASCII)
		charnum = 0
		listatxt = list(txt)
		while charnum < txt.__len__():
			if math.fmod(charnum,2) != 0:
				if (ord(txt[charnum]) <= 253) and (ord(txt[charnum]) >= 28):
					listatxt[charnum] = chr(ord(txt[charnum])-3)
			else:
				if (ord(txt[charnum]) <= 243) and (ord(txt[charnum]) >= 18):
					listatxt[charnum] = chr(ord(txt[charnum])+7)
			charnum += 1
		txt = ''.join(listatxt)
		return txt
	
		

# Comienza la interfaz del usr

# Creamos el archivo donde se van a almacenar los logs de esta sesion
os.system('echo \'\' > message.txt')

# Levanto los parametros necesarios para la comunicacion
name = raw_input('Name(4-char) [random]: ')

if targetfromparam == False:
	target = raw_input('Target device [192.168.1.1]: ')
	
if encodefromparam == False:
	encodetype = raw_input('Encode Type [0]: ')

passwd = raw_input('Key for the communication(8-char) [20121357]: ')
interface = raw_input('Interface for the communication (listening) [eth0]: ')

# Seteo los defaults en caso de que el usuario no complete algun parametro
if name == '':
	# Creo un nombre random si no hay uno definido
	name = ''.join([random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for x in xrange(4)])
if target == '':
	target = '192.168.1.1'
if encodetype == '':
	encodetype = '0'
if passwd == '':
	passwd = '20121357'
if interface == '':
	interface = 'eth0'

# Trunco las variables en caso de que excedan el tamanio max
name = name[0:4]
passwd = passwd[0:8]
encodetype = encodetype[0:1]

# Completo las variables en caso de que sean mas cortas que el min
while name.__len__() < 4:
	name = name+'_'
while passwd.__len__() < 8:
	passwd = passwd+'_'
	
# Dejo monitoreando en background para la recepcion de mensajes
rec_p = subprocess.Popen(['python', 'recive.py','--name='+name,'--interface='+interface,'--password='+passwd,'--encode='+encodetype,'&'])
rec_pid = rec_p.pid

# Loop para chatear
print '\nTo exit write: \':q!\''
print 'To have help write: \':h!\'\n\n'

while True:

	# Leemos el texto del usuario
	txt=raw_input('')
	
	# Parametros internos
	
	if txt.strip() ==':c!':		# Clear Screen
		os.system('clear')
		continue
		
	elif txt.strip() ==':send!':		# Send File
		source = raw_input('File Path (no spaces): ')
		dest = '/tmp/semSharedFile'
		encoder(source,dest)
		fdest = open(dest, "r")
		txt = fdest.read()
		fdest.close()
		sendtxt(txt,'f') # Mando el archivo
		md5orig = str(getmd5(source)) # Calculo el md5sum del archivo original que envio
		sendtxt(md5orig,'s') # Mando el md5sum del archivo original (antes de convertirlo a base64)
		# Borro el archivo temporal donde guarde el base64 del archivo que quiero enviar
		os.system('rm -f /tmp/semSharedFile')
		continue
		
		
	elif txt.strip() ==':save!':		# Save a recived File
		transid = raw_input('Transfer ID: ')
		# Lugar donde se habia almacenado temporalmente el base64 del archivo que nos mandaron
		source = '/tmp/'+transid     
		dest = raw_input('Save in (full path): ')
		decoder(source,dest)
		print '\n\n\n		***[ File Successfully Saved! ]***'
		print '		      - path: '+dest+' -\n'
		# Mostramos el md5sum del archivo que nos llego
		print '      Local File md5sum: '+str(getmd5(dest)).split(' ')[0]+'\n\n\n'  
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
	
	else:							# Send User Text
		txt=txt+'\n'
		sendtxt(txt,'t')				
	
	
	

# Mato el proceso que escucha los paquetes que llegan y los loguea/muestra por pantalla
os.system('kill -9 '+str(rec_pid))

# Creo el archivo donde van a quedar guardados los logs
logfilename = str(int(time.time()))
os.system('mv message.txt chatlog_'+logfilename[-6:-1]+'.txt')
print '\n\n\n*** [ Session Log File: chatlog_'+logfilename[-6:-1]+'.txt ] ***'
print '\n\nGood Bye!\n\n'

