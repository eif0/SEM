#!/usr/bin/python

#
# recive.py es parte de SEM (Security Enhanced Messaging).
# 
# Last release available in:
# https://github.com/renateitor/SEM
#

# ------------------------------------------------------
# Los paquetes estan compuestos de la siguiente manera:
# (los datos se pasan en el campo load)
# bits 1-8 > key
# bits 9-12 > nombre del usr
# bit 13 > indicamos si el paquete es el primero de la serie (0) o no lo es (1)
# bit 14-.. > texto a mandar
# ------------------------------------------------------


# Importamos libs
import sys
import getopt
import logging

# Definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Levantamos lo que se pasa por parametro
opts, extra = getopt.getopt(sys.argv[1:], 'n:i:f:p:', ['name=', 'interface=', 'file=', 'password=' ])

# Definimos valores por defecto { solo se usa en ejecuciones manuales del script }
interface='eth0'
archivo='message.txt'
passwd='20121357'
name ='test'

# Levanta los valores de los parametros
for code,param in opts:
  if code in ['-n','--name']:
     name = param	
  if code in ['-i','--interface']:
     interface = param
  elif code in ['-f','--file']:
     archivo = param
  elif code in ['-p','--password']:
     passwd = param     
     
     
# Definimos la funcion que se va a llamar en la llegada de cada paquete
def monitor_callback(pkt):
	# Diltramos solamente los paquetes que sean ICMP del tipo 'echo-request'( tipo 8 ) y que contengan la key que definimos
	if ICMP in pkt and pkt[ICMP].type == 8 and pkt[ICMP].load[0:8] == passwd:
		# Abrimos el archivo de destino y escribimos los datos recibidos
		f = open(archivo, 'a')
		data = pkt[ICMP].load[13:]
		# Verifico si es la primer parte
		if pkt[ICMP].load[12:13] == '0':
			print >>f,'[',pkt[ICMP].load[8:12],']: ',
			print >>f, data,
		else:
			print >>f,data,
		f.close()

		# Si es el ultimo paquete mostramos los datos por pantalla
		if pkt[ICMP].load[12:13] == '9':
			f = open(archivo, 'r')
			lastline = f.readlines()[-1] # Leo la ultima linea del log
			# Me fijo si la ultima linea del log no se corresponde a un chat enviado por mi
			# (esto lo hago ya que cuando vuelve el ping me llega lo que yo mandé tambien)
			if lastline[0:11] != '[ '+name+' ]:  ':
				print '					<< '+lastline[11:]
			f.close()	
				
####################  DEPRECATED
#		f = open(archivo, 'r')
#		lastline = f.readlines()[-1] # Leo la ultima linea del log
#		# Si la ultima linea esta completa y no faltan llegar partes lo imprime
#		if ('\n' in lastline) and (lastline[0:11] != '[ '+name+' ]:  '):
#			print '					<< '+lastline[11:]
#		f.close()
####################


# empezamos a escuchar en la interface definida por parametro
pkts = sniff(iface=interface, prn=monitor_callback)
