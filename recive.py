#!/usr/bin/python

#
# recive.py es parte de SEM (Security Enhanced Messaging).
# 
# Last release available in:
# https://github.com/renateitor/SEM
#

# ------------------------------------------------------
#
# Los paquetes estan compuestos de la siguiente manera:
# (los datos se pasan en el campo load)
#
# bits 1-8 :
#		key de para identificar al paquete
#
# bits 9-12 :
#		nombre del usr
#
# bit 13 :	
#		es '0' si es la primer parte de una serie
#		es '1' si es una parte intermedia en un envio de una serie
#		es '2' si es una parte intermedia de un archivo
#		es '3' si es el ultimo paquete de datos de un archivo
#		es '4' si es el primer paquete de datos de un archivo
#		es '5' si es un envio de una sola parte
#		es '9' si es la ultima parte de un envio de una serie 
#
# bit 14-.. :
#		texto a mandar
#
# ------------------------------------------------------


# Importamos libs
import sys
import getopt
import logging
import time

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
tempfile = str(int(time.time()))
recibido = '/tmp/'+tempfile


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
	global recibido
	global tempfile
	# Filtramos solamente los paquetes que sean ICMP del tipo 'echo-request'( tipo 8 ) y que contengan la key que definimos
	if ICMP in pkt and pkt[ICMP].type == 8 and pkt[ICMP].load[0:8] == passwd:
		# Abrimos el archivo de destino y escribimos los datos recibidos
		f = open(archivo, 'a')
		data = pkt[ICMP].load[13:]
		
		
		# Verifico si es la primer parte de una serie o un paquete unico
		if (pkt[ICMP].load[12:13] == '0') or (pkt[ICMP].load[12:13] == '5'):
			print >>f,'[',pkt[ICMP].load[8:12],']: ', # Imprimo en el log el nombre del usuario
			print >>f, data,
		
		# Me fijo para loguear los datos que pertenecen a la parte intermedia o final
		elif (pkt[ICMP].load[12:13] == '1') or (pkt[ICMP].load[12:13] == '9'):
			print >>f,data,
		f.close()

		# Si es el ultimo paquete de una serie, o el unico mostramos los datos por pantalla
		if (pkt[ICMP].load[12:13] == '9') or (pkt[ICMP].load[12:13] == '5'):
			f = open(archivo, 'r')
			lastline = f.readlines()[-1] # Leo la ultima linea del log
			# Me fijo que el ultimo mensaje del log no sea mio (ya que vuelven los echo-reply con mi propio texto)
			if lastline[0:11] != '[ '+name+' ]:  ':
				print '					<< '+lastline[11:]
			f.close()
		
		
		
		# Si me llega una parte inicial de un archivo
		elif pkt[ICMP].load[12:13] == '4':
			data = pkt[ICMP].load[13:]
			
			f = open(recibido, 'a')
			print >>f, data,
			f.close()
		
		# Si me llega una parte intermedia de un archivo
		elif pkt[ICMP].load[12:13] == '2':
			data = pkt[ICMP].load[13:]

			f = open(recibido, 'a')
			print >>f, data,
			f.close()
			
		# Si me llega la ultima parte de un archivo
		elif pkt[ICMP].load[12:13] == '3':
			data = pkt[ICMP].load[13:]

			f = open(recibido, 'a')
			print >>f, data,
			f.close()
			print '\n\n\n		***[ Se completo la transferencia del archivo ]***'
			print '		        [ Transfer ID: '+tempfile+' ]\n\n\n'
			tempfile = str(int(time.time()))
			recibido = '/tmp/'+tempfile



# empezamos a escuchar en la interface definida por parametro
pkts = sniff(iface=interface, prn=monitor_callback)
