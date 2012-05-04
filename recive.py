#!/usr/bin/python

#importamos librerias
import sys
import getopt
import logging

# definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *



opts, extra = getopt.getopt(sys.argv[1:], 'n:i:f:p:', ['name=', 'interface=', 'file=', 'password=' ])

# Seteo los valores por defecto en caso de que no los setee el usuario en los parametros
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
     
     
# definimos la funcion que se va a llamar en la llegada de cada paquete
def monitor_callback(pkt):
	# filtramos solamente los paquetes que sean ICMP del tipo 'echo-request'( tipo 8 ) y que contengan la clave que definimos
	if ICMP in pkt and pkt[ICMP].type == 8 and pkt[ICMP].load[0:8] == passwd:
		# abrimos el archivo de destino y escribimos los datos recibidos
		f = open(archivo, 'a')
		data = pkt[ICMP].load[13:]
		if pkt[ICMP].load[12:13] == '0':
			print >>f,'[',pkt[ICMP].load[8:12],']: ',
			print >>f, data,
		else:
			print >>f,data,
		f.close()
#		print '			<< '+data

# empezamos a escuchar en la interface definida por parametro
pkts = sniff(iface=interface, prn=monitor_callback)
