#!/usr/bin/python
#
# Script para testear el envío de mensajes
# Toma como parámetros: -t (target) -d (datos a enviar, entre comillas) -p (key de identificacion)
#

# importamos librerias
import sys
import getopt
import logging

# definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# levantamos los parametros que se le pasan al paquete
opts, extra = getopt.getopt(sys.argv[1:], 't:d:p:', ['target=', 'data=', 'password=' ])

# seteo los valores por defecto en caso de que no los setee el usuario en los parametros
target='127.0.0.1'
data='Testing Cover Channel...'
passwd='20121357' # con esta clave vamos a diferenciar nuestros paquetes de los otros paquetes ICMP que van a llegar al host


# levantamos lo que pasamos por parametro
for code,param in opts:
  if code in ['-t','--target']:
     target = param
  elif code in ['-d','--data']:
     data = param
  elif code in ['-p','--password']:
     passwd = param

# agrego salto de linea al mensaje
data = data+'\n' 

# a partir de aca empieza el armado del paquete y el envío

# construimos la capa 3 del paquete (IP)
l3 = IP()
l3.dst = target

# construimos la capa 4 del paquete (ICMP)
l4 = ICMP()

# definimos el resto de las variables
msgsize = 12 # como vamos a dividir el mensaje en partes, aca definimos el tamano de cada parte
# las variables (first) (last) (count) las utilizamos para el proceso de corte y envío del paquete
first = 0
last = (msgsize)
count = (len(data)/msgsize)+1
# entramos en un bucle en el cual vamos a enviar un paquete para cada parte de los datos
print "							[ %s : " %(count),
for a in range(0, count):
	print "%s " %(a + 1),
	payload = passwd + data[first:last]
	# ensamblamos el paquete
	# las capas que no definimos son definidas automaticamente por scapy
	pkt = l3/l4/payload
	# enviamos el paquete
	a = sr(pkt, verbose = 0, retry = 0, timeout = 1)
	first += msgsize
	last += msgsize
print ']',
