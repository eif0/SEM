#!/usr/bin/python

#importamos librerias
import sys
import getopt
import logging
from scapy.all import *

# definimos que solamente se debe alertar ante un error
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)



# levantamos los parametros que se le pasan al paquete
opts, extra = getopt.getopt(sys.argv[1:], 't:d:p:', ['target=', 'data=', 'password=' ])

# seteo los valores por defecto en caso de que no los setee el usuario en los parametros
target='127.0.0.1'
data='Testing Covert Channel...'
passwd='20121357' # con esta clave vamos a diferenciar nuestros paquetes de los otros paquetes ICMP que van a llegar al host


# levanta los valores de los parametros
for code,param in opts:
  if code in ['-t','--target']:
     target = param
  elif code in ['-d','--data']:
     data = param
  elif code in ['-p','--password']:
     passwd = param

data = data+'\n'



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
count = (len(data)/msgsize)+1
# entramos en un bucle en el cual vamos a enviar un paquete para cada trozo de datos
for a in range(0, count):
	print "							[%s/%s]" %(a + 1, count)
	payload = passwd + data[first:last]
	# ensamblamos el paquete (las capas que no definimos son definidas automaticamente por scapy)
	pkt = l3/l4/payload
	# enviamos el paquete
	a = sr(pkt, verbose = 0, retry = 0, timeout = 1)
	first += msgsize
	last += msgsize
print "							[ok]"
