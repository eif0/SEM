#!/usr/bin/python

import subprocess
import sys

resul = subprocess.Popen(['python', 'sendfile.py','--encode=hola'])
if resul == '__hola__':
	print 'bien'
else:
	print 'mal'
