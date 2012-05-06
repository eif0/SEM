#!/usr/bin/python

import os
import getopt
import sys


def encoder(source,dest):
	code = os.system('base64 '+source+' > '+dest)

source = 'test.png'
dest = 'encodeado.txt'
	
	
encoder(source,dest)
print 'list0!'
