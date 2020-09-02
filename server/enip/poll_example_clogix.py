#! /usr/bin/env python

# 
# Poll a PowerFlex 750 series at IP (or DNS name) "<hostname>" (default: localhost)
# 
#     python -m cpppo.server.enip.poll_example <hostname>
# 
# To start a simulator on localhost suitable for polling:
# 
#     python -m cpppo.server.enip.poll_test
# 

import logging
import sys
import time
import threading

import cpppo
cpppo.log_cfg['level'] = logging.NORMAL
logging.basicConfig( **cpppo.log_cfg )

from cpppo.server.enip import poll
#from cpppo.server.enip.get_attribute import proxy_simple as device # MicroLogix
from cpppo.server.enip.get_attribute import proxy_connected as device # ControlLogix
#from cpppo.server.enip.ab import powerflex_750_series as device # PowerFlex 750

# Device IP in 1st arg, or 'localhost' (run: python -m cpppo.server.enip.poll_test)
hostname			= sys.argv[1] if len( sys.argv ) > 1 else 'localhost'

# Parameters valid for device; for *Logix, others, try:
params				= []
params			       += [('@1/1/1','INT'),('@1/1/7', ('SSTRING', 'USINT'))]
params			       += [ "A63FGRDT", "T455ADT", "blah de blah" ]

def failure( exc ):
    failure.string.append( str(exc) )
failure.string			= [] # [ <exc>, ... ]

def process( par, val ):
    process.values[par]		= val
process.done			= False
process.values			= {} # { <parameter>: <value>, ... }

poller				= threading.Thread(
    target=poll.poll, kwargs={
        'proxy_class':  device,
        'address': 	(hostname, 44818),
        'cycle':	1.0,
        'timeout':	0.5,
        'process':	process,
        'failure':	failure,
        'params':	params,
    })
poller.start()

# Monitor the process.values {} and failure.string [] (updated in another Thread)
try:
    while True:
        while process.values:
            par,val		= process.values.popitem()
            print( "%s: %16s == %r" % ( time.ctime(), par, val ))
        while failure.string:
            exc			= failure.string.pop( 0 )
            print( "%s: %s" %( time.ctime(), exc ))
        time.sleep( .1 )
finally:
    process.done		= True
    poller.join()
