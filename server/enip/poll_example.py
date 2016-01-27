#! /usr/bin/env python

# 
# Poll a PowerFlex 750 series at IP (or DNS name) "<hostname>" (default: localhost)
# 
#     poll_example.py <hostname>
#
import logging
import sys
import time
import threading

import cpppo
#cpppo.log_cfg['level'] = logging.DETAIL
logging.basicConfig( **cpppo.log_cfg )

from cpppo.history import timestamp # requires 'pip install pytz'
from cpppo.server.enip import poll
from cpppo.server.enip.ab import powerflex_750_series

address				= (sys.argv[1] if len( sys.argv ) > 1 else 'localhost', 44818)
params				= [ "Motor Velocity", "Output Current" ]
timeout				= .5
values				= {} # { <parameter>: (<timer>, <value>), ... }
failed				= [] # [ (<timer>, <exc>), ... ]

def failure( exc ):
    failed.append( (cpppo.timer(),str(exc)) )

def process( p, v ):
    values[p]			= (cpppo.timer(),v)
process.done			= False

poller				= threading.Thread(
    target=poll.poll, args=(powerflex_750_series,), kwargs={ 
        'address': 	address,
        'cycle':	1.0,
        'timeout':	0.5,
        'process':	process,
        'failure':	failure,
        'params':	params,
    })
poller.deamon			= True
poller.start()

# Monitor the values and failed dicts (updated in another Thread)
try:
    while True:
        while values:
            for par,(tmr,val) in [ values.popitem() ]:
                print( "%s: %16s == %r" % ( timestamp( tmr ), par, val ))
        while failed:
            for tmr,exc in [ failed.pop( 0 ) ]:
                print( "%s: %s" %( timestamp( tmr ), exc ))
        time.sleep( .1 )
finally:
    process.done		= True
    poller.join()
