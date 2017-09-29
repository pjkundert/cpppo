#! /usr/bin/env python

# 
# Poll a PowerFlex 750 series at IP (or DNS name) "<hostname>" (default: localhost)
# 
# Multiple Threads are used to poll at differing rates, with occasional writes, all
# using to the same cpppo.server.enip.get_attribute 'proxy_simple' instance.
# 
#     python -m cpppo.server.enip.poll_example_many_with_write <hostname>
#
# To start a simple A-B Powerflex simulator on localhost suitable for polling:
# 
#     python -m cpppo.server.enip.poll_test
# 
import logging
import random
import sys
import time
import threading
import traceback

import cpppo
#cpppo.log_cfg['level'] = logging.DETAIL
logging.basicConfig( **cpppo.log_cfg )

from cpppo.history import timestamp # requires 'pip install pytz'
from cpppo.server.enip import poll
from cpppo.server.enip.ab import powerflex_750_series

address				= (sys.argv[1] if len( sys.argv ) > 1 else 'localhost', 44818)
targets				= {
     .5: [ "Output Frequency" ],
    1.0: [ "Motor Velocity", "Output Current" ],
    5.0: [ "Elapsed KwH" ],
   10.0: [ "Speed Units" ],
}
timeout				= .5
values				= {} # { <parameter>: (<timer>, <value>), ... }
failed				= [] # [ (<timer>, <exc>), ... ]

# Capture a timestamp with each event
def failure( exc ):
    failed.append( (cpppo.timer(),str(exc)) )

def process( p, v ):
    values[p]			= (cpppo.timer(),v)
process.done			= False

poller				= []
via				= powerflex_750_series( 
    host=address[0], port=address[1], timeout=timeout )
for cycle,params in targets.items():
    poller		       += [ threading.Thread( target=poll.run, kwargs={
        'via':		via,
        'cycle':	cycle,
        'process':	process,
        'failure':	failure,
        'params':	params,
    })]
    poller[-1].start()

# Monitor the values and failed containers (updated in another Thread)
try:
    while True:
        while values:
            par,(tmr,val)	= values.popitem()
            print( "%s: %-32s == %r" % ( timestamp( tmr ), par, val ))
        while failed:
            tmr,exc		= failed.pop( 0 )
            print( "%s: %s" %( timestamp( tmr ), exc ))
        time.sleep( .1 )
        # Every 2 seconds-ish, fall thru and update 'Motor Velocity'
        if random.randint( 0, 2*10-1 ):
            continue
        try:
            param		= 'Motor Velocity = (REAL)%s' % (
                round( random.uniform( 0, 100 ), 3 ))
            with via: # establish gateway, detects Exception (closing gateway)
                val,		= via.write(
                    via.parameter_substitution( param ), checking=True )
                print( "%s: %-32s == %s" % ( timestamp(), param, val ))
        except Exception as exc:
            logging.detail( "Exception writing Parameter: %s, %s", exc, traceback.format_exc() )
            failure( exc )
finally:
    process.done		= True
    for p in poller:
        p.join()
