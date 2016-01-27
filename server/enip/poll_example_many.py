#! /usr/bin/env python

# 
# Poll a PowerFlex 750 series at IP (or DNS name) "<hostname>" (default: localhost)
# 
#     poll_example_many.py <hostname>
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
targets				= {
     .5: [ "Output Frequency" ],
    1.0: [ "Motor Velocity", "Output Current" ],
    5.0: [ "Elapsed KwH" ],
   10.0: [ "Speed Units" ],
}
timeout				= .5
values				= {} # { <parameter>: (<timer>, <value>), ... }
failed				= [] # [ (<timer>, <exc>), ... ]

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
    poller[-1].deamon		= True
    poller[-1].start()

# Monitor the values and failed containers (updated in another Thread)
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
    for p in poller:
        p.join()

    '''
    # See if there are any interesting memory leaks
    import objgraph
    objgraph.show_most_common_types()
    objs = objgraph.by_type("dict")[:100]
    objgraph.show_backrefs( objs, max_depth=15, highlight=lambda v: v in objs,
                            filename='cpppo.png' )
    '''
