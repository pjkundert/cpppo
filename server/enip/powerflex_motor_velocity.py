# 
# Write a Motor Velocity to an AB PowerFlex AC Drive Controller
# 
#     python -m cpppo.server.enip.powerflex_motor_velocity @localhost 123.45
# 
# To start a simulator (a partial AB PowerFlex) on localhost suitable for writing:
# 
#     python -m cpppo.server.enip.poll_test
# 
import logging
import sys
import time
import traceback

import cpppo
#cpppo.log_cfg['level'] = logging.DETAIL
logging.basicConfig( **cpppo.log_cfg )

#from cpppo.server.enip.get_attribute import proxy_simple as device # MicroLogix
#from cpppo.server.enip.get_attribute import proxy as device	    # ControlLogix
from cpppo.server.enip.ab import powerflex_750_series as device	   # PowerFlex 750

# Optionally specify Powerflex DNS name or IP address, prefixed with '@':
host				= 'localhost'
if len( sys.argv ) > 1 and sys.argv[1].startswith( '@' ):
    host			= sys.argv.pop( 1 )[1:]

# Optionally specify velocity; defaults to 0:
velocity			= 0
if len( sys.argv ) > 1:
    velocity			= float( sys.argv.pop( 1 ))

param				= 'Motor Velocity = (REAL)%s' % ( velocity )
try:
    via				= device( host=host )
    with via: # establish gateway, detects Exception (closing gateway)
	val,			= via.write(
	    via.parameter_substitution( param ), checking=True )
    print( "%s: %-32s == %s" % ( time.ctime(), param, val ))
except Exception as exc:
    logging.detail( "Exception writing Parameter %s: %s, %s",
	param, exc, traceback.format_exc() )
    sys.exit( 1 )
