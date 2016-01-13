from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

try:
    from future_builtins import zip
except ImportError:
    pass # already available in Python3

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
Example of using cpppo.server.enip EtherNet/IP CIP client API.

To see the Tag operations succeed, fire up:
    python -m cpppo.server.enip Tag=DINT[10]
"""
import sys
import logging
import traceback

import cpppo
from cpppo.server import enip
from cpppo.server.enip import address, client

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )
    #logging.getLogger().setLevel(logging.INFO)
    host			= 'localhost'	# Controller IP address
    port			= address[1]	# default is port 44818
    depth			= 1		# Allow 1 transaction in-flight
    multiple			= 0		# Don't use Multiple Service Packet
    fragment			= False		# Don't force Read/Write Tag Fragmented
    timeout			= 1.0		# Any PLC I/O fails if it takes > 1s
    printing			= True		# Print a summary of I/O
    tags			= ["Tag[0-9]+16=(DINT)4,5,6,7,8,9", "@0x2/1/1", "Tag[3-5]"]

    failures			= 0
    try:
        with client.connector( host=host, port=port, timeout=timeout ) as connection:
            connection.list_services()
            response		= next( connection )
            print( enip.enip_format( response ))
    except Exception as exc:
        failures		= 1
        logging.warning( "Failed to receive List Services reply: %s\n%s", exc, traceback.format_exc() )

    sys.exit( 1 if failures else 0 )
    
