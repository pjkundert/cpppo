from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
Example of using cpppo.server.enip EtherNet/IP CIP client API.

To see the List {Services, Interfaces, Identity} operations succeed, fire up:
    python -m cpppo.server.enip Tag=DINT[10]
"""
import argparse
import sys
import logging
import traceback

import cpppo
from cpppo.server import enip
from cpppo.server.enip import client

if __name__ == "__main__":
    ap				= argparse.ArgumentParser(
        description = "List Services (by default) on EtherNet/IP CIP device(s).",
        epilog = "" )
    ap.add_argument( '-v', '--verbose', action="count",
                     default=0, 
                     help="Display logging information." )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to bind to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
    ap.add_argument( '-u', '--udp', action='store_true',
                     default=False, 
                     help="Use UDP/IP queries (default: False)" )
    ap.add_argument( '-b', '--broadcast', action='store_true',
                     default=False, 
                     help="Allow multiple peers, and use of broadcast address (default: False)" )
    ap.add_argument( '-i', '--list-identity', action='store_true',
                     default=False, 
                     help="List Identity (default: False)" )
    ap.add_argument( '-I', '--list-interfaces', action='store_true',
                     default=False, 
                     help="List Interfaces (default: False)" )
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )
    ap
    args			= ap.parse_args()

    # Set up logging level (-v...) and --log <file>
    levelmap 			= {
        0: logging.WARNING,
        1: logging.NORMAL,
        2: logging.DETAIL,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )

    logging.basicConfig( **cpppo.log_cfg )

    addr			= args.address.split(':')
    assert 1 <= len( addr ) <= 2, "Invalid --address [<interface>]:[<port>}: %s" % args.address
    addr			= ( str( addr[0] ) if addr[0] else enip.address[0],
                                    int( addr[1] ) if len( addr ) > 1 and addr[1] else enip.address[1] )
    timeout			= float( args.timeout )

    failures			= 0
    try:
        with client.connector( host=addr[0], port=addr[1], timeout=timeout,
                               udp=args.udp, broadcast=args.broadcast ) as connection:
            connection.list_services()
            if args.list_identity:
                connection.list_identity()
            if args.list_interfaces:
                connection.list_interfaces()
            connection.shutdown() # starts a client-initiated clean shutdown for TCP/IP
            while True:
                response,ela	= client.await( connection, timeout=timeout )
                if response:
                    print( enip.enip_format( response ))
                else:
                    break # No response (None) w'in timeout or EOF ({})

    except Exception as exc:
        failures		= 1
        logging.warning( "Failed to receive List Services reply: %s\n%s", exc, traceback.format_exc() )

    sys.exit( 1 if failures else 0 )
    
