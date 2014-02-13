#!/usr/bin/env python
'''
modbus_poll.py -- A Modbus PLC Poller

    Polls the specified registers from the target PLC, logging data changes.

OPTIONS

  --address <addr>[:port]	Address to bind to (default all, port 502)
  --reach   N                   Combine ranges of registers up N registers distant from each-other
  <begin>-<end>                 Ranges of registers to serve, and their initial value(s)


EXAMPLE

  modbus_poll.py --address localhost:7502 --reach 10 40001-40100 40120-40150

    Starts a simulated PLC serving Holding registers 40001-40100 == 0, on port 7502
    on interface 'localhost', which delays all responses for 2.5 seconds.

'''
import os
import sys
import traceback
import random
import time
import socket
import struct
import logging
import argparse

import cpppo
from cpppo.remote.plc_modbus import (poller_modbus, Defaults)

#---------------------------------------------------------------------------# 
# configure the service logging
#---------------------------------------------------------------------------# 

log 			= logging.getLogger( 'modbus_poll' )


def main():
    parser			= argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = """\

    Register range(s) and value(s) must be supplied:
    
      <begin>[-<end>]
    
    EXAMPLE
    
      modbus_poll --address localhost:7502 40001-40100
    
    """ )
    parser.add_argument( '-v', '--verbose',
                         default=0, action="count", help="Display logging information." )
    parser.add_argument('-l', '--log', 
                        type=str, default=None, help="Direct log output to the specified file" )
    parser.add_argument( '-a', '--address', default="0.0.0.0:502",
                         help="Default [interface][:port] to bind to (default: any, port 502)" )
    parser.add_argument( '-r', '--reach',	default=1,
                         help="Merge polls within <reach> registers of each-other" )
    parser.add_argument( '-R', '--rate',	default=1.0,
                         help="Target poll rate" )
    parser.add_argument( 'registers', nargs="+" )
    args			= parser.parse_args()
    
    # Deduce logging level and target file (if any)
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
    if args.log:
        cpppo.log_cfg['filename'] = args.log
    logging.basicConfig( **cpppo.log_cfg )

    # (INADDR_ANY) if only :port is supplied.  Port defaults to 502 if only
    # interface is supplied.  After this block, 'address' is always a tuple
    # like ("interface",502)
    address			= None
    if args.address:
        address			= args.address.split(':')
        assert 1 <= len( address ) <= 2
        address			= (
            str( address[0] ),
            int( address[1] ) if len( address ) > 1 else Defaults.Port )
        log.info( "--address '%s' produces address=%r" % ( args.address, address ))

    # Start the PLC poller

    poller			= poller_modbus(
        "Modbus/TCP", host=address[0], port=address[1], reach=int( args.reach ), rate=float( args.rate ))

    
    for r in args.registers:
        rng			= r.split('-')
        beg,cnt			= int(rng[0]), int(rng[1])-int(rng[0])+1 if len(rng) else 1
        for reg in range( beg, beg+cnt ):
            poller.poll( reg )
    
    load			= ''
    fail			= ''
    poll			= ''
    regs			= {}
    while True:
        loadcur			= "%.2f" % ( poller.load[0] if poller.load[0] else 0 )
        if loadcur != load:
            load		= loadcur
            logging.detail( "load: %s", loadcur )
        failcur			= ", ".join( [ ("%d-%d" % (b,b+c-1)) for b,c in poller.failing ] )
        pollcur			= ", ".join( [ ("%d-%d" % (b,b+c-1)) for b,c in poller.polling ] )
        if ( failcur != fail or pollcur != poll ):
            fail, poll		= failcur, pollcur
            logging.normal( "failing: %s, polling: %s", fail, poll )
        # log data changes
        for beg,cnt in poller.polling:
            for reg in range( beg, beg+cnt ):
                val		= poller.read( reg )
                old		= regs.get( reg ) # may be None
                if val != old:
                    logging.warning( "%5d == %5d (was: %s)" %( reg, val, old ))
                    regs[reg]	= val

        time.sleep( 1 )

if __name__ == "__main__":
    sys.exit( main() )
