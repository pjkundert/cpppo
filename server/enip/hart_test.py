from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import ast
import errno
import logging
import os
import re
import socket
import sys
import time
import threading

import pytest

if __name__ == "__main__":
    if __package__ is None:
        __package__	= "cpppo.server.enip"
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    logging.getLogger().setLevel( logging.DETAIL )

import cpppo
from cpppo.dotdict import dotdict
from cpppo.misc import timer, near
from cpppo.modbus_test import nonblocking_command
from cpppo.server import enip, network
from cpppo.server.enip import poll, client

from cpppo.server.enip.get_attribute import proxy
from cpppo.server.enip.hart import HART, proxy_hart # Class, proxy

def start_hart_simulator( *options, **kwds ):
    """Start a simple EtherNet/IP CIP simulator w/ a HART I/O module (execute this file as __main__),
    optionally with Tag=<type>[<size>] (or other) positional arguments appended to the command-line.
    Return the command-line used, and the detected (host,port) address bound.  Looks for something
    like:

        11-11 11:46:16.301     7fff7a619000 network  NORMAL   server_mai enip_srv server PID [ 7573] running on ('', 44818)

    containing a repr of the (<host>,<port>) tuple.  Recover this address using the safe ast.literal_eval.

    At least one positional parameter containing a Tag=<type>[<size>] must be provided.

    """
    command                     = nonblocking_command( [
        'python',
        os.path.abspath( __file__ ),
        '-vvv',
        '--log', 'hart_test.log',
    ] + list( options ))

    # For python 2/3 compatibility (can't mix positional wildcard, keyword parameters in Python 2)
    CMD_WAIT			= kwds.pop( 'CMD_WAIT', 10.0 )
    CMD_LATENCY			= kwds.pop( 'CMD_LATENCY', 0.1 )
    assert not kwds, "Unrecognized keyword parameter: %s" % ( ", ".join( kwds ))

    begun			= timer()
    address			= None
    data			= ''
    while address is None and timer() - begun < CMD_WAIT:
        # On Python2, socket will raise IOError/EAGAIN; on Python3 may return None 'til command started.
        try:
            raw			= command.stdout.read()
            logging.debug( "Socket received: %r", raw)
            if raw:
                data  	       += raw.decode( 'utf-8' )
        except IOError as exc:
            logging.debug( "Socket blocking...")
            assert exc.errno == errno.EAGAIN, "Expected only Non-blocking IOError"
        except Exception as exc:
            logging.warning("Socket read return Exception: %s", exc)
        if not data:
            time.sleep( CMD_LATENCY )
        while data.find( '\n' ) >= 0:
            line,data		= data.split( '\n', 1 )
            logging.info( "%s", line )
            m			= re.search( "running on (\([^)]*\))", line )
            if m:
                address		= ast.literal_eval( m.group(1).strip() )
                logging.normal( "EtherNet/IP CIP Simulator started after %7.3fs on %s:%d",
                                    timer() - begun, address[0], address[1] )
                break
    return command,address


@pytest.fixture( scope="module" )
def simulated_hart_gateway():
    return start_hart_simulator( 'SCADA=INT[100]' )


def test_hart_packet():
    """
    0000   00 1d 9c c9 3e 2a b0 5a da b4 f9 1f 08 00 45 00
    0010   00 66 30 3f 40 00 80 06 00 00 64 64 66 01 64 64
    0020   66 0a c4 50 af 12 f7 0d 5f c5 44 a0 85 e2 50 18
    0030   00 fb 95 2c 00 00 6f 00 26 00 04 00 31 00 00 00
    0040   00 00 6c 74 00 00 88 f9 59 07 00 00 00 00 00 00
    0050   00 00 08 00 02 00 00 00 00 00 b2 00 16 00 52 02
    0060   20 06 24 01 05 f7 08 00 4b 03 21 00 5d 03 24 08
    0070   01 00 01 02
    """

def test_hart_simple( simulated_hart_gateway ):
    hart_kwds			= dict(
        timeout		= 15.0,
        depth		= 5,		# max. requests in-flight
        multiple	= 0#500,		# max. bytes of req/rpy per Multiple Service Packet
    )

    logging.getLogger().setLevel( logging.INFO )
    command,address             = simulated_hart_gateway
    try:
        assert address, "Unable to detect HART EtherNet/IP CIP Gateway IP address"
        hio				= client.connector( host=address[0], port=address[1] )
        operations		= [{
            "method":		"service_code",
            "code":		HART.RD_VAR_REQ,
            "data":		[],			# No payload
            "data_size":	2+36,			# Known response size: command,status,<payload>
            "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
        }]
        

        # Now, use the underlying client.connector to issue a HART "Read Dynamic Variable" Service Code
        for PV in ( 0.0, 1.23, 0.0 ):
            with hio:
                results			= []
                failures		= 0
                for idx,dsc,req,rpy,sts,val in hio.pipeline(
                        operations=operations, **hart_kwds ):
                    logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))
                    if not val:
                        logging.warning( "Client %s harvested %d/%d results; failed request: %s",
                                         hio, len( results ), len( operations ), rpy )
                        failures       += 1
                    results.append( (dsc,val,rpy) )
                assert not failures
                rpylast	       		= results[-1][-1]
                #assert near( rpylast.read_var.PV, PV )

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise

# 
# python hart_test.py -- A *Logix w/ a 16-channel HART Interface Card
# 
def main( **kwds ):
    """Set up a *Logix w/ a 16-channel HART Interface card, eg. 1756-IF8H"""

    enip.config_files 	       += [ __file__.replace( '.py', '.cfg' ) ]

    HART( name="HART Channels", instance_id=0 ) # Class Object
    for i in range( 16 ):
        HART( name="HART Channel %d" % i, instance_id=i + 1 )

    # Establish Identity and TCPIP objects w/ some custom data for the test, from a config file
    return enip.main( argv=sys.argv[1:] )


if __name__ == "__main__":
    sys.exit( main() )
