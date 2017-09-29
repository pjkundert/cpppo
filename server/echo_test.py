from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import logging
import os
import random
import socket
import traceback

import cpppo
from   cpppo.server import network, echo

log				= logging.getLogger( "echo.cli")

client_count			= 15
charrange, chardelay		= (2,10), .01	# split/delay outgoing msgs
draindelay			= 5.   		# long in case server slow, but immediately upon EOF

echo_cli_kwds			= {
	'reps':	10,
}


def echo_cli( number, reps ):
    log.normal( "Echo Client %3d connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( echo.address )
    log.detail( "Echo Client %3d connected", number )
        
    sent			= b''
    rcvd			= b''
    try:
        # Send messages and collect replies 'til done (or incoming EOF).  Then, shut down 
        # outgoing half of socket to drain server and shut down server.
        eof			= False
        for r in range( reps ):
            msg			= ("Client %3d, rep %d\r\n" % ( number, r )).encode()
            log.detail("Echo Client %3d send: %5d: %s", number, len( msg ), cpppo.reprlib.repr( msg ))
            sent	       += msg

            while len( msg ) and not eof:
                out		= min( len( msg ), random.randrange( *charrange ))
                conn.send( msg[:out] )
                msg		= msg[out:]

                # Await inter-block chardelay if output remains, otherwise await final response
                # before dropping out to shutdown/drain/close.  If we drop out immediately and send
                # a socket.shutdown, it'll sometimes deliver a reset to the server end of the
                # socket, before delivering the last of the data.
                rpy		= network.recv( conn, timeout=chardelay if len( msg ) else draindelay )
                if rpy is not None:
                    eof		= not len( rpy )
                    log.detail( "Echo Client %3d recv: %5d: %s", number, len( rpy ),
                              "EOF" if eof else cpppo.reprlib.repr( rpy ))
                    rcvd       += rpy
            if eof:
                break

        log.normal( "Echo Client %3d done; %s", number, "due to EOF" if eof else "normal termination" )

    except KeyboardInterrupt as exc:
        log.warning( "Echo Client %3d terminated: %r", number, exc )
    except Exception as exc:
        log.warning( "Echo Client %3d failed: %r\n%s", number, exc, traceback.format_exc() )
    finally:
        # One or more packets may be in flight; wait 'til we timeout/EOF.  This shuts down conn.
        rpy			= network.drain( conn, timeout=draindelay )
        log.info( "Echo Client %3d drain %5d: %s", number, len( rpy ) if rpy is not None else 0,
                  cpppo.reprlib.repr( rpy ))
        if rpy is not None:
            rcvd   	       += rpy

    # Count the number of success/failures reported by the Echo client threads
    failed			= not ( rcvd == sent )
    if failed:
        log.warning( "Echo Client %3d failed: %s != %s sent", number, cpppo.reprlib.repr( rcvd ),
                     cpppo.reprlib.repr( sent ))
    
    log.info( "Echo Client %3d exited", number )
    return failed


def test_echo_bench():
    failed			= network.bench( server_func=echo.main,
                                                 client_func=echo_cli, client_count=client_count, 
                                                 client_kwds=echo_cli_kwds )
    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


if __name__ == "__main__":
    test_echo_bench()
