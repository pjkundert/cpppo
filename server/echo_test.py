from __future__ import absolute_import
from __future__ import print_function

import logging
import multiprocessing
import os
import random
import socket
import sys
import threading
import time
import traceback

try:
    from reprlib import repr as repr
except ImportError:
    from repr import repr as repr

if __name__ == "__main__" and __package__ is None:
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import cpppo
from   cpppo.server import *

logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger( "echo.cli")


clisuccess			= {}		# One entry per client number expected
clicount, clireps		= 5, 10
charrange, chardelay		= (2,10), .01	# split/delay outgoing msgs
draindelay			= 1   		# long in case server slow, but immediately upon EOF


def echo_cli( number, reps ):
    global clisuccess
    log.info( "%3d echo client connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( echo.address )
    log.info( "%3d echo client connected", number )
        
    sent			= b''
    rcvd			= b''
    try:
        for r in range( reps ):
            msg			= ("Client %3d, rep %d\r\n" % ( number, r )).encode()
            log.info("%3d echo send: %5d: %s", number, len( msg ), repr( msg ))
            sent	       += msg
            while msg:
                out		= min( len( msg ), random.randrange( *charrange ))
                conn.send( msg[:out] )
                msg		= msg[out:]

                # Await inter-block chardelay if output remains, otherwise await
                # final response before dropping out to shutdown/drain/close.
                # If we drop out immediately and send a socket.shutdown, it'll
                # sometimes deliver a reset to the server end of the socket,
                # before delivering the last of the data.
                rpy		= echo.recv( conn, timeout=chardelay if msg else draindelay )
                if rpy is not None:
                    log.info("%3d echo recv: %5d: %s", number, len( rpy ), repr( rpy ) if rpy else "EOF" )
                    if not rpy:
                        raise Exception( "Server closed connection" )
                    rcvd       += rpy

    except KeyboardInterrupt as exc:
        log.warning( "%3d echo client terminated: %r", number, exc )
    except Exception as exc:
        log.warning( "%3d echo client failed: %r\n%s", number, exc, traceback.format_exc() )
    finally:
        # One or more packets may be in flight; wait 'til we timeout/EOF
        rpy			= True
        while rpy: # neither None (timeout) nor b'' (EOF)
            rpy			= echo.drain( conn, timeout=draindelay )
            if rpy is not None:
                log.info("%3d echo drain %5d: %s", number, len( rpy ), repr( rpy ) if rpy else "EOF" )
                rcvd   	       += rpy

    # Count the number of success/failures reported by the Echo client threads
    success			= ( rcvd == sent )
    clisuccess[number]		= success
    if not success:
        log.warning( "%3d echo client failed: %s != %s sent", number, repr( rcvd ), repr( sent ))
    
    log.info( "%3d echo client exited", number )


def test_echo():
    # Tries to start  a server; will fail if one already bound to port
    log.info( "Server startup..." )
    server			= multiprocessing.Process( target=echo.main )
    server.start()
    time.sleep( .25 )

    try:
        log.info( "Client tests: %d", clicount )
        threads			= []
        for i in range( clicount ):
            threads.append( threading.Thread( target=echo_cli, args=(i,clireps) ))
        
        [ t.start() for t in threads ]
        
        [ t.join() for t in threads ]
        assert len( clisuccess ) == clicount
        failures		= clicount - sum( clisuccess.values() )
        assert not failures, "%d Echo clients reported mismatching results" % failures

        log.info( "Client tests done" )

    finally:
        server.terminate()
        server.join()

if __name__ == "__main__":
    test_echo()
