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
from   cpppo        import misc
from   cpppo.server import *

from   .            import tnetstrings # reference implementation

logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger( "tnet.cli")


def test_tnet_machinery():
    # parsing integers
    path			= "machinery"
    SIZE			= tnet.integer_parser( name="SIZE", context="size")
    data			= cpppo.dotdict()
    source			= cpppo.chainable( "123" )
    for m,s in SIZE.run( source=source, data=data, path=path ):
        if s is None:
            break
    log.info( "After SIZE: %r", data )
    assert s and s.terminal
    assert data.machinery.size == 123

    # repeat, limited by parent context's 'value' in data
    DATA			= tnet.data_parser(
        name="DATA", context="data", repeat="..size" )
    source.chain( b"abc" * 123 )
    for m,s in DATA.run( source=source, data=data, path=path ):
        if s is None:
            break
    log.info( "After DATA: %r", data )
    

def test_tnet():
    tv				= [
        "Hello, world!",
        None,
    ]

    for t in tv:
        tns			= tnetstrings.dump( t )

        tnsmach			= tnet.tnet_machine()
        data			= cpppo.dotdict()
        source			= cpppo.peekable( tns )

        sequence		= tnsmach.run( source=source, data=data, path="decode" )

        try:
            for mch, sta in sequence:
                log.info( "%s byte %5d: data: %r",
                          misc.centeraxis( mch, 25, clip=True ), source.sent, data )
                if sta is None:
                    break
            if sta:
                log.info( "%s byte %5d: data: %r", 
                          misc.centeraxis( echo_line, 25, clip=True ), source.sent, data )
        finally:
            log.info("Parsing tnetstring:\n%s\n%s", tns, '-' * (source.sent-1) + '^')


'''
clisuccess			= {}		# One entry per client number expected
clicount, clireps		= 5, 10
charrange, chardelay		= (2,10), .01	# split/delay outgoing msgs
draindelay			= 1   		# long in case server slow, but immediately upon EOF

def tnet_cli( number, reps ):
    global clisuccess
    log.info( "%3d tnet client connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( tnet.address )
    log.info( "%3d tnet client connected", number )
        
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


def test_tnet():
    # Tries to start  a server; will fail if one already bound to port
    log.info( "Server startup..." )
    server			= multiprocessing.Process( target=tnet.main )
    server.start()
    time.sleep( .25 )

    try:
        log.info( "Client tests: %d", clicount )
        threads			= []
        for i in range( clicount ):
            threads.append( threading.Thread( target=tnet_cli, args=(i,clireps) ))
        
        [ t.start() for t in threads ]
        
        [ t.join() for t in threads ]
        assert len( clisuccess ) == clicount
        failures		= clicount - sum( clisuccess.values() )
        assert not failures, "%d tnet clients reported mismatching results" % failures

        log.info( "Client tests done" )

    finally:
        server.terminate()
        server.join()
'''

if __name__ == "__main__":
    # test_echo()
    test_tnet()
