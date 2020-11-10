# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division, unicode_literals
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import contextlib
import json
import logging
import os
import platform
import pytest
import random
import socket
import traceback

import cpppo
from   cpppo        import misc
from   cpppo.server import network, tnet, tnetstrings

#logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger( "tnet.cli")
#log.setLevel( logging.DEBUG )

def test_tnet_machinery():
    # parsing integers
    path			= "machinery"
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'123:' )
    with cpppo.integer_bytes( name="SIZE", context="size", terminal=True ) as SIZE:
        with contextlib.closing( SIZE.run( source=source, data=data, path=path )) as engine:
            for m,s in engine:
                if s is None:
                    break
        log.info( "After SIZE: %r", data )
        assert SIZE.terminal
    assert data.machinery.size == 123

    # repeat, limited by parent context's 'value' in data
    source.chain( b"abc" * 123 )
    with tnet.data_parser( name="DATA", context="data", repeat="..size" ) as DATA:
        with contextlib.closing( DATA.run( source=source, data=data, path=path )) as engine:
            for m,s in engine:
                if s is None:
                    break
        log.info( "After DATA: %r", data )
    

def test_tnet_string():
    testvec			= [
        "The π character is called pi",
    ]

    successes			= 0
    for t in testvec:
      with tnet.tnet_machine() as tnsmach:
        path			= "test_tnet"
        tns			= tnetstrings.dump( t )

        data			= cpppo.dotdict()
        source			= cpppo.peekable( tns )

        for mch, sta in tnsmach.run( source=source, data=data, path=path ):
            log.info( "%s byte %5d: data: %r",
                      misc.centeraxis( mch, 25, clip=True ), source.sent, data )
            log.info("Parsing tnetstring:\n%s\n%s (byte %d)", repr(bytes(tns)),
                     '-' * (len(repr(bytes(tns[:source.sent])))-1) + '^', source.sent )
        if sta is None or not sta.terminal:
            # Ended in a non-terminal state
            log.info( "%s byte %5d: failure: data: %r; Not terminal; unrecognized", 
                      misc.centeraxis( tnsmach, 25, clip=True ), source.sent, data )
        else:
            # Ended in a terminal state.
            if source.peek() is None:
                log.info( "%s byte %5d: success: data: %r", 
                          misc.centeraxis( tnsmach, 25, clip=True ), source.sent, data )
                successes      += 1
            else:
                log.info( "%s byte %5d: failure: data: %r; Terminal, but TNET string wasn't consumed",
                          misc.centeraxis( tnsmach, 25, clip=True ), source.sent, data )

    assert successes == len( testvec )


client_count			= 15
charrange, chardelay		= (2,10), .01	# split/delay outgoing msgs
draindelay			= 2.0  		# long in case server slow, but immediately upon EOF

tnet_cli_kwds			= {
    "tests": [
        1,
        "abcdefghijklmnopqrstuvwxyz",
        str("a"),
        9999999,
        None,
    ],
}

def tnet_cli( number, tests=None ):
    log.info( "%3d client connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( tnet.address )
    log.info( "%3d client connected", number )
        
    rcvd			= ''
    try:
        eof			= False
        for t in tests:
            msg			= tnetstrings.dump( t )

            while len( msg ) and not eof:
                out		= min( len( msg ), random.randrange( *charrange ))
                log.info( "Tnet Client %3d send: %5d/%5d: %s", number, out, len( msg ),
                          cpppo.reprlib.repr( msg[:out] ))
                conn.sendall( msg[:out] )
                msg		= msg[out:]

                # Await inter-block chardelay if output remains, otherwise await
                # final response before dropping out to shutdown/drain/close.
                # If we drop out immediately and send a socket.shutdown, it'll
                # sometimes deliver a reset to the server end of the socket,
                # before delivering the last of the data.
                rpy		= network.recv( conn, timeout=chardelay if len( msg ) else draindelay )
                if rpy is not None:
                    eof		= not len( rpy )
                    log.info( "Tnet Client %3d recv: %5d: %s", number, len( rpy ),
                              "EOF" if eof else cpppo.reprlib.repr( rpy ))
                    rcvd       += rpy.decode( "utf-8" )
            if eof:
                break

        log.normal( "Tnet Client %3d done; %s", number, "due to EOF" if eof else "normal termination" )

    except KeyboardInterrupt as exc:
        log.normal( "%3d client terminated: %r", number, exc )
    except Exception as exc:
        log.warning( "%3d client failed: %r\n%s", number, exc, traceback.format_exc() )
    finally:
        # One or more packets may be in flight; wait 'til we timeout/EOF
        rpy			= network.drain( conn, timeout=draindelay )
        log.info( "Tnet Client %3d drain %5d: %s", number, len( rpy ) if rpy is not None else 0,
                  cpppo.reprlib.repr( rpy ))
        if rpy is not None:
            rcvd   	       += rpy.decode( "utf-8" )

    # Count the number of successfully matched JSON decodes
    successes			= 0
    i 				= 0
    for i, (t, r) in enumerate( zip( tests, rcvd.split( '\n\n' ))):
        e			= json.dumps( t )
        log.info( "%3d test #%3d: %32s --> %s", number, i, cpppo.reprlib.repr( t ), cpppo.reprlib.repr( e ))
        if r == e:
            successes	       += 1
        else:
            log.warning( "%3d test #%3d: %32s got %s", number, i, cpppo.reprlib.repr( t ), cpppo.reprlib.repr( e ))
        
    failed			= successes != len( tests )
    if failed:
        log.warning( "%3d client failed: %d/%d tests succeeded", number, successes, len( tests ))
    
    log.info( "%3d client exited", number )
    return failed


tnet_svr_kwds			= {
    "argv": [ "-vv" ]
}


def tnet_bench():
    logging.getLogger().setLevel(logging.INFO)
    failed			= cpppo.server.network.bench(
        server_func=tnet.main,
        server_kwds=tnet_svr_kwds,
        client_func=tnet_cli, client_count=client_count, 
        client_kwds=tnet_cli_kwds )

    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


def test_tnet_bench():
    assert not tnet_bench(), "One or more tnet_banch clients reported failure"
