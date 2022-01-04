# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division, unicode_literals
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import logging
import socket
import time

from .network import soak, bench
from ..dotdict import dotdict, apidict

log				= logging.getLogger( "soak" )

def test_soak_basic():
    """Setting buffering=1 doesn't appear to enable line-buffering.  In order to allow read() to return
    whatever input is available at the moment, non-blocking must be specified, and the emitter must
    force a sys.stdout.flush().

    """
    r,w				= socket.socketpair()
    wf				= w.makefile( "w" )
    r.setblocking(False)
    rf				= r.makefile( "r" )
    wf.write('abc\n')
    wf.flush()
    assert rf.read() == 'abc\n'


def bench_cli( n, address=None ):
    log.normal( "Client {} connecting to {!r}".format( n, address ))
    success			= address == ("127.0.0.1", 12345)
    return not success


def bench_srv( server ):
    import sys
    address			= "127.0.0.1",12345

    # Transmit address on stdout and via control dict.
    print( "Server TCP address = {}:{}".format( *address ))
    sys.stdout.flush()
    control			= server.get( 'control' )
    if control:
        control['address']	= address

    while not control or not control.get( 'done' ):
        print( "control {}: {}".format( server.get( 'control' ).__class__, server.get( 'control' )))
        sys.stdout.flush()
        time.sleep( .5 )
    print( "Server TCP address = {}:{}: done signaled".format( *address ))

    
bench_srv_kwds			= dict(
    server	= dotdict(
        control	= apidict(
            timeout	= 1.0,
            done	= False,
        ),
    )
)

def test_soak_Process():
    from multiprocessing import Process as server_cls
    bench(
        server_func		= bench_srv,
        server_kwds		= bench_srv_kwds,
        client_func		= bench_cli,
        client_count		= 10,
        client_max		= 5,
        client_kwds		= None,
        address_delay		= 5.0,
        server_cls		= server_cls,
    )

def test_soak_Thread():
    from threading import Thread as server_cls
    bench(
        server_func		= bench_srv,
        server_kwds		= bench_srv_kwds,
        client_func		= bench_cli,
        client_count		= 10,
        client_max		= 5,
        client_kwds		= None,
        address_delay		= 5.0,
        server_cls		= server_cls,
    )
