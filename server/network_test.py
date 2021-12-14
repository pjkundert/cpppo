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
    log.normal( "Client {} connecting to {}".format( n, address ))
    success			= address == ("localhost", 12345)
    return not success


def bench_srv( server ):
    import sys
    print( "Server TCP address = {}:{}".format( "localhost", 12345 ))
    sys.stdout.flush()
    while not server.control.done:
        time.sleep( .1 )

    
bench_srv_kwds			= dict(
    server	= dotdict(
        control	= apidict(
            timeout	= 1.0,
            done	= False,
        ),
    )
)


def test_soak():
    bench(
        server_func		= bench_srv,
        server_kwds		= bench_srv_kwds,
        client_func		= bench_cli,
        client_count		= 10,
        client_max		= 5,
        client_kwds		= None,
        address_delay		= 5.0
    )
