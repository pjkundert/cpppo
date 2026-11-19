# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division, unicode_literals
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import logging
import multiprocessing
import socket
import time

from .network import soak, bench

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


soak_address			= ("127.0.0.1", 12345)

def bench_cli( n, address=None ):
    """Just"""
    log.normal( "Client {} connecting to {!r}".format( n, address ))
    success			= address == soak_address
    return not success


def bench_srv( server, report_control=True ):
    """Outputs the server's (hypothetical) address, both via server.control.address, and via stdout for
    the stdout "soak" process of harvesting the server address.  Doesn't actually bind to an
    address.

    """
    import sys
    address			= soak_address

    # Transmit address on stdout and via control dict.
    print( "Server TCP address = {}:{}".format( *address ))
    sys.stdout.flush()
    control			= server.get( 'control' )
    if report_control and control:
        control['address']	= address

    while not control or not control.get( 'done' ):
        print( "control {}: {}".format( server.get( 'control' ).__class__, server.get( 'control' )))
        sys.stdout.flush()
        time.sleep( .5 )
    print( "Server TCP address = {}:{}: done signaled".format( *address ))


def test_soak_Thread():
    from threading import Thread
    assert not bench(
        server_func=bench_srv,
        server_kwds={'server': {'control': {'done': False}}},
        client_func=bench_cli,
        client_count=10,
        address_delay=5.0,
        server_cls=Thread,
    )


def test_soak_Process():
    with multiprocessing.Manager() as manager:
        for via_stdout in (True, False):
            control = manager.dict(done=False)
            assert not bench(
                server_func=bench_srv,
                server_kwds={'server': {'control': control}, 'report_control': not via_stdout},
                client_func=bench_cli,
                client_count=10,
                address_delay=5.0,
                address_via_stdout=via_stdout,
            )
            assert control['address'] == soak_address
