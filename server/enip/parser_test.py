from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

try:
    from future_builtins import map, zip
except ImportError:
    pass

import errno
import logging
import multiprocessing
import random
import socket
import threading
import time

import cpppo
from . import parser

log				= logging.getLogger( "parser" )


def test_IPADDR():
    # IP addresses are expressed as Network byte-ordered UDINTs, on the wire
    source			= parser.IPADDR.produce( '10.0.0.1' )
    assert source == b'\x0A\x00\x00\x01'
    # But, we parse them as Network byte-ordered UDINTs and present them as IP addresses
    with parser.IPADDR() as machine:
        data			= cpppo.dotdict()
        for m,s in machine.run( source=source, data=data ):
            pass
    assert data.IPADDR == '10.0.0.1'
