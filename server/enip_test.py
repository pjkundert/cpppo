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
from   cpppo.server import ( enip, network )

logging.basicConfig( **cpppo.log_cfg )
log				= logging.getLogger( "enip.tst" )


def test_octets():
    """Scans raw octets"""
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'abc123' )
    name			= "five"
    with enip.octets( name, repeat=5, context=name ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, path='octets', data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 4
    assert source.peek() == b'3'[0]

    assert data.octets.five_input.tostring() == b'abc12'


def test_octets_struct():
    """Parses a specified struct format from scanned octets"""

    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'abc123' )
    name			= 'ushort'
    format			= '<H'
    with enip.octets_struct( name, format=format, context=name ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, path='octets_struct', data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 1
    assert source.peek() == b'c'[0]

    assert data.octets_struct.ushort_input.tostring() == b'ab'
    assert data.octets_struct.ushort == 25185

def test_enip():
    reg_ses_request 		= bytes(bytearray([
                                            0x65, 0x00, #/* 9.....e. */
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, #/* ........ */
        0x00, 0x00                                      #/* .. */
    ]))

    data			= cpppo.dotdict()
    source			= cpppo.chainable( reg_ses_request )
    name			= 'header'
    with enip.enip_header( name, context=name ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, path='enip', data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 18
    assert source.peek() == b'\x00'[0]

    assert data.enip.header.command	== 0x0065
