from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import array
import json
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
    import reprlib
except ImportError:
    import repr as reprlib

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import cpppo
from   cpppo import misc
from   cpppo.server import (network, enip)
from   cpppo.server.enip import logix

log				= logging.getLogger( "enip.tst" )


def test_octets():
    """Scans raw octets"""
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'abc123' )

    # Scan 5; source is sufficient
    name			= "five"
    with enip.octets( name, repeat=5, context=name, terminal=True ) as machine:
        try:
            for i,(m,s) in enumerate( machine.run( source=source, path='octets', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
                if s is None:
                    break
        except:
            assert False, "%s: Should not have failed with exception: %s" % ( 
                machine.name_centered(), ''.join( traceback.format_exception( *sys.exc_info() )))
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 4
    assert source.peek() == b'3'[0]
    assert data.octets.five.input.tostring() == b'abc12'


def test_octets_singly():
    """Scans raw octets, but only provides them one at a time"""
    data			= cpppo.dotdict()
    origin			= cpppo.chainable( b'abc123' )
    source			= cpppo.chainable( b'' )

    name			= "singly"
    with enip.octets( name, repeat=5, context=name, terminal=True ) as machine:
        try:
            for i,(m,s) in enumerate( machine.run( source=source, path='octets', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
                if s is None:
                    log.info( "%s chain: %r", machine.name_centered(), [origin.peek()] )
                    if source.peek() is None and origin.peek() is not None:
                        source.chain( [next( origin )] )
        except:
            assert False, "%s: Should not have failed with exception: %s" % ( 
                machine.name_centered(), ''.join( traceback.format_exception( *sys.exc_info() )))
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 9
    assert origin.peek() == b'3'[0]
    assert data.octets.singly.input.tostring() == b'abc12'

def test_octets_deficient():
    """Scans octets where the source is deficient"""
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'3' )

    name			= "less"
    with enip.octets( name, repeat=5, context=name, terminal=True ) as machine:
        try:
            for i,(m,s) in enumerate( machine.run( source=source, path='octets', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
            assert False, "%s: Should have failed asserting no progress accepting symbol" % ( 
                machine.name_centered() )
        except AssertionError as exc:
            assert "no progress" in str(exc) 
            pass
        assert not machine.terminal, "%s: Should have not have reached terminal state" % machine.name_centered()
        assert i == 2
    assert source.peek() is None

def test_octets_zero():
    """Scans no octets (repeat=0)"""
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'abc123' )

    name			= "none"
    with enip.octets( name, repeat=0, context=name, terminal=True ) as machine:
        i			= None
        try:
            for i,(m,s) in enumerate( machine.run( source=source, path='octets', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
        except:
            assert False, "%s: Should not have failed with exception: %s" % ( 
                machine.name_centered(), ''.join( traceback.format_exception( *sys.exc_info() )))
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i is None
    assert source.peek() == b'a'[0]

def test_words():
    """Scans raw words, but only provides bytes them one at a time"""
    data			= cpppo.dotdict()
    origin			= cpppo.chainable( b'abc123z' )
    source			= cpppo.chainable( b'' )

    name			= "singly"
    with enip.words( name, repeat=3, context=name, terminal=True ) as machine:
        try:
            for i,(m,s) in enumerate( machine.run( source=source, path='words', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, source.sent, source.peek(), data )
                if s is None:
                    log.info( "%s chain: %r", machine.name_centered(), [origin.peek()] )
                    if source.peek() is None and origin.peek() is not None:
                        source.chain( [next( origin )] )
        except:
            assert False, "%s: Should not have failed with exception: %s" % ( 
                machine.name_centered(), ''.join( traceback.format_exception( *sys.exc_info() )))
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 11
    assert origin.peek() == b'z'[0]
    assert data.words.singly.input.tostring() == b'abc123'


def test_octets_struct():
    """Parses a specified struct format from scanned octets"""

    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'abc123' )
    name			= 'ushort'
    format			= '<H'
    with enip.octets_struct( name, format=format, context=name, terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, path='octets_struct', data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 1
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
    assert source.peek() == b'c'[0]

    assert data.octets_struct.ushort == 25185

def test_enip_TYPES():
    
    pkt				= b'\x05abc123'
    data			= cpppo.dotdict()
    source			= cpppo.chainable( pkt )
    with enip.SSTRING() as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 8
    assert data.SSTRING.length == 5
    assert data.SSTRING.string == 'abc12'

    res				= enip.SSTRING.produce( data.SSTRING )
    assert len( res ) == data.SSTRING.length+1
    assert res == b'\x05abc12'

    data.SSTRING.length	       += 1
    res				= enip.SSTRING.produce( data.SSTRING )
    assert len( res ) == data.SSTRING.length+1
    assert res == b'\x06abc12\x00'

    data.SSTRING.length	        = None
    res				= enip.SSTRING.produce( data.SSTRING )
    assert len( res ) == data.SSTRING.length+1
    assert res == b'\x05abc12'

    del data.SSTRING['length']
    res				= enip.SSTRING.produce( data.SSTRING )
    assert len( res ) == data.SSTRING.length+1
    assert res == b'\x05abc12'

    data.SSTRING.length		= 0
    res				= enip.SSTRING.produce( data.SSTRING )
    assert len( res ) == data.SSTRING.length+1
    assert res == b'\x00'

    


# pkt4
# "4","0.000863000","192.168.222.128","10.220.104.180","ENIP","82","Register Session (Req)"
rss_004_request 		= bytes(bytearray([
    # Register Session
                                        0x65, 0x00, #/* 9.....e. */
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, #/* ........ */
    0x00, 0x00                                      #/* .. */
]))
# pkt6
# "6","0.152924000","10.220.104.180","192.168.222.128","ENIP","82","Register Session (Rsp)"
rss_004_reply 		= bytes(bytearray([
                                        0x65, 0x00, #/* ......e. */
    0x04, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, #/* ........ */
    0x00, 0x00                                      #/* .. */
]))
# pkt8
# "8","0.153249000","192.168.222.128","10.220.104.180","CIP","100","Get Attribute All"
gaa_008_request 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9.w...o. */
    0x16, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x06, 0x00, 0x01, 0x02, #/* ........ */
    0x20, 0x66, 0x24, 0x01                          #/*  f$. */
]))
# pkt10
# "10","0.247332000","10.220.104.180","192.168.222.128","CIP","116","Success"
gaa_008_reply 		= bytes(bytearray([
                                        0x6f, 0x00, #/* ..T...o. */
    0x26, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* &....... */
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x16, 0x00, 0x81, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x2d, 0x00, 0x01, 0x00, 0x01, 0x01, 0xb1, 0x2a, #/* -......* */
    0x1b, 0x00, 0x0a, 0x00                          #/* .... */
]))
# pkt11
# "11","0.247477000","192.168.222.128","10.220.104.180","CIP CM","114","Unconnected Send: Get Attribute All"
gaa_011_request	 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9.....o. */
    0x24, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* $....... */
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x14, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, 0x01, 0xfa, 0x06, 0x00, #/*  .$..... */
    0x01, 0x02, 0x20, 0x01, 0x24, 0x01, 0x01, 0x00, #/* .. .$... */
    0x01, 0x00                                      #/* .. */
]))
# pkt13
# "13","0.336669000","10.220.104.180","192.168.222.128","CIP","133","Success"
gaa_011_reply	 		= bytes(bytearray([
                                        0x6f, 0x00, #/* ..dD..o. */
    0x37, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* 7....... */
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x27, 0x00, 0x81, 0x00, #/* ....'... */
    0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x36, 0x00, #/* ......6. */
    0x14, 0x0b, 0x60, 0x31, 0x1a, 0x06, 0x6c, 0x00, #/* ..`1..l. */
    0x14, 0x31, 0x37, 0x35, 0x36, 0x2d, 0x4c, 0x36, #/* .1756-L6 */
    0x31, 0x2f, 0x42, 0x20, 0x4c, 0x4f, 0x47, 0x49, #/* 1/B LOGI */
    0x58, 0x35, 0x35, 0x36, 0x31                    #/* X5561 */
    ]))
# pkt14
# "14","0.337357000","192.168.222.128","10.220.104.180","CIP CM","124","Unconnected Send: Unknown Service (0x52)"
unk_014_request 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9.#...o. */
    0x2e, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, 0x05, 0x9d, 0x10, 0x00, #/*  .$..... */
    0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
    0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, #/* A....... */
    0x01, 0x00, 0x01, 0x00                          #/* .... */  
]))
# pkt16
# "16","0.423402000","10.220.104.180","192.168.222.128","CIP","102","Success"
unk_014_reply 		= bytes(bytearray([
                                        0x6f, 0x00, #/* ..7...o. */
    0x18, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x08, 0x00, 0xd2, 0x00, #/* ........ */
    0x00, 0x00, 0xc3, 0x00, 0x27, 0x80              #/* ....'. */
]))
# pkt17
# "17","0.423597000","192.168.222.128","10.220.104.180","CIP CM","124","Unconnected Send: Unknown Service (0x52)"
unk_017_request 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9.....o. */
    0x2e, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, 0x05, 0x9d, 0x10, 0x00, #/*  .$..... */
    0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
    0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
    0x01, 0x00, 0x01, 0x00                          #/* .... */
]))
# pkt19
#"19","0.515458000","10.220.104.180","192.168.222.128","CIP","138","Success"
unk_017_reply		= bytes(bytearray([
                                        0x6f, 0x00, #/* ..jz..o. */
    0x3c, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* <....... */
    0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x2c, 0x00, 0xd2, 0x00, #/* ....,... */
    0x00, 0x00, 0xc3, 0x00, 0x4c, 0x10, 0x08, 0x00, #/* ....L... */
    0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, #/* ........ */
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe6, 0x42, #/* .......B */
    0x07, 0x00, 0xc8, 0x40, 0xc8, 0x40, 0x00, 0x00, #/* ...@.@.. */
    0xe4, 0x00, 0x00, 0x00, 0x64, 0x00, 0xb2, 0x02, #/* ....d... */
    0xc8, 0x40                                      #/* .@ */
]))
# pkt20
# "20","0.515830000","192.168.222.128","10.220.104.180","CIP CM","130","Unconnected Send: Unknown Service (0x53)"
unk_020_request 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9.X...o. */
    0x34, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* 4....... */
    0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x24, 0x00, 0x52, 0x02, #/* ....$.R. */
    0x20, 0x06, 0x24, 0x01, 0x05, 0x9d, 0x16, 0x00, #/*  .$..... */
    0x53, 0x05, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* S...SCAD */
    0x41, 0x00, 0x28, 0x0c, 0xc3, 0x00, 0x01, 0x00, #/* A.(..... */
    0x00, 0x00, 0x00, 0x00, 0xc9, 0x40, 0x01, 0x00, #/* .....@.. */
    0x01, 0x00                                      #/* .. */
]))
# pkt22
# "22","0.602090000","10.220.104.180","192.168.222.128","CIP","98","Success"
unk_020_reply 		= bytes(bytearray([
                                        0x6f, 0x00, #/* ..&...o. */
    0x14, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x04, 0x00, 0xd3, 0x00, #/* ........ */
    0x00, 0x00                                      #/* .. */
]))
# pkt23
# "23","0.602331000","192.168.222.128","10.220.104.180","CIP CM","126","Unconnected Send: Unknown Service (0x52)"
unk_023_request 		= bytes(bytearray([
                                        0x6f, 0x00, #/* 9..x..o. */
    0x30, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* 0....... */
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x20, 0x00, 0x52, 0x02, #/* .... .R. */
    0x20, 0x06, 0x24, 0x01, 0x05, 0x9d, 0x12, 0x00, #/*  .$..... */
    0x52, 0x05, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
    0x41, 0x00, 0x28, 0x0c, 0x01, 0x00, 0x00, 0x00, #/* A.(..... */
    0x00, 0x00, 0x01, 0x00, 0x01, 0x00              #/* ...... */
]))
# pkt 25
# "25","0.687210000","10.220.104.180","192.168.222.128","CIP","102","Success"
unk_023_reply 			= bytes(bytearray([
                                        0x6f, 0x00, #/* ...c..o. */
    0x18, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x08, 0x00, 0xd2, 0x00, #/* ........ */
    0x00, 0x00, 0xc3, 0x00, 0xc8, 0x40              #/* .....@ */
]))

# Read Tag Fragmented Request SCADA[10000], 10 elements
rfg_001_request			= bytes(bytearray([
                                  0x6f,0x00, 0x32,0x00,0x02,0x67,0x02,0x10,0x00,0x00,  #9.. ..o. 2..g....
    0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  #........ ........
    0x00,0x00,0x05,0x00,0x02,0x00,0x00,0x00, 0x00,0x00,0xb2,0x00,0x22,0x00,0x52,0x02,  #........ ....".R.
    0x20,0x06,0x24,0x01,0x05,0x9d,0x14,0x00, 0x52,0x06,0x91,0x05,0x53,0x43,0x41,0x44,  # .$..... R...SCAD
    0x41,0x00,0x29,0x00,0x10,0x27,0x0a,0x00, 0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00  #A.)..'.. ........
]))
# Read Tag Fragmented Reply (error 0x05)
rfg_001_reply			= bytes(bytearray([
                                  0x6f,0x00, 0x14,0x00,0x02,0x67,0x02,0x10,0x00,0x00,  #..Im..o. ...g....
    0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  #........ ........
    0x00,0x00,0x05,0x00,0x02,0x00,0x00,0x00, 0x00,0x00,0xb2,0x00,0x04,0x00,0xd2,0x00,  #........ ........
    0x05,0x00                                                                          #..               
]))

# Read Tag Fragmented Request SCADAX (bad Tag), 10 elements
rfg_002_request			= bytes(bytearray([
                                  0x6f,0x00, 0x2e,0x00,0x02,0x6b,0x02,0x10,0x00,0x00,  #9.....o. ...k....
    0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  #........ ........
    0x00,0x00,0x05,0x00,0x02,0x00,0x00,0x00, 0x00,0x00,0xb2,0x00,0x1e,0x00,0x52,0x02,  #........ ......R.
    0x20,0x06,0x24,0x01,0x05,0x9d,0x10,0x00, 0x52,0x04,0x91,0x06,0x53,0x43,0x41,0x44,  # .$..... R...SCAD
    0x41,0x58,0x01,0x00,0x00,0x00,0x00,0x00, 0x01,0x00,0x01,0x00                       #AX...... ....    
]))

# Read Tag Fragmented Reply (error,0x04 w/ 1 extended status,0x0000)
rfg_002_reply			= bytes(bytearray([
                                  0x6f,0x00, 0x16,0x00,0x02,0x6b,0x02,0x10,0x00,0x00,  #...o..o. ...k....
    0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  #........ ........
    0x00,0x00,0x05,0x00,0x02,0x00,0x00,0x00, 0x00,0x00,0xb2,0x00,0x06,0x00,0xd2,0x00,  #........ ........
    0x04,0x01,0x00,0x00                                                                #....             
]))


eip_tests			= [
            ( b'', {} ),        # test that parsers handle/reject empty/EOF
            ( rss_004_request,	{ 'enip.command': 0x0065, 'enip.length': 4 }),
            ( rss_004_reply,	{} ),
            ( gaa_008_request,	{} ),
            ( gaa_008_reply,	{} ),
            ( gaa_011_request,	{} ),
            ( gaa_011_reply,	{} ),
            ( unk_014_request,	{} ),
            ( unk_014_reply,	{} ),
            ( unk_017_request,	{} ),
            ( unk_017_reply,	{} ),
            ( unk_020_request,	{} ),
            ( unk_020_reply,	{} ),
            ( unk_023_request,	{} ),
            ( unk_023_reply,	{} ),
            ( rfg_001_request,	{} ),
            ( rfg_001_reply,	{} ),
            ( rfg_002_request,	{} ),
            ( rfg_002_reply,	{} ),
]

def test_enip_header():
    for pkt,tst in eip_tests:
        # Parse just the headers, forcing non-transitions to fetch one symbol at a time.  Accepts an
        # empty header at EOF.
        data			= cpppo.dotdict()
        origin			= cpppo.chainable( pkt )
        source			= cpppo.chainable()
        with enip.enip_header( 'header' ) as machine: # don't use default '.header' context!
            for i,(m,s) in enumerate( machine.run( source=source, path='enip', data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
                if s is None:
                    if source.peek() is None and origin.peek() is not None:
                        log.info( "%s chain: %r", machine.name_centered(), [origin.peek()] )
                        source.chain( [next( origin )] )

            assert i == ( 54 if len( pkt ) else 1 )
        if pkt:
            assert origin.peek() is not None
   
        for k,v in tst.items():
            assert data[k] == v


def test_enip_machine():
    for pkt,tst in eip_tests:
        # Parse the headers and encapsulated command data
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.enip_machine() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
                if s is None and source.peek() is None:
                    break # simulate detection of EOF
            if not pkt:
                assert i == 2		# enip_machine / enip_header reports state
            else:
                pass 			# varies...
        assert source.peek() is None
   
        log.normal( "EtherNet/IP Request: %s", enip.enip_format( data ))
        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # Ensure we can reproduce the original packet from the parsed data (placed in .enip)
        if data:
            assert enip.enip_encode( data.enip ) == pkt, "Invalid data: %r" % data

extpath_1		= bytes(bytearray([
    0x01,						# 1 word
    0x28, 0x01,   					# 8-bit element segment == 1
    0x28, 0x02,						# Decoy -- shouldn't be processed!
]))
extpath_2		= bytes(bytearray([
    0x05,						# 5 words
    0x28, 0x01,   					# 8-bit element segment == 1
    0x28, 0x02,
    0x2a, 0x00, 0x01, 0x02, 0x03, 0x04,
    0xff,						# Decoy -- shouldn't be processed!
]))
extpath_3		= bytes(bytearray([
    0x0f,						# 15 words
    0x28, 0x01,   					#  8-bit element   segment == 0x01
    0x29, 0x00, 0x01, 0x02,				# 16-bit element   segment == 0x0201
    0x2a, 0x00, 0x01, 0x02, 0x03, 0x04,			# 32-bit element   segment == 0x04030201

    0x20, 0x11,   					#  8-bit class     segment == 0x11
    0x21, 0x00, 0x11, 0x02,				# 16-bit class     segment == 0x0211

    0x24, 0x21,   					#  8-bit instance  segment == 0x21
    0x25, 0x00, 0x21, 0x02,				# 16-bit instance  segment == 0x0221

    0x30, 0x31,   					#  8-bit attribute segment == 0x31
    0x31, 0x00, 0x31, 0x02,				# 16-bit attribute segment == 0x0231

    0xff,						# Decoy -- shouldn't be processed!
]))
extpath_4		= bytes(bytearray([
    0x08,						# 4 words
    0x91, 0x06,
    b'a'[0], b'b'[0], b'c'[0], b'1'[0], b'2'[0], b'3'[0],# 6-character symbolic
    0x91, 0x05,
    b'x'[0], b'y'[0], b'z'[0], b'1'[0], b'2'[0], 0x00,	# 5-character symbolic + pad
    0xff,						# Decoy -- shouldn't be processed!
]))
extpath_5		= bytes(bytearray([
    0x01, 0x00, 0x01, 0x00				# 1 word (pad) port #1, link 0x00
]))
extpath_6		= bytes(bytearray([
    0x02, 0x00, 0x0F, 0x01, 0x02, 0x99			# 1 word (pad) port #513, link 0x00
]))
extpath_7		= bytes(bytearray([
    # From Vol 1-3.13, Table 10-6.15
    0x0E, 0x00,						# 14 word (pad), port 3, link 130.151.137.105
    0x13, 0x0F, 0x31, 0x33,
    0x30, 0x2E, 0x31, 0x35,
    0x31, 0x2E, 0x31, 0x33,
    0x37, 0x2E, 0x31, 0x30,
    0x35, 
          0x00,            # < errata (added)
          0x21, 0x00, 0x04,				# Class ID 4, Instance ID 2, Attribute ID 3
    0x00, 0x25, 0x00, 0x02,
    0x00, 0x30, 0x03,#0x00,  < errata (deleted)
]))
extpath_7_prod		= bytes(bytearray([		# The produced path is shorter (uses 8-bit formats)
    # From Vol 1-3.13, Table 10-6.15
    0x0C, 0x00,						# 14 word (pad), port 3, link 130.151.137.105
    0x13, 0x0F, 0x31, 0x33,
    0x30, 0x2E, 0x31, 0x35,
    0x31, 0x2E, 0x31, 0x33,
    0x37, 0x2E, 0x31, 0x30,
    0x35, 
          0x00,            # < errata (added)
          0x20,       0x04,				# Class ID 4, Instance ID 2, Attribute ID 3
          0x24,       0x02,
          0x30, 0x03,#0x00,  < errata (deleted)
]))

extpath_8		= bytes(bytearray([
    # From Vol 1-3.13, Table 10-6.15 (w/extended path)
    0x0F, 0x00,						# 14 word (pad), port 3, link 130.151.137.105
    0x1F, 0x0F, 
                0x03, 0x01,# extended path == 0x0103 
                0x31, 0x33,
    0x30, 0x2E, 0x31, 0x35,
    0x31, 0x2E, 0x31, 0x33,
    0x37, 0x2E, 0x31, 0x30,
    0x35, 
          0x00,            # < errata (added)
          0x21, 0x00, 0x04,				# Class ID 4, Instance ID 2, Attribute ID 3
    0x00, 0x25, 0x00, 0x02,
    0x00, 0x30, 0x03,#0x00,  < errata (deleted)
]))
extpath_8_prod		= bytes(bytearray([		# The produced path is shorter (uses 8-bit formats)
    # From Vol 1-3.13, Table 10-6.15
    0x0D, 0x00,						# 14 word (pad), port 3, link 130.151.137.105
    0x1F, 0x0F,
                0x03, 0x01, # 
                0x31, 0x33,
    0x30, 0x2E, 0x31, 0x35,
    0x31, 0x2E, 0x31, 0x33,
    0x37, 0x2E, 0x31, 0x30,
    0x35, 
          0x00,            # < errata (added)
          0x20,       0x04,				# Class ID 4, Instance ID 2, Attribute ID 3
          0x24,       0x02,
          0x30, 0x03,#0x00,  < errata (deleted)
]))

# The byte order of EtherNet/IP CIP data is little-endian; the lowest-order byte
# of the value arrives first.
extpath_tests			= [
            ( extpath_1, enip.EPATH,	{
                'request.EPATH.size': 1,
                'request.EPATH.segment': [{'element': 1}]
            } ),
            ( extpath_2, enip.EPATH,	{ 
                'request.EPATH.size': 5,
                'request.EPATH.segment': [
                    {'element':		0x01}, {'element':	0x02}, {'element':	0x04030201}
                ]
            } ),
            ( extpath_3, enip.EPATH,	{ 
                'request.EPATH.size': 15,
                'request.EPATH.segment': [
                    {'element':		0x01}, {'element':	0x0201}, {'element':	0x04030201},
                    {'class':		0x11}, {'class':	0x0211},
                    {'instance':	0x21}, {'instance':	0x0221},
                    {'attribute':	0x31}, {'attribute':	0x0231},
                ]
            } ),
            ( extpath_4, enip.EPATH,	{ 
                'request.EPATH.size': 8,
                'request.EPATH.segment': [
                    {'symbolic':	'abc123'},
                    {'symbolic':	'xyz12'},
                ]
            } ), 
            ( extpath_5, enip.route_path, { 
                'request.route_path.size': 1,
                'request.route_path.segment': [
                    {'port': 1, 'link': 0},
                ],
            } ), 
            ( extpath_6, enip.route_path, { 
                'request.route_path.size': 2,
                'request.route_path.segment': [
                    {'port': 513, 'link': 0x99},
                ],
            } ), 
            ( (extpath_7, extpath_7_prod), enip.route_path, { 
                'request.route_path.size': 14,
                'request.route_path.segment': [
                    {'port': 		3, 'link': '130.151.137.105'},
                    {'class': 		4},
                    {'instance': 	2},
                    {'attribute': 	3},
                ],
            } ), 
            ( (extpath_8, extpath_8_prod), enip.route_path, { 
                'request.route_path.size': 15,
                'request.route_path.segment': [
                    {'port': 	    0x103, 'link': '130.151.137.105'},
                    {'class': 		4},
                    {'instance': 	2},
                    {'attribute': 	3},
                ],
            } ), 
]

def test_enip_EPATH():
    for pkt,cls,tst in extpath_tests:
        # We may supply an expected produced value 'prod'; or, get it from the packet
        prod			= None
        if type( pkt ) is tuple:
            pkt,prod		= pkt

        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with cls() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # And, ensure that we can get the original EPATH back (ignoring extra decoy bytes)
        if not prod:
            prod		= pkt[:(2 if cls is enip.route_path else 1)+data.request[cls.__name__].size*2]

        out			= cls.produce( data.request[cls.__name__] )
        assert out == prod, \
            "Invalid EPATH data: %r\nexpect: %r\nactual: %r" % ( data, prod, out )




# "17","0.423597000","192.168.222.128","10.220.104.180","CIP CM","124","Unconnected Send: Unknown Service (0x52)"
readfrag_1_req 			= bytes(bytearray([
    0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
    0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
]))
#"19","0.515458000","10.220.104.180","192.168.222.128","CIP","138","Success"
readfrag_1_rpy			= bytes(bytearray([
                                        0xd2, 0x00, #/* ....,... */
    0x00, 0x00, 0xc3, 0x00, 0x4c, 0x10, 0x08, 0x00, #/* ....L... */
    0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, #/* ........ */
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe6, 0x42, #/* .......B */
    0x07, 0x00, 0xc8, 0x40, 0xc8, 0x40, 0x00, 0x00, #/* ...@.@.. */
    0xe4, 0x00, 0x00, 0x00, 0x64, 0x00, 0xb2, 0x02, #/* ....d... */
    0xc8, 0x80                                      #/* .@ */
]))
writetag_1_req	 		= bytes(bytearray([
    0x53, 0x05, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* S...SCAD */
    0x41, 0x00, 0x28, 0x0c, 0xc3, 0x00, 0x01, 0x00, #/* A.(..... */
    0x00, 0x00, 0x00, 0x00, 0xc9, 0x40              #/* .....@.. */
]))
# pkt22
# "22","0.602090000","10.220.104.180","192.168.222.128","CIP","98","Success"
writetag_1_rpy	 		= bytes(bytearray([
                                        0xd3, 0x00, #/* ........ */
    0x00, 0x00                                      #/* .. */
]))

tag_tests			= [
    (
        readfrag_1_req,	{
            'request.service': 			0x52,
            'request.path.segment': 		[{'symbolic': 'SCADA'}],
            'request.read_frag.elements':	20,
            'request.read_frag.offset':	2,
        }
    ), ( 
        readfrag_1_rpy,	{
            'request.service': 			0xd2,
            'request.status':			0x00,
            'request.read_frag.type':		0x00c3,
            'request.read_frag.data':	[
                0x104c, 0x0008,
                0x0003, 0x0002, 0x0002, 0x0002,
                0x000e, 0x0000, 0x0000, 0x42e6,
                0x0007, 0x40c8, 0x40c8, 0x0000,
                0x00e4, 0x0000, 0x0064, 0x02b2,
                0x80c8-0x10000 # 2's complement negative...
            ]
        }
    ),(
        writetag_1_req, {},
    ),(
        writetag_1_rpy, {},
    )
]

def test_enip_Logix():
    for pkt,tst in tag_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with logix.Logix.parser as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # And, ensure that we can get the original EPATH back (ignoring extra decoy bytes)
        try:
            assert logix.Logix.produce( data.request ) == pkt
        except:
            log.warning ( "Invalid packet produced from logix data: %r", data )
            raise
        
cpf_1		 		= bytes(bytearray([
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, 0x05, 0x9d, 0x10, 0x00, #/*  .$..... */
    0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
    0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
    0x01, 0x00, 0x01, 0x00                          #/* .... */
]))
cpf_1_rpy	 		= bytes(bytearray([
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x2c, 0x00, 0xd2, 0x00, #/* ....,... */
    0x00, 0x00, 0xc3, 0x00, 0x4c, 0x10, 0x08, 0x00, #/* ....L... */
    0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, #/* ........ */
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe6, 0x42, #/* .......B */
    0x07, 0x00, 0xc8, 0x40, 0xc8, 0x40, 0x00, 0x00, #/* ...@.@.. */
    0xe4, 0x00, 0x00, 0x00, 0x64, 0x00, 0xb2, 0x02, #/* ....d... */
    0xc8, 0x40                                      #/* .@ */
]))
cpf_2				= bytes(bytearray([ # gaa_011_request
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x14, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, 0x01, 0xfa, 0x06, 0x00, #/*  .$..... */
    0x01, 0x02, 0x20, 0x01, 0x24, 0x01, 0x01, 0x00, #/* .. .$... */
    0x01, 0x00                                      #/* .. */
]))
cpf_2_rpy	 		= bytes(bytearray([ # gaa_011_rpy
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x27, 0x00, 0x81, 0x00, #/* ....'... */
    0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x36, 0x00, #/* ......6. */
    0x14, 0x0b, 0x60, 0x31, 0x1a, 0x06, 0x6c, 0x00, #/* ..`1..l. */
    0x14, 0x31, 0x37, 0x35, 0x36, 0x2d, 0x4c, 0x36, #/* .1756-L6 */
    0x31, 0x2f, 0x42, 0x20, 0x4c, 0x4f, 0x47, 0x49, #/* 1/B LOGI */
    0x58, 0x35, 0x35, 0x36, 0x31                    #/* X5561 */
]))
CPF_tests			= [
    (
        cpf_1,
        {
            "CPF.count": 2, 
            "CPF.item[0].length": 0,
            "CPF.item[0].type_id": 0,
            "CPF.item[1].length": 30, 
            "CPF.item[1].type_id": 178, 
            "CPF.item[1].unconnected_send.length": 16, 
            "CPF.item[1].unconnected_send.request.path.segment[0].symbolic": "SCADA",
            "CPF.item[1].unconnected_send.request.path.size": 4, 
            "CPF.item[1].unconnected_send.request.read_frag.elements": 20, 
            "CPF.item[1].unconnected_send.request.read_frag.offset": 2, 
            "CPF.item[1].unconnected_send.request.service": 82, 
            "CPF.item[1].unconnected_send.path.segment[0].class": 6,
            "CPF.item[1].unconnected_send.path.segment[1].instance": 1,
            "CPF.item[1].unconnected_send.path.size": 2, 
            "CPF.item[1].unconnected_send.priority": 5, 
            "CPF.item[1].unconnected_send.service": 82, 
            "CPF.item[1].unconnected_send.timeout_ticks": 157,
        }
    ), (
        cpf_1_rpy,
        {
            "CPF.count": 2, 
            "CPF.item[0].length": 0, 
            "CPF.item[0].type_id": 0, 
            "CPF.item[1].length": 44, 
            "CPF.item[1].type_id": 178, 
            #"CPF.item[1].unconnected_send.request.input": "array('c', '\\xd2\\x00\\x00\\x00\\xc3\\x00L\\x10\\x08\\x00\\x03\\x00\\x02\\x00\\x02\\x00\\x02\\x00\\x0e\\x00\\x00\\x00\\x00\\x00\\xe6B\\x07\\x00\\xc8@\\xc8@\\x00\\x00\\xe4\\x00\\x00\\x00d\\x00\\xb2\\x02\\xc8@')", 
            "CPF.item[1].unconnected_send.request.read_frag.data": [
                4172, 
                8, 
                3, 
                2, 
                2, 
                2, 
                14, 
                0, 
                0, 
                17126, 
                7, 
                16584, 
                16584, 
                0, 
                228, 
                0, 
                100, 
                690, 
                16584
            ], 
            "CPF.item[1].unconnected_send.request.read_frag.type": 195, 
            "CPF.item[1].unconnected_send.request.service": 210, 
            "CPF.item[1].unconnected_send.request.status": 0, 
            "CPF.item[1].unconnected_send.request.status_ext.size": 0
        }
    ), (
        cpf_2,
        {
            "CPF.count": 2, 
            "CPF.item[0].length": 0, 
            "CPF.item[0].type_id": 0, 
            "CPF.item[1].length": 20, 
            "CPF.item[1].type_id": 178, 
            "CPF.item[1].unconnected_send.length": 6, 
            "CPF.item[1].unconnected_send.path.segment[0].class": 6, 
            "CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
            "CPF.item[1].unconnected_send.path.size": 2, 
            "CPF.item[1].unconnected_send.priority": 1, 
            "CPF.item[1].unconnected_send.request.get_attributes_all": True, 
            # "CPF.item[1].unconnected_send.request.input": "array('B', [1, 2, 32, 1, 36, 1])", 
            "CPF.item[1].unconnected_send.request.path.segment[0].class": 1, 
            "CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
            "CPF.item[1].unconnected_send.request.path.size": 2, 
            "CPF.item[1].unconnected_send.request.service": 1, 
            "CPF.item[1].unconnected_send.route_path.segment[0].link": 0, 
            "CPF.item[1].unconnected_send.route_path.segment[0].port": 1, 
            "CPF.item[1].unconnected_send.route_path.size": 1, 
            "CPF.item[1].unconnected_send.service": 82, 
            "CPF.item[1].unconnected_send.timeout_ticks": 250
        }
    ), (
        cpf_2_rpy,
        {
            "CPF.count": 2, 
            "CPF.item[0].length": 0, 
            "CPF.item[0].type_id": 0, 
            "CPF.item[1].length": 39, 
            "CPF.item[1].type_id": 178, 
            #"CPF.item[1].unconnected_send.request.get_attributes_all.input": "array('B', [1, 0, 14, 0, 54, 0, 20, 11, 96, 49, 26, 6, 108, 0, 20, 49, 55, 53, 54, 45, 76, 54, 49, 47, 66, 32, 76, 79, 71, 73, 88, 53, 53, 54, 49])", 
            #"CPF.item[1].unconnected_send.request.input": "array('B', [129, 0, 0, 0, 1, 0, 14, 0, 54, 0, 20, 11, 96, 49, 26, 6, 108, 0, 20, 49, 55, 53, 54, 45, 76, 54, 49, 47, 66, 32, 76, 79, 71, 73, 88, 53, 53, 54, 49])", 
            "CPF.item[1].unconnected_send.request.service": 129, 
            "CPF.item[1].unconnected_send.request.status": 0, 
            "CPF.item[1].unconnected_send.request.status_ext.size": 0
        }
    )
]

def test_enip_CPF():
    for pkt,tst in CPF_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.CPF() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )

        # Now, parse the encapsulated message(s).  We'll assume it is destined for a Logix Object.
        Lx			= logix.Logix()
        assert 'CPF' in data
        for item in data.CPF.item:
            if 'unconnected_send' in item:
                assert 'request' in item.unconnected_send # the encapsulated request
                with Lx.parser as machine:
                    log.normal( "Parsing %3d bytes using %s.parser, from %s", len( item.unconnected_send.request.input ),
                                Lx, enip.enip_format( item ))
                    # Parse the unconnected_send.request.input octets, putting parsed items into the
                    # same request context
                    for i,(m,s) in enumerate( machine.run( source=cpppo.peekable( item.unconnected_send.request.input ),
                                                           data=item.unconnected_send.request )):
                        log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                                    machine.name_centered(), i, s, source.sent, source.peek(), data )
                    log.normal( "Parsed  %3d bytes using %s.parser, into %s", len( item.unconnected_send.request.input ),
                                Lx, enip.enip_format( data ))

        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise


        # Ensure that we can get the original CPF back
        for k in list(data.keys()):
            if k.endswith( 'input' ):
                log.detail( "del data[%r]", k )
                del data[k]
        try:
            for item in data.CPF.item:
                if 'unconnected_send' in item:
                    item.unconnected_send.request.input	= bytearray( Lx.produce( item.unconnected_send.request ))
                    log.normal("Produce Logix message from: %r", item.unconnected_send.request )
            log.normal( "Produce CPF message from: %r", data.CPF )
            data.input		= bytearray( enip.CPF.produce( data.CPF )) 
            assert data.input == pkt
        except:
            log.warning ( "Invalid packet produced from CPF data: %r", data )
            raise



 
CIP_tests			= [
            ( 
                b'', {}
            ), (
                rss_004_request,
                { 
                    "enip.CIP.register.options": 0, 
                    "enip.CIP.register.protocol_version": 1, 
                    "enip.command": 101, 
                    "enip.length": 4, 
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0
                }
            ), (
                gaa_008_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 6, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attributes_all": True, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\x01\\x02 f$\\x01')", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 102, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 22, 
                    "enip.options": 0, 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0,
                }
            ), (
                gaa_008_reply,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 22, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attributes_all.input": "array('c', '\\x00\\x08\\x00\\x00\\x00\\x00-\\x00\\x01\\x00\\x01\\x01\\xb1*\\x1b\\x00\\n\\x00')", 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\x81\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x00-\\x00\\x01\\x00\\x01\\x01\\xb1*\\x1b\\x00\\n\\x00')", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 129, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 38, 
                    "enip.options": 0, 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0,
                }
            ), ( 
                gaa_011_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 20, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attributes_all": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 250, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 36, 
                    "enip.options": 0, 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
            ), ( 
                gaa_011_reply,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 39, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attributes_all.input": "array('c', '\\x01\\x00\\x0e\\x006\\x00\\x14\\x0b`1\\x1a\\x06l\\x00\\x141756-L61/B LOGIX5561')", 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\x81\\x00\\x00\\x00\\x01\\x00\\x0e\\x006\\x00\\x14\\x0b`1\\x1a\\x06l\\x00\\x141756-L61/B LOGIX5561')", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 129, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    #"enip.input": "array('c', \"\\x00\\x00\\x00\\x00\\x05\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\xb2\\x00'\\x00\\x81\\x00\\x00\\x00\\x01\\x00\\x0e\\x006\\x00\\x14\\x0b`1\\x1a\\x06l\\x00\\x141756-L61/B LOGIX5561\")", 
                    "enip.length": 55, 
                    "enip.options": 0, 
                    #"enip.sender_context.input": "array('c', '\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x00')", 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
            ), (
                unk_014_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0,
                    "enip.CIP.send_data.CPF.item[0].type_id": 0,
                    "enip.CIP.send_data.CPF.item[1].length": 30, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].symbolic": "SCADA",
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 4, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.elements": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.offset": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 16, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 157,
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 46, 
                    "enip.options": 0, 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0,
                }
            ), (
                unk_014_reply,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 8, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', \"\\xd2\\x00\\x00\\x00\\xc3\\x00'\\x80\")", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.data": [
                        -32729
                    ], 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.type": 195, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 210, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    #"enip.input": "array('c', \"\\x00\\x00\\x00\\x00\\x05\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\xb2\\x00\\x08\\x00\\xd2\\x00\\x00\\x00\\xc3\\x00'\\x80\")", 
                    "enip.length": 24, 
                    "enip.options": 0, 
                    #"enip.sender_context.input": "array('c', '\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00')", 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
          ), (
              unk_017_request,
              {
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.elements": 20, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.offset": 2, 
              }
          ), (
                unk_017_reply,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 44, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\xd2\\x00\\x00\\x00\\xc3\\x00L\\x10\\x08\\x00\\x03\\x00\\x02\\x00\\x02\\x00\\x02\\x00\\x0e\\x00\\x00\\x00\\x00\\x00\\xe6B\\x07\\x00\\xc8@\\xc8@\\x00\\x00\\xe4\\x00\\x00\\x00d\\x00\\xb2\\x02\\xc8@')", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.data": [
                        4172, 
                        8, 
                        3, 
                        2, 
                        2, 
                        2, 
                        14, 
                        0, 
                        0, 
                        17126, 
                        7, 
                        16584, 
                        16584, 
                        0, 
                        228, 
                        0, 
                        100, 
                        690, 
                        16584
                    ], 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.type": 195, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 210, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    #"enip.input": "array('c', '\\x00\\x00\\x00\\x00\\x05\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\xb2\\x00,\\x00\\xd2\\x00\\x00\\x00\\xc3\\x00L\\x10\\x08\\x00\\x03\\x00\\x02\\x00\\x02\\x00\\x02\\x00\\x0e\\x00\\x00\\x00\\x00\\x00\\xe6B\\x07\\x00\\xc8@\\xc8@\\x00\\x00\\xe4\\x00\\x00\\x00d\\x00\\xb2\\x02\\xc8@')", 
                    "enip.length": 60, 
                    "enip.options": 0, 
                    #"enip.sender_context.input": "array('c', '\\x04\\x00\\x00\\x00\\x00\\x00\\x00\\x00')", 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
            ), ( 
              unk_020_request,	 
              {
                  "enip.CIP.send_data.CPF.count": 2, 
                  "enip.CIP.send_data.CPF.item[0].length": 0, 
                  "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                  "enip.CIP.send_data.CPF.item[1].length": 36, 
                  "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].symbolic": "SCADA", 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].element": 12, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 5, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 83, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.write_frag.data": [ 16585 ], 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.write_frag.elements": 1, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.write_frag.offset": 0, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.write_frag.type": 195, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 22, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 157, 
                  "enip.CIP.send_data.interface": 0, 
                  "enip.CIP.send_data.timeout": 5, 
                  "enip.command": 111, 
                  "enip.length": 52, 
                  "enip.options": 0, 
                  "enip.session_handle": 285351425, 
                  "enip.status": 0,
              }
            ), (
                unk_020_reply,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 4, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    #"enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\xd3\\x00\\x00\\x00')", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 211, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.write_frag": True, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    #"enip.input": "array('c', '\\x00\\x00\\x00\\x00\\x05\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\xb2\\x00\\x04\\x00\\xd3\\x00\\x00\\x00')", 
                    "enip.length": 20, 
                    "enip.options": 0, 
                    #"enip.sender_context.input": "array('c', '\\x05\\x00\\x00\\x00\\x00\\x00\\x00\\x00')", 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
          ), (
                unk_023_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 32, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 18, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].symbolic": "SCADA", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].element": 12, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.elements": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.offset": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].link": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].port": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.size": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 157, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 48, 
                    "enip.options": 0, 
                    "enip.session_handle": 285351425, 
                    "enip.status": 0
                }
            ),

]
  

def test_enip_CIP():
    for pkt,tst in CIP_tests:
        # Parse just the CIP portion following the EtherNet/IP encapsulation header
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.enip_machine( context='enip' ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        # In a real protocol implementation, an empty header (EOF with no input at all) is
        # acceptable; it indicates a session closed by the client.
        if not data:
            log.normal( "EtherNet/IP Request: Empty (session terminated): %s", enip.enip_format( data ))
            continue

        log.normal( "EtherNet/IP Request: %s", enip.enip_format( data ))
            
        # Parse the encapsulated .input

        data.enip.encapsulated	= cpppo.dotdict()
        
        with enip.CIP() as machine:
            for i,(m,s) in enumerate( machine.run( path='enip', source=cpppo.peekable( data.enip.input ), data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )

        log.normal( "EtherNet/IP CIP Request: %s", enip.enip_format( data ))

        # Assume the request in the CIP's CPF items are Logix requests.
        # Now, parse the encapsulated message(s).  We'll assume it is destined for a Logix Object.
        if 'enip.CIP.send_data' in data:
            Lx		= logix.Logix()
            for item in data.enip.CIP.send_data.CPF.item:
                if 'unconnected_send.request' in item:
                    # An Unconnected Send that contained an encapsulated request (ie. not just a Get
                    # Attribute All)
                    with Lx.parser as machine:
                        log.normal( "Parsing %3d bytes using %s.parser, from %s", 
                                    len( item.unconnected_send.request.input ),
                                    Lx, enip.enip_format( item ))
                        # Parse the unconnected_send.request.input octets, putting parsed items into the
                        # same request context
                        for i,(m,s) in enumerate( machine.run(
                                source=cpppo.peekable( item.unconnected_send.request.input ),
                                data=item.unconnected_send.request )):
                            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                                        machine.name_centered(), i, s, source.sent, source.peek(), data )
                        log.normal( "Parsed  %3d bytes using %s.parser, into %s", 
                                    len( item.unconnected_send.request.input ),
                                    Lx, enip.enip_format( data ))

        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise
            

        # Ensure that we can get the original EtherNet/IP CIP back
        for k in list(data.keys()):
            if k.endswith( 'input' ) and 'sender_context' not in k:
                log.detail( "del data[%r]", k )
                del data[k]
        try:
            # First reconstruct any SendRRData CPF items, containing encapsulated requests/responses
            if 'enip.CIP.send_data' in data:
                cpf		= data.enip.CIP.send_data
                for item in cpf.CPF.item:
                    if 'unconnected_send' in item:
                        item.unconnected_send.request.input	= bytearray( Lx.produce( item.unconnected_send.request ))
                        log.normal("Produce Logix message from: %r", item.unconnected_send.request )
                log.normal( "Produce CPF message from: %r", cpf.CPF )
                cpf.input		= bytearray( enip.CPF.produce( cpf.CPF )) 
            # Next, reconstruct the CIP Register, SendRRData.  The CIP.produce must be provided the
            # EtherNet/IP header, because it contains data (such as .command) relevant to
            # interpreting the .CIP... contents.
            data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
            # And finally the EtherNet/IP encapsulation itself
            data.input			= bytearray( enip.enip_encode( data.enip ))
            assert data.input == pkt
        except:
            log.warning ( "Invalid packet produced from EtherNet/IP CIP data: %r", data )
            raise


def test_enip_device_symbolic():
    enip.device.symbol['SCADA'] = {'class':0x401, 'instance':1, 'attribute':2}
    path={'segment':[{'symbolic':'SCADA'}, {'element':4}]}
    assert enip.device.resolve( path, attribute=True ) == (0x401,1,2)
    assert enip.device.resolve( path ) == (0x401,1,None)

    try:
        result			= enip.device.resolve(
            {'segment':[{'class':5},{'symbolic':'SCADA'},{'element':4}]} )
        assert False, "Should not have succeeded: %r" % result
    except AssertionError as exc:
        assert "Failed to override" in str(exc)

    try:
        result			= enip.device.resolve( 
            {'segment':[{'class':5},{'symbolic':'BOO','length':5},{'element':4}]} )
        assert False, "Should not have succeeded: %r" % result
    except AssertionError as exc:
        assert "Unrecognized symbolic name 'BOO'" in str(exc)

    try:
        result			= enip.device.resolve( {'segment':[{'instance':1}]} )
        assert False, "Should not have succeeded: %r" % result
    except AssertionError as exc:
        assert "Failed to resolve" in str(exc)

    try:
        result			= enip.device.resolve(
            {'segment':[{'class':0x404}, {'instance':1}, {'something':10}]}, attribute=True )
        assert False, "Should not have succeeded: %r" % result
    except AssertionError as exc:
        assert "Invalid term" in str(exc)


def test_enip_device():
    # Find a new Class ID.
    class_found			= True
    while class_found:
        class_num		= random.randrange( 1, 256 )
        class_found		= enip.device.lookup( class_id=class_num )

    class Test_Device( enip.device.Object ):
        class_id		= class_num

    # Create an instance (creates class-level instance_id==0 automatically)
    O				= Test_Device( 'Test Class', instance_id=1 )

    # Confirm the new entries in the enip.device.directory
    assert sorted( enip.device.directory[str(O.class_id)].keys(), key=misc.natural ) == [
        '0.0',				# the class-level instance
        '0.1', 				# ... and class-level attributes
        '0.2',
        '0.3',
        '0.4',
        str(O.instance_id)+'.0',	# The Instance we just created (it has no Attributes)
    ]

    assert enip.device.lookup( class_id=class_num, instance_id=1 ) is O
    assert enip.device.directory[str(O.class_id)+'.0.1'].value == 0
    assert enip.device.directory[str(O.class_id)+'.0.3'].value == 1 # Number of Instances

    O2				= Test_Device( 'Test Class' )
    assert enip.device.directory[str(O.class_id)+'.0.3'].value == 2 # Number of Instances
    log.normal( "device.directory: %s", '\n'.join(
        "%16s: %s" % ( k, enip.device.directory[k] )
        for k in sorted( enip.device.directory.keys(), key=misc.natural)))



    Ix				= enip.device.Identity( 'Test Identity' )
    attrs			= enip.device.directory[str(Ix.class_id)+'.'+str(Ix.instance_id)]
    log.normal( "New Identity Instance directory: %s", enip.enip_format( attrs ))
    assert attrs['7'].produce() == b'\x141756-L61/B LOGIX5561'
    
    request			= cpppo.dotdict({'service': 0x01, 'path':{'segment':[{'class':Ix.class_id},{'instance':Ix.instance_id}]}})
    gaa				= Ix.request( request )
    log.normal( "Identity Get Attributes All: %r, data: %s", gaa, enip.enip_format( request ))
    assert request.input == b'\x81\x00\x00\x00\x01\x00\x0e\x006\x00\x14\x0b`1\x1a\x06l\x00\x141756-L61/B LOGIX5561'

    # Look up Objects/Attribute by resolving a path
    assert enip.device.lookup( *enip.device.resolve( {'segment':[{'class':class_num}, {'instance':1}]} )) is O
    assert enip.device.lookup( *enip.device.resolve( {'segment':[{'class':class_num}, {'instance':2}]} )) is O2

    enip.device.symbol['BOO'] = {'class': class_num, 'instance': 1}

    path			= {'segment':[{'symbolic':'BOO', 'length':3}, {'attribute':2}, {'element':4}]}
    assert enip.device.lookup( *enip.device.resolve( path )) is O

    Oa1	= O.attribute['2'] 	= enip.device.Attribute('Something', enip.parser.INT, default=0)
    assert '0' in O.attribute # the Object
    assert '2' in O.attribute
    assert enip.device.lookup( *enip.device.resolve( path, attribute=True )) is Oa1


def test_enip_logix():
    """The logix module implements some features of a Logix Controller."""
    Obj				= logix.Logix()
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'Something', enip.parser.INT, default=[n for n in range( 100 )])

    assert len( Obj_a1 ) == 100

    # Set up a symbolic tag referencing the Logix Object's Attribute
    enip.device.symbol['SCADA']	= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':1 }

    # Lets get it to parse a request:
    #     'service': 			0x52,
    #     'path.segment': 		[{'symbolic': 'SCADA', 'length': 5}],
    #     'read_frag.elements':		20,
    #     'read_frag.offset':		2,

    req_1	 		= bytes(bytearray([
        0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
        0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
    ]))
    source			= cpppo.peekable( req_1 )
    data 			= cpppo.dotdict()
    with Obj.parser as machine:
        for m,w in machine.run( source=source, data=data ):
            pass
    log.normal( "Logix Request parsed: %s", enip.enip_format( data ))

    # If we ask a Logix Object to process the request, it should respond.
    proceed			= Obj.request( data )
    log.normal("Logix Request processed: %s", enip.enip_format( data ))


# Run the bench-test.  Sends some request from a bunch of clients to a server, testing responses

def enip_process_canned( addr, data, **kwds ):
    """Process a request, recognizing a subset of the known requests, and returning a "canned"
    response."""
    if not data:
        log.normal( "EtherNet/IP Request Empty; end of session" )
        return False

    log.detail( "EtherNet/IP Request: %s", enip.parser.enip_format( data.request ))
    if data.request.enip.command == 0x0065:
        source			= cpppo.chainable( rss_004_reply )
        with enip.enip_machine( terminal=True ) as machine: # Load data.response.enip
            for m,s in machine.run( path='response', source=source, data=data ):
                pass
            if machine.terminal:
                log.debug( "EtherNet/IP Response: %s", enip.parser.enip_format( data.response ))
            else:
                log.error( "EtherNet/IP Response failed to parse: %s", enip.parser.enip_format( data.response ))
        log.detail( "EtherNet/IP Response: %s", enip.parser.enip_format( data.request ))
        return True

    raise Exception( "Unrecognized request: %s" % ( enip.parser.enip_format( data )))

# The default Client will wait for draindelay after 
#client_count, client_max	= 15, 10
client_count, client_max	= 1, 1
charrange, chardelay		= (2,10), .1	# split/delay outgoing msgs
draindelay			= 10.  		# long in case server very slow (eg. logging), but immediately upon EOF

def enip_cli( number, tests=None ):
    """Sends a series of test messages, testing response for expected results."""
    log.info( "EtherNet/IP Client %3d connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( enip.address )
    log.normal( "EtherNet/IP Client %3d connected to server at %s", number, enip.address )
        
    successes			= 0
    try:
        eof			= False
        source			= cpppo.chainable()
        for req,tst in tests:
            errors		= 0
            data		= cpppo.dotdict()

            log.normal( "EtherNet/IP Client %3d req.: %5d: %s ", number, len( req ), repr( req ))

            # Await response, sending request in chunks using inter-block chardelay if output
            # remains, otherwise await response using draindelay.  Stop if EOF from server.  For
            # each request, run a EtherNet/IP frame parser state machine 'til it reports terminal.
            rpy			= b''
            sta			= None
            with enip.enip_machine( terminal=True ) as machine:
                engine		= machine.run( source=source, path='response', data=data )
                while not eof:
                    if len( req ):
                        if machine.terminal:
                            log.warning(
                                "EtherNet/IP Client %3d reply complete, before full request sent!" % (
                                    number ))
                            error += 1
                        out	= min( len( req ), random.randrange( *charrange ))
                        log.detail( "EtherNet/IP Client %3d send: %5d/%5d: %s", number, out, len( req ),
                                    repr( req[:out] ))
                        conn.send( req[:out] )
                        req	= req[out:]
                    # Wait up to draindelay if done request but machine not terminal
                    done	= len( req ) == 0
                    rcvd	= network.recv(
                        conn, timeout=draindelay if done and not machine.terminal else chardelay )
                    if rcvd is None:
                        # No input; if we're done sending, we've waited long enough; either
                        # chardelay or draindelay.  Quit.
                        if done:
                            if not machine.terminal:
                                log.warning(
                                    "EtherNet/IP Client %3d reply incomplete, but drained for %f seconds!" % (
                                        number, draindelay ))
                            break
                    else:
                        log.detail( "EtherNet/IP Client %3d recv: %5d: %s", number, len( rcvd ),
                                    repr( rcvd ) if len( rcvd ) else "EOF" )
                        eof		= not len( rcvd )
                        rpy	       += rcvd

                        # New data; keep running machine's engine (a generator)
                        source.chain( rcvd )
                        for mch,sta in engine:
                            log.detail("EtherNet/IP Client %3d rpy.: %s -> %10.10s; next byte %3d: %-10.10r: %s",
                                       number, machine.name_centered(), sta, source.sent, source.peek(), reprlib.repr( data ))

                # Parsed response should be in data.
                assert machine.terminal, \
                    "%3d client failed to decode EtherNet/IP response: %r\ndata: %s" % (
                        number, rpy, enip.parser.enip_format( data ))

            log.detail( "EtherNet/IP Client %3d rpy.: %5d: %s ", number, len( rpy ), repr( rpy ))
            log.normal( "EtherNet/IP Client %3d rpy.: %s", number, enip.parser.enip_format( data ))

            # Successfully sent request and parsed response; can continue; test req/rpy parsed data
            for k,v in tst.items():
                if data[k] != v:
                    log.warning( "EtherNet/IP Client %3d test failed: %s != %s; %s", number, data[k], v,
                                 enip.parser.enip_format( data ))
                    errors     += 1
            if not errors:
                successes      += 1
            if eof:
                break

    except KeyboardInterrupt as exc:
        log.warning( "EtherNet/IP Client %3d terminated: %r", number, exc )
    except Exception as exc:
        log.warning( "EtherNet/IP Client %3d client failed: %r\n%s", number, exc, traceback.format_exc() )
    finally:
        pass

    failed			= successes != len( tests )
    if failed:
        log.warning( "%3d client failed: %d/%d tests succeeded", number, successes, len( tests ))
    
    log.normal( "%3d client exited", number )
    return failed

enip_cli_kwds_basic		= {
	'tests':	[
            ( rss_004_request, {
                'response.enip.command': 		0x0065,
                'response.enip.session_handle':		285351425,
            }),
        ]
}

enip_svr_kwds_basic		= { 
    'enip_process': 	enip_process_canned,
    'argv':		[ 
        #'-v',
        'SCADA=INT[1000]',
    ],
    'server': 		{
        'control':	cpppo.apidict( enip.timeout, {
            'done':	False,
        }),
    },
}

def test_enip_bench_basic():
    failed			= cpppo.server.network.bench( server_func=enip.main,
                                                              server_kwds=enip_svr_kwds_basic,
                                                              client_func=enip_cli,
                                                              client_kwds=enip_cli_kwds_basic,
                                                              client_count=client_count,
                                                                client_max=client_max)
    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


enip_cli_kwds_logix		= {
	'tests':	[
            ( 
                rss_004_request,
                {
                    'response.enip.command':	 	0x0065,
                    #'response.enip.session_handle':	285351425, # Server generates
                }
            ), ( 
                gaa_008_request,
                {
                    "response.enip.length": 		42, 
                }
            ), ( 
                gaa_011_request,
                {
                    "response.enip.length": 		55, 
                }
            ), ( 
                unk_014_request, # Read Frag, 1 element
                {
                    "response.enip.length": 		24,
                }
            ), ( 
                unk_020_request, # Write Frag, 1 elements (index 12)
                {
                    "response.enip.length": 		20,
                }
            ), ( 
                unk_023_request, # Read Frag, 1 elements (index 12)
                {
                    "response.enip.length": 		24,
                }
            ),
        ]
}

enip_svr_kwds_logix 		= { 
    'enip_process': 	logix.process,
    'argv':		[
        #'-v', 
        'SCADA=INT[1000]'
    ],
    'server': 		{
        'control': 	cpppo.apidict( enip.timeout, {
            'done':	False,
        }),
    },
}


def test_enip_bench_logix():
    failed			= cpppo.server.network.bench( server_func=enip.main,
                                                              server_kwds=enip_svr_kwds_logix,
                                                              client_func=enip_cli,
                                                              client_kwds=enip_cli_kwds_logix,
                                                              client_count=client_count,
                                                                client_max=client_max)
    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


if __name__ == "__main__":
    '''
    import yappi
    yappi.start()
    '''
    test_enip_bench_logix()
    '''
    print( "\nFunction Total:" )
    yappi.print_stats( sys.stdout, yappi.SORTTYPE_TTOTAL )
    print( "\nWithin Function:" )
    yappi.print_stats( sys.stdout, yappi.SORTTYPE_TSUB )
    '''
