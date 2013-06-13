from __future__ import absolute_import
from __future__ import print_function

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

if __name__ == "__main__" and __package__ is None:
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import cpppo
from   cpppo import misc
from   cpppo.server import (enip, network)
from   cpppo.server.enip import logix

logging.basicConfig( **cpppo.log_cfg )
#logging.getLogger().setLevel( logging.DEBUG )
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
unk_023_reply 		= bytes(bytearray([
                                        0x6f, 0x00, #/* ...c..o. */
    0x18, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x08, 0x00, 0xd2, 0x00, #/* ........ */
    0x00, 0x00, 0xc3, 0x00, 0xc8, 0x40              #/* .....@ */
]))

# Read Tag Fragmented Request SCADA[10000], 10 elements
# 0030                    6f 00  32 00 02 67 02 10 00 00   9.. ..o. 2..g....
# 0040  00 00 07 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
# 0050  00 00 05 00 02 00 00 00  00 00 b2 00 22 00 52 02   ........ ....".R.
# 0060  20 06 24 01 05 9d 14 00  52 06 91 05 53 43 41 44    .$..... R...SCAD
# 0070  41 00 29 00 10 27 0a 00  00 00 00 00 01 00 01 00   A.)..'.. ........

# Read Tag Fragmented Reply (error 0x05)
# 0030                    6f 00  14 00 02 67 02 10 00 00   ..Im..o. ...g....
# 0040  00 00 07 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
# 0050  00 00 05 00 02 00 00 00  00 00 b2 00 04 00 d2 00   ........ ........
# 0060  05 00                                              ..               

# Read Tag Fragmented Request SCADAX (bad Tag), 10 elements
# 0030                    6f 00  2e 00 02 6b 02 10 00 00   9.....o. ...k....
# 0040  00 00 07 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
# 0050  00 00 05 00 02 00 00 00  00 00 b2 00 1e 00 52 02   ........ ......R.
# 0060  20 06 24 01 05 9d 10 00  52 04 91 06 53 43 41 44    .$..... R...SCAD
# 0070  41 58 01 00 00 00 00 00  01 00 01 00               AX...... ....    

# Read Tag Fragmented Reply (error 0x04 w/ 1 extended status 0x0000)
# 0030                    6f 00  16 00 02 6b 02 10 00 00   ...o..o. ...k....
# 0040  00 00 07 00 00 00 00 00  00 00 00 00 00 00 00 00   ........ ........
# 0050  00 00 05 00 02 00 00 00  00 00 b2 00 06 00 d2 00   ........ ........
# 0060  04 01 00 00                                        ....             


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

# The byte order of EtherNet/IP CIP data is little-endian; the lowest-order byte
# of the value arrives first.
extpath_tests			= [
            ( extpath_1,	{
                'request.EPATH.size': 1,
                'request.EPATH.segment': [{'element': 1}]
            } ),
            ( extpath_2,	{ 
                'request.EPATH.size': 5,
                'request.EPATH.segment': [
                    {'element':		0x01}, {'element':	0x02}, {'element':	0x04030201}
                ]
            } ),
            ( extpath_3,	{ 
                'request.EPATH.size': 15,
                'request.EPATH.segment': [
                    {'element':		0x01}, {'element':	0x0201}, {'element':	0x04030201},
                    {'class':		0x11}, {'class':	0x0211},
                    {'instance':	0x21}, {'instance':	0x0221},
                    {'attribute':	0x31}, {'attribute':	0x0231},
                ]
            } ),
            ( extpath_4,	{ 
                'request.EPATH.size': 8,
                'request.EPATH.segment': [
                    {'symbolic':	'abc123', 'length': 6 },
                    {'symbolic':	'xyz12',  'length': 5 },
                ]
            } )
]

def test_enip_EPATH():
    for pkt,tst in extpath_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.EPATH() as machine:
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
        assert enip.EPATH.produce( data.request.EPATH ) == pkt[:1+data.request.EPATH.size*2], \
            "Invalid EPATH data: %r" % data




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
            'request.logix.service': 		0x52,
            'request.logix.path.segment': 		[{'symbolic': 'SCADA', 'length': 5}],
            'request.logix.read_frag.elements':	20,
            'request.logix.read_frag.offset':	2,
        }
    ), ( 
        readfrag_1_rpy,	{
            'request.logix.service': 		0xd2,
            'request.logix.status':			0x00,
            'request.logix.read_frag.type':		0x00c3,
            'request.logix.read_frag.data':	[
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

def test_enip_Tag():
    for pkt,tst in tag_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.Tag(context='logix') as machine:
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
            assert enip.Tag.produce( data.request.logix ) == pkt
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
CPF_tests			= [
    ( cpf_1, {
        "CPF.count": 2, 
        "CPF.item[0].length": 0,
        "CPF.item[0].type_id": 0,
        "CPF.item[1].length": 30, 
        "CPF.item[1].type_id": 178, 
        "CPF.item[1].unconnected_send.length": 16, 
        "CPF.item[1].unconnected_send.Tag.path.segment[0].symbolic": "SCADA",
        "CPF.item[1].unconnected_send.Tag.path.size": 4, 
        "CPF.item[1].unconnected_send.Tag.read_frag.elements": 20, 
        "CPF.item[1].unconnected_send.Tag.read_frag.offset": 2, 
        "CPF.item[1].unconnected_send.Tag.service": 82, 
        "CPF.item[1].unconnected_send.request_path.segment[0].class": 6,
        "CPF.item[1].unconnected_send.request_path.segment[1].instance": 1,
        "CPF.item[1].unconnected_send.request_path.size": 2, 
        "CPF.item[1].unconnected_send.priority": 5, 
        "CPF.item[1].unconnected_send.service": 82, 
        "CPF.item[1].unconnected_send.timeout_ticks": 157,
    })
]

def test_enip_CPF():
    for pkt,tst in CPF_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.CPF() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise
            
        '''
        # And, ensure that we can get the original EPATH back (ignoring extra decoy bytes)
        try:
            assert enip.logix.produce( data.request.logix ) == pkt
        except:
            log.warning ( "Invalid packet produced from logix data: %r", data )
            raise
        '''

 
cip_tests			= [
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
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 102, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 1, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.timeout": 5, 
                    "enip.command": 111, 
                    "enip.length": 22, 
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
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.get_attributes_all": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].class": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.service": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
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
                unk_014_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0,
                    "enip.CIP.send_data.CPF.item[0].type_id": 0,
                    "enip.CIP.send_data.CPF.item[1].length": 30, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].length": 5,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].symbolic": "SCADA",
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.size": 4, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.elements": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.offset": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 16, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 6,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
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
              unk_017_request,
              {
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.elements": 20, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.offset": 2, 
              }
          ), (
              unk_020_request,	 
              {
                  "enip.CIP.send_data.CPF.count": 2, 
                  "enip.CIP.send_data.CPF.item[0].length": 0, 
                  "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                  "enip.CIP.send_data.CPF.item[1].length": 36, 
                  "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].length": 5, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].symbolic": "SCADA", 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[1].element": 12, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.size": 5, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.service": 83, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.write_frag.data": [ 16585 ], 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.write_frag.elements": 1, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.write_frag.offset": 0, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.write_frag.type": 195, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 22, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 6, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
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
                unk_023_request,
                {
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 32, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].length": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[0].symbolic": "SCADA", 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.segment[1].element": 12, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.path.size": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.elements": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.read_frag.offset": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.Tag.service": 82, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 18, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
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
    for pkt,tst in cip_tests:
        # Parse just the CIP portion following the EtherNet/IP encapsulation header
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.enip_header( 'header', context='enip' ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        # In a real protocol implementation, an empty header (EOF with no input at all) is
        # acceptable; it indicates a session closed by the client.
        if not data:
            log.normal( "EtherNet/IP Request: Empty (session terminated): %s", enip.enip_format( data ))
            continue
            
        # We're not parsing an encapsulated.input; we're parsing from the same stream, so
        # create the 
        data.enip.encapsulated	= cpppo.dotdict()
        with enip.CIP() as machine:
            for i,(m,s) in enumerate( machine.run( path='enip', source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )

        log.normal( "EtherNet/IP CIP Request: %s", enip.enip_format( data ))
        try:
            for k,v in tst.items():
                assert data[k] == v
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise
            

def test_enip_device_symbolic():
    enip.device.symbol['SCADA'] = {'class':0x401, 'instance':1, 'attribute':2}
    path={'segment':[{'symbolic':'SCADA'}, {'element':4}]}
    assert enip.device.resolve( path, attribute=True ) == (0x401,1,2)
    assert enip.device.resolve( path ) == (0x401,1,None)

    try:
        result			= enip.device.resolve(
            {'segment':[{'class':5},{'symbolic':'SCADA','length':5},{'element':4}]} )
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
    log.normal( "New Identity Instance directory: %s", json.dumps(
        attrs, indent=4, sort_keys=True,  default=lambda obj: repr( obj )))
    assert attrs['7'].produce() == b'\x141756-L61/B LOGIX5561'
    
    gaa				= Ix.request( cpppo.dotdict({'service': 0x01 }))
    log.normal( "Identity Get Attributes All: %r", gaa )
    assert gaa == b'\x01\x00\x0e\x006\x00\x14\x0b`1\x1a\x06l\x00\x141756-L61/B LOGIX5561'

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
    Obj				= logix.Logix_Data()
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'Something', enip.parser.INT, default=[n for n in range( 100 )])

    assert len( Obj_a1 ) == 100

    # Set up a symbolic tag referencing the Logix_Data Object's Attribute
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

    # If we ask a Logix_Data Object to process the request, it should respond.
    proceed			= Obj.request( data )
    log.normal("Logix Request processed: %s", enip.enip_format( data ))


# Run the bench-test.  Sends some request from a bunch of clients to a server, testing responses

def enip_process_canned( addr, source, data ):
    """Process a request, recognizing a subset of the known requests, and returning a "canned"
    response."""
    if not data:
        log.normal( "EtherNet/IP Request Empty; end of session" )
        return False

    log.detail( "EtherNet/IP Request: %s", enip.parser.enip_format( data.request ))
    if data.request.enip.command == 0x0065:
        source			= cpppo.chainable( rss_004_reply )
        with enip.enip_machine() as machine: # Load data.response.enip
            for m,s in machine.run( path='response', source=source, data=data ):
                pass
            if machine.terminal:
                log.debug( "EtherNet/IP Response: %s", enip.parser.enip_format( data.response ))
        return True

    raise Exception( "Unrecognized request: %s" % ( enip.parser.enip_format( data )))

# The default Client will wait for draindelay after 
client_count, client_max	= 15, 10
charrange, chardelay		= (2,10), .1	# split/delay outgoing msgs
draindelay			= 10.  		# long in case server very slow (eg. logging), but immediately upon EOF

def enip_cli( number, tests=None ):
    """Sends a series of test messages, testing response for expected results."""
    log.info( "EhterNet/IP Client %3d connecting... PID [%5d]", number, os.getpid() )
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
            ( rss_004_request, {
                'response.enip.command':	 	0x0065,
                #'response.enip.session_handle':	285351425, # Server generates
            }),
        ]
}

enip_svr_kwds_logix 		= { 
    'enip_process': 	logix.process,
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
    test_enip_bench()

