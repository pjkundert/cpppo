from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import array
import codecs
import logging
import os
import platform
import pytest
import random
import socket
import sys
import traceback

is_pypy				= platform.python_implementation() == "PyPy"

has_pylogix			= False
try:
    import pylogix
    has_pylogix			= True
except Exception:
    pass

# for @profile, kernprof.py -v -l enip_test.py
#from line_profiler import LineProfiler

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    if __package__ is None:
        __package__ = "cpppo.server"
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )

import cpppo
from   cpppo.misc import hexdump
from   cpppo.server import network, enip
from   cpppo.server.enip import parser, device, logix, client, pccc

log				= logging.getLogger( "enip" )

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
    if sys.version_info[0] < 3:
        assert data.octets.five.input.tostring() == b'abc12'
    else:
        assert data.octets.five.input.tobytes() == b'abc12'


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
    if sys.version_info[0] < 3:
        assert data.octets.singly.input.tostring() == b'abc12'
    else:
        assert data.octets.singly.input.tobytes() == b'abc12'

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
    if sys.version_info[0] < 3:
        assert data.words.singly.input.tostring() == b'abc123'
    else:
        assert data.words.singly.input.tobytes() == b'abc123'


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

def test_enip_TYPES_SSTRING():

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

    pkt				= res
    data			= cpppo.dotdict()
    source			= cpppo.chainable( pkt )
    with enip.SSTRING() as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 3
    assert data.SSTRING.length == 0
    assert data.SSTRING.string == ''

    # 3 x 0-length SSTRING followed by 'a'
    pkt				= b'\x00\x00\x00\x01a'
    data			= cpppo.dotdict()
    source			= cpppo.chainable( pkt )
    with enip.typed_data( tag_type=enip.SSTRING.tag_type, terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 33
    assert len( data.typed_data.data ) == 4
    assert data.typed_data.data == ['','','','a']


def test_enip_TYPES_numeric():
    pkt				= b'\x01\x00\x02\x00\x03\x00'
    data			= cpppo.dotdict()
    source			= cpppo.chainable( pkt )
    with enip.INT() as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 1
    assert data.INT == 1

    # 4 x REAL
    pkt				= b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data			= cpppo.dotdict()
    source			= cpppo.chainable( pkt )
    with enip.typed_data( tag_type=enip.REAL.tag_type, terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert i == 32
    assert len( data.typed_data.data ) == 4
    assert data.typed_data.data == [0.0]*4


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

#                                o     \x00  \xa6 \x01 \xa6 \x1c \xf9 \xf5 \x00 \x00
#   \x00 \x00 0    \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x02 \x00
#   \x00 \x00 \x00 \x00 \xb2 \x00 \x96 \x01  \xcc \x00 \x00 \x00 \xc3 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00
#   \x00 \x00 \x00 \x00 \x00 \x00 \x00 \x00  \x00 \x00 \x00 \x00 \x00 \x00'
rtg_001_reply			= bytes(bytearray([
                                  0x6f,0x00, 0xa6,0x01,0xa6,0x1c,0xf9,0xf5,0x00,0x00,
    0x00,0x00,0x30,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
    0x00,0x00,0x00,0x00,0xb2,0x00,0x96,0x01, 0xcc,0x00,0x00,0x00,0xc3,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00
]))

wtg_001_request			= bytes(bytearray([
  # 0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,  # ....E..s..@.@...
  # 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xd1, 0x55, 0xaf, 0x12, 0xda, 0x64, 0xfb, 0xa8,  # .........U...d..
  # 0x91, 0x4f, 0x50, 0xd7, 0x80, 0x18, 0x18, 0xe8, 0xfe, 0x67, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a,  # .OP......g......
  # 0x3b, 0x90, 0x9d, 0x4a, 0x3b, 0x90, 0x9d, 0x4a, 
                                                    0x70, 0x00, 0x27, 0x00, 0x01, 0x85, 0x02, 0x14,  # ;..J;..Jp.'.....
    0x00, 0x00, 0x00, 0x00, 0x6e, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ....no..........
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0xa1, 0x00, 0x04, 0x00, 0x02, 0x8f, 0x97, 0x01,  # ................
    0xb1, 0x00, 0x13, 0x00, 0x02, 0x00, 0x4d, 0x05, 0x91, 0x07, 0x49, 0x54, 0x45, 0x53, 0x54, 0x4f,  # ......M...ITESTO
    0x50, 0x00, 0xc1, 0x00, 0x01, 0x00, 0x01,                                                        # P......
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
            ( rtg_001_reply,	{} ),
            ( wtg_001_request,	{} ),
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
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))

@pytest.mark.skipif( is_pypy, reason="Not yet supported under PyPy" )
def test_enip_machine():
    ENIP			= enip.enip_machine( context='enip' )
    for pkt,tst in eip_tests:
        # Parse the headers and encapsulated command data
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with ENIP as machine:
            engine		= machine.run( source=source, data=data )
            try:
                for i,(m,s) in enumerate( engine ):
                    log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                              machine.name_centered(), i, s, source.sent, source.peek(), data )
                    if s is None and source.peek() is None:
                        break # simulate detection of EOF
            finally:
                engine.close()
                del engine
            if not pkt:
                assert i == 2		# enip_machine / enip_header reports state
            else:
                pass 			# varies...
        assert source.peek() is None
   
        log.normal( "EtherNet/IP Request: %s", enip.enip_format( data ))
        try:
            for k,v in tst.items():
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # Ensure we can reproduce the original packet from the parsed data (placed in .enip)
        if data:
            assert enip.enip_encode( data.enip ) == pkt, "Invalid data: %r" % data

extpath_0		= bytes(bytearray([
    0x00,						# 0 words
]))
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
extpath_9		= bytes(bytearray([
    # From LEC-GEN1_v1 EDS
    0x04,		# 4 words
    0x20, 0x04,		# Class ID 0x04 -- Assembly
    0x24, 0x05,		# Instance 5
    0x2C, 0x03,		# Connection Point 3
    0x2C, 0x64,		# Connection Point 100
]))
# The byte order of EtherNet/IP CIP data is little-endian; the lowest-order byte
# of the value arrives first.
extpath_tests			= [
            ( extpath_0, enip.EPATH,	{
                'request.EPATH.size': 0,
            } ),
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
            ( extpath_9, enip.EPATH, {
                'request.EPATH.size': 4,
                'request.EPATH.segment': [
                    {'class':		4 },
                    {'instance':	5 },
                    {'connection':	3 },
                    {'connection':    100 },
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
        log.info( "Testing %s against %r", cls.__name__, pkt )
        with cls() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        try:
            for k,v in tst.items():
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # And, ensure that we can get the original EPATH back (ignoring extra decoy bytes)
        if not prod:
            prod		= pkt[:(2 if cls is enip.route_path else 1)+data.request[cls.__name__].size*2]

        out			= cls.produce( data.request[cls.__name__] )
        assert out == prod, \
            "Invalid EPATH data: %r\nexpect: %r\nactual: %r" % ( data, prod, out )


commserv_1			= bytes(bytearray([
    0x01, 0x00, 0x20, 0x00, b'C'[0], b'o'[0], b'm'[0], b'm'[0],
     b'u'[0], b'n'[0], b'i'[0], b'c'[0], b'a'[0], b't'[0], b'i'[0], b'o'[0],
     b'n'[0], b's'[0], 0x00,
    ]))

def test_enip_listservices():
    # The CPF item produced by the ListServices command is the "Communications"
    # item (type_id = 0x0100).
    
    data			= cpppo.dotdict()
    data.type_id		= 0x0100
    data.length			= 0
    data.version		= 1
    data.capability		= 0x0001 << 5 # CIP encapsulation only
    data.service_name		= 'Communications'

    result			= parser.communications_service.produce( data )
    
    assert result == commserv_1


    data			= cpppo.dotdict()
    source			= cpppo.chainable( commserv_1 )

    with parser.communications_service( terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 24
    assert source.peek() is None
    assert 'communications_service' in data
    assert data.communications_service.version == 1
    assert data.communications_service.service_name == 'Communications'

    # Minimal ListServices request is empty
    data			= cpppo.dotdict()
    source			= cpppo.chainable( b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Funstuff\x00\x00\x00\x00' )
    with enip.enip_machine( context='enip' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
    assert source.peek() is None
    assert data.enip.command == 0x0004
    assert data.enip.length  == 0


def escaped_chunks_to_bytes( escaped, chunk=4 ):
    """Produce un-escapbed bytes from an escaped, padded, chunked input like br'c___\x01\n__'.
    Providing just padding produces the pad symbol, eg.  '____' --> '_'.

    """
    assert len( escaped ) % chunk == 0, \
        "escaped bytes of length %d must be divisible by chunk %d" % ( len( escaped ), chunk )
    def escape_decode( chk ):
        res,_			= codecs.escape_decode( chk.strip( b'_' ) or b'_' )
        assert len( res ) == 1, \
            "escaped chunk %r must yield 1 byte result instead of %d-byte %r" % ( chk, len( res ), res )
        return res
    return b''.join( escape_decode( escaped[i:i+chunk] )
                     for i in range( 0, len( escaped ), chunk ))

listident_1_req			= escaped_chunks_to_bytes(
        br'''c___\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
)
# PowerFlex 753 List Identity reply, with (corrected) EtherNet/IP framing and CPF framing errors...
listident_1_rpy			= escaped_chunks_to_bytes(
        #              vv      -- EtherNet/IP frame size wrong (was \x00\x00)...
        br'''c___\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
        #                    v -- CPF item size wrong (was '___\x00)...
        br'''\x01\x00\x0c\x00B___\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00{___\x00\x90\x04\x0b\x01a___\x05\x15\x1dI___\x80 ___P___o___w___e___r___F___l___e___x___'''
        br''' ___7___5___3___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___\xff'''
)
listident_1_rpy_bad_CPF_framing	= escaped_chunks_to_bytes(
        #              vv      -- EtherNet/IP frame size wrong (was \x00\x00)...
        br'''c___\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
        #                    v -- CPF item size wrong; will truncate 'product_name', omit 'state'
        br'''\x01\x00\x0c\x00'___\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00{___\x00\x90\x04\x0b\x01a___\x05\x15\x1dI___\x80 ___P___o___w___e___r___F___l___e___x___'''
        br''' ___7___5___3___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___\xff'''
)
# *Logix 1796 List Identity reply, with no errors...
listident_2_rpy			= escaped_chunks_to_bytes(
        br'''c___\x00E___\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00\x0c\x00?___\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00\x0e\x00\x95\x00\x1b\x0b0___\x00^___3___\x1e\xc0\x1d1___7___6___9___-___L___2___4___E___'''
        br'''R___-___Q___B___1___B___/___A___ ___L___O___G___I___X___5___3___2___4___E___R___\x03'''
)
# *Logix 1796 List Identity reply, with extra payload (ignored)...
listident_3_rpy			= escaped_chunks_to_bytes(
        br'''c___\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00\x0c\x00\x42\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x01\x00\x0e\x00\x95\x00\x1b\x0b0___\x00^___3___\x1e\xc0\x1d1___7___6___9___-___L___2___4___E___'''
        br'''R___-___Q___B___1___B___/___A___ ___L___O___G___I___X___5___3___2___4___E___R___\x03\x01\x02\x03'''
)


def test_enip_listidentity():
    # The CPF item produced by the ListIdentity command has item (type_id = 0x000C).

    data			= cpppo.dotdict()
    data.version		= 0x0001
    data.sin_family		= 0x0002				# (network byte order)
    data.sin_port		= 44818					# (network byte order)
    data.sin_addr		= "10.161.1.5"				# (network byte order) 10.161.1.5
    data.vendor_id		= 0x0001 # AB
    data.device_type		= 0x007B
    data.product_code		= 0x0490
    data.product_revision	= 0x010b
    data.status_word		= 0x0561
    data.serial_number		= 0x80491D15
    data.product_name		= "PowerFlex 753                   "	# 32 characters
    data.state			= 0xFF

    result			= parser.identity_object.produce( data )
    
    assert result == listident_1_rpy[30:] # 24-byte EtherNet/IP header + 6-byte CPF count/size/type

    # Minimal ListIdentity request is empty
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listident_1_req )
    with enip.enip_machine( context='enip' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
    assert source.peek() is None
    assert data.enip.command == 0x0063
    assert data.enip.length  == 0

    # ListIdentity reply
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listident_1_rpy )
    with enip.enip_machine( context='enip' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
    assert source.peek() is None
    assert data.enip.command == 0x0063
    assert data.enip.length  == 72
    
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listident_1_rpy[30:] )
    with parser.identity_object( terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 83
    assert source.peek() is None
    assert 'identity_object' in data
    assert data.identity_object.product_name == "PowerFlex 753                   "

    # Lets make sure we can handle requests with bad CPF item framing, such as from PowerFlex...
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listident_1_rpy_bad_CPF_framing[30:] )
    with parser.identity_object( terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 83
    assert source.peek() is None
    assert 'identity_object' in data
    assert data.identity_object.product_name == "PowerFlex 753                   "

    data			= cpppo.dotdict()
    source			= cpppo.chainable( listident_2_rpy[30:] )
    with parser.identity_object( terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 80
    assert source.peek() is None
    assert 'identity_object' in data
    assert data.identity_object.product_name == "1769-L24ER-QB1B/A LOGIX5324ER"


# Basic empty List Interfaces request and response...
listifaces_1_req		= escaped_chunks_to_bytes(
        br'''\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
)
listifaces_1_rpy		= escaped_chunks_to_bytes(
        br'''\x64\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'''
        br'''\x00\x00'''
)

def test_enip_listinterfaces():
    # Minimal ListInterfaces request is empty
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listifaces_1_req )
    with enip.enip_machine( context='enip' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
    assert source.peek() is None
    assert data.enip.command == 0x0064
    assert data.enip.length  == 0

    # ListIdentity reply
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listifaces_1_rpy )
    with enip.enip_machine( context='enip' ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
    assert source.peek() is None
    assert data.enip.command == 0x0064
    assert data.enip.length  == 2

    # The CPF payload hasn't been parsed...
    data			= cpppo.dotdict()
    source			= cpppo.chainable( listifaces_1_rpy[24:] )
    with parser.list_identity( terminal=True ) as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                      i, s, source.sent, source.peek(), data )
        assert machine.terminal, "%s: Should have reached terminal state" % machine.name_centered()
        assert i == 7
    assert source.peek() is None
    assert data.list_identity.CPF.count == 0


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

multiple_1_rpy			= bytes(bytearray([
    0x8a,     0x00,     0x00,     0x00,     0x11,     0x00, ord('$'),     0x00, ord('('),
    0x00, ord(','),     0x00, ord('0'),     0x00, ord('4'),     0x00, ord('@'),     0x00,
ord('D'),     0x00, ord('R'),     0x00, ord('b'),     0x00, ord('f'),     0x00, ord('j'),
    0x00, ord('t'),     0x00, ord('x'),     0x00, ord('|'),     0x00,     0x80,     0x00,
    0x8e,     0x00,     0x9c,     0x00,     0xcd,     0x00,     0x00,     0x00,     0xd3,
    0x00,     0x00,     0x00,     0xcd,     0x00,     0x00,     0x00,     0xcd,     0x00,
    0x00,     0x00,     0xcc,     0x00,     0x00,     0x00,     0xc3,     0x00,     0x00,
    0x00,     0x00,     0x00,     0x00,     0x00,     0xcd,     0x00,     0x00,     0x00,
    0xcc,     0x00,     0x00,     0x00,     0xc3,     0x00,     0x00,     0x00,     0x00,
    0x00,     0x00,     0x00,     0x00,     0x00,     0xcc,     0x00,     0x00,     0x00,
    0xc3,     0x00,     0x00,     0x00, ord('a'),     0x00, ord('b'),     0x00, ord('c'),
    0x00,     0x00,     0x00,     0xcd,     0x00,     0x00,     0x00,     0xcd,     0x00,
    0x00,     0x00,     0xcc,     0x00,     0x00,     0x00,     0xc3,     0x00,     0x00,
    0x00,     0x00,     0x00,     0xcd,     0x00,     0x00,     0x00,     0xcd,     0x00,
    0x00,     0x00,     0xcd,     0x00,     0x00,     0x00,     0xd2,     0x00,     0x00,
    0x00,     0xc3,     0x00, ord('a'),     0x03, ord('b'),     0x03,     0x00,     0x00,
    0x00,     0x00,     0xcc,     0x00,     0x00,     0x00,     0xc3,     0x00,     0x00,
    0x00,     0x00,     0x00,     0x00,     0x00,     0x00,     0x00,     0xcc,     0x00,
    0x00,     0x00,     0xc3,     0x00,     0x00,     0x00
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
    ),(
        multiple_1_rpy, {},
    )
]

def test_enip_Logix():
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    logix.Logix( instance_id=1 )

    for pkt,tst in tag_tests:
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with logix.Logix.parser as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        try:
            for k,v in tst.items():
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise

        # And, ensure that we can get the original Logix req/rpy back (ignoring extra decoy bytes)
        try:
            assert logix.Logix.produce( data.request ) == pkt
        except:
            log.warning ( "Invalid packet produced from logix data: %s", enip.enip_format( data ))
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
gal_3				= bytes(bytearray([ # get_attribute_list
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x14, 0x00, 0x52, 0x02, #/* ......R. */
    0x20, 0x06, 0x24, 0x01, # path 0x06/1

                            0x02, 0xfa, 0x06, 0x00, #/*  .$..... */
    0x01, 0x02, 0x20, 0x01, 0x24, 0x01, 0x01, 0x00, #/* .. .$... */
    0x01, 0x00                                      #/* .. */
]))
gal_2_rpy	 		= bytes(bytearray([ # get_attribute_list reply
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x27, 0x00, 0x81, 0x00, #/* ....'... */
    0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x36, 0x00, #/* ......6. */
    0x14, 0x0b, 0x60, 0x31, 0x1a, 0x06, 0x6c, 0x00, #/* ..`1..l. */
    0x14, 0x31, 0x37, 0x35, 0x36, 0x2d, 0x4c, 0x36, #/* .1756-L6 */
    0x31, 0x2f, 0x42, 0x20, 0x4c, 0x4f, 0x47, 0x49, #/* 1/B LOGI */
    0x58, 0x35, 0x35, 0x36, 0x31                    #/* X5561 */
]))


mlx_0_request			= bytes(bytearray([ # MicroLogix request
                            0x02, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0xb2, 0x00, 0x2E, 0x00,             #/* ......   */ length: 46 (0x2E)

    b'T'[0],   0x02, b' '[0],    0x06, b'$'[0],    0x01, b'\n'[0],   0x0e,
    # ^ 0x54 Forward Open
    # (wrong...  See Vol 1, Table 3-5.16 for request format)
    #     ^^^^- 2 word request path
    #            ^^^^^^^^^- Class 0x06
    #                       ^^^^^^^^^- Instance 0x0e (14)
    b'O'[0],   0xaf,    0x87,    0xf4,    0x06,    0xaf,    0x87,    0xf4,
    0xb2,   b'U'[0],    0x01,    0x00,    0xc4,    0x8b, b'O'[0], b'@'[0],
    0x02,      0x00,    0x00,    0x00,    0xc0,    0xc6, b'-'[0],    0x00,
    0x02,   b'C'[0],    0xc0,    0xc6, b'-'[0],    0x00,    0x02, b'C'[0],
    0xa3,      0x02, b' '[0],    0x02, b'$'[0],    0x01,
]))

cpf_type_0x0001			= bytes(bytearray([ # EtherNet/IP command 0x0001 (undocumented) reply
                                                                                        0x01, 0x00,  #               ..
    0x01, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaf, 0x12, 0xc0, 0xa8, 0x05, 0xfd,  # ..$.............
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e,  # ........192.168.
    0x35, 0x2e, 0x32, 0x35, 0x33, 0x00, 0x00, 0x00,                                                  # 5.253...]
]))


CPF_tests			= [
    (
        b'',
        {
            "CPF": {},
        }
    ), (
        gal_2_rpy,
        {
            "CPF.count": 2,
            "CPF.item[0].type_id": 0,
            "CPF.item[0].length": 0,
            "CPF.item[1].type_id": 178,
            "CPF.item[1].length": 39,
            "CPF.item[1].unconnected_send.request.service": 129,
            "CPF.item[1].unconnected_send.request.status": 0,
            "CPF.item[1].unconnected_send.request.status_ext.size": 0,
            "CPF.item[1].unconnected_send.request.get_attributes_all.data": [
                1,
                0,
                14,
                0,
                54,
                0,
                20,
                11,
                96,
                49,
                26,
                6,
                108,
                0,
                20,
                49,
                55,
                53,
                54,
                45,
                76,
                54,
                49,
                47,
                66,
                32,
                76,
                79,
                71,
                73,
                88,
                53,
                53,
                54,
                49
            ]
        }
    ), (
        cpf_type_0x0001,
        {
            "CPF.count": 1, 
            "CPF.item[0].type_id": 1, 
            "CPF.item[0].length": 36, 
            "CPF.item[0].legacy_CPF_0x0001.version": 1, 
            "CPF.item[0].legacy_CPF_0x0001.unknown_1": 0, 
            "CPF.item[0].legacy_CPF_0x0001.sin_family": 2, 
            "CPF.item[0].legacy_CPF_0x0001.sin_port": 44818, 
            "CPF.item[0].legacy_CPF_0x0001.sin_addr": "192.168.5.253", 
            "CPF.item[0].legacy_CPF_0x0001.ip_address": "192.168.5.253"
        }
    ), (
        b'\x00\x00',
        # ^^^^^^^^ count == 0.  No item list is generated/required
        {
            "CPF.count": 0,
        }
    ), (
        b'\x01\x00\x00\x01\x08\x00\x03\x00\x04\x00abc\0',
        # ^^^^^^^^ count == 1
        #         ^^^^^^^^ type_id == 0x0100
        #                 ^^^^^^^^ length == 8
        #                         ^^^^^^^^ version == 3
        #                                  ^^^^^^^^ capability == 4
        #                                          ^^^^^ service_name == abc\0
        {
            "CPF.count": 1,
            "CPF.item[0].length": 8,
            "CPF.item[0].type_id": 0x0100,
            "CPF.item[0].communications_service.version": 3,
            "CPF.item[0].communications_service.capability": 4,
            "CPF.item[0].communications_service.service_name": "abc",
        }
    ), (
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
        assert 'CPF' in data
        if 'item' in data.CPF:
          for item in data.CPF.item:
            if 'unconnected_send' in item:
                assert 'request' in item.unconnected_send # the encapsulated request
                with logix.Logix.parser as machine:
                    log.normal( "Parsing %3d bytes using %s.parser, from %s", len( item.unconnected_send.request.input ),
                                logix.Logix.__name__, enip.enip_format( item ))
                    # Parse the unconnected_send.request.input octets, putting parsed items into the
                    # same request context
                    for i,(m,s) in enumerate( machine.run( source=cpppo.peekable( item.unconnected_send.request.input ),
                                                           data=item.unconnected_send.request )):
                        log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                                    machine.name_centered(), i, s, source.sent, source.peek(), data )
                    log.normal( "Parsed  %3d bytes using %s.parser, into %s", len( item.unconnected_send.request.input ),
                                logix.Logix.__name__, enip.enip_format( data ))

        try:
            for k,v in tst.items():
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))
        except:
            log.warning( "%r not in data, or != %r: %s", k, v, enip.enip_format( data ))
            raise


        # Ensure that we can get the original CPF back
        for k in list(data.keys()):
            if k.endswith( 'input' ):
                log.detail( "del data[%r]", k )
                del data[k]
        try:
            if 'item' in data.CPF:
              for item in data.CPF.item:
                if 'unconnected_send' in item:
                    item.unconnected_send.request.input	= bytearray( logix.Logix.produce( item.unconnected_send.request ))
                    log.normal("Produce Logix message from: %r", item.unconnected_send.request )
            log.normal( "Produce CPF message from: %r", data.CPF )
            data.input		= bytearray( enip.CPF.produce( data.CPF )) 
            assert data.input == pkt
        except:
            log.warning ( "Invalid packet produced from EtherNet/IP CPF data: %r", data )
            raise


# These Get Attribute Single requests are in a SendRRData (0x006f) encapsulation, but not
# encapsulated in an Unconnected Send (0x52) encapsulation; hence no send_path, route_path.
gas_001_request		= bytes(bytearray([
    0x6f, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x08, 0x00,
    0x0e, 0x03, 0x20, 0x93, 0x24, 0x0b, 0x30, 0x0a,
]))

gas_001_reply		= bytes(bytearray([
    0x6f, 0x00, 0x18, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0d, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x08, 0x00,
    0x8e, 0x00, 0x00, 0x00, 0x0a, 0xd7, 0xa3, 0x3d,
]))

# These Get Attribute Single are also only in SendRRData (0x006f) encapsulation, and also Multiple
# Packet Service encapsulation (rejected by PowerFlex; no Message Router Object 0x02/1)
gas_m01_request		= bytes(bytearray([
    0x6f, 0x00, 0x36, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x26, 0x00,
    0x0a, 0x02, 0x20, 0x02, 0x24, 0x01, 0x03, 0x00,
    0x08, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0e, 0x03,
    0x20, 0x93, 0x24, 0x0b, 0x30, 0x0a, 0x0e, 0x03,
    0x20, 0x93, 0x24, 0x03, 0x30, 0x0a, 0x0e, 0x03,
    0x20, 0x93, 0x24, 0x01, 0x30, 0x0a,
]))

gas_m01_reply		= bytes(bytearray([
    0x6f, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x04, 0x00,
    0x8a, 0x00, 0x08, 0x00,
]))

# A Multiple Packet Service containing a Get Attribute List
gal_m01_request		= b'p\x00\xec\x01fM\xf4\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xa1\x00\x04\x00~\xa1;\x8f\xb1\x00\xd8\x01P)\n\x02 \x02$\x01\x17\x000\x00<\x00N\x00`\x00p\x00\x84\x00\xa2\x00\xb6\x00\xc8\x00\xd8\x00\xe8\x00\xfa\x00\n\x01\x1a\x01*\x01<\x01Z\x01l\x01~\x01\x90\x01\xa0\x01\xb0\x01\xc0\x01\x03\x02 \xac$\x01\x02\x00\x01\x00\x03\x00R\x05\x91\x08LFF26E7C\x01\x00\x00\x00\x00\x00R\x05\x91\x07I86LFMC\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x05I23LF\x00\x01\x00\x00\x00\x00\x00R\x06\x91\nLFF26LF1_A\x01\x00\x00\x00\x00\x00R\x0b\x91\x13BOVMANUALSTROKE_HMI\x00\x01\x00\x00\x00\x00\x00R\x06\x91\tLFF26E14C\x00\x01\x00\x00\x00\x00\x00R\x05\x91\x07A63GGCD\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x06ACT101\x01\x00\x00\x00\x00\x00R\x04\x91\x06ACT100\x01\x00\x00\x00\x00\x00R\x05\x91\x07A26E17C\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x06L1ACTC\x01\x00\x00\x00\x00\x00R\x04\x91\x06N3OSPD\x01\x00\x00\x00\x00\x00R\x04\x91\x06H1ACTM\x01\x00\x00\x00\x00\x00R\x05\x91\x07C75QGGC\x00\x01\x00\x00\x00\x00\x00R\x0b\x91\x13IGVMANUALSTROKE_HMI\x00\x01\x00\x00\x00\x00\x00R\x05\x91\x08A26FG1_A\x01\x00\x00\x00\x00\x00R\x05\x91\x07A99GG2B\x00\x01\x00\x00\x00\x00\x00R\x05\x91\x07A99GG2A\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x05SSS63\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x05SSS62\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x05SSS61\x00\x01\x00\x00\x00\x00\x00R\x04\x91\x06TGLSET\x01\x00\x00\x00\x00\x00'
    

# EtherNet/IP CIP Legacy command 0x0001 reply
leg_0x1_reply		= bytes(bytearray([
                      0x01, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                    #       ..*.......
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,  # ................
    0x01, 0x00, 0x24, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xaf, 0x12, 0xc0, 0xa8, 0x05, 0xfd,  # ..$.............
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e,  # ........192.168.
    0x35, 0x2e, 0x32, 0x35, 0x33, 0x00, 0x00, 0x00,                                                  # 5.253...]
]))

fwd_o01_request		= bytes(bytearray([
                                        0x6f, 0x00, 0x40, 0x00, 0x05, 0x00, 0x0d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xd0, 0x92, 0x00, 0x00, 0x50, 0x80, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x30, 0x00, 0x54, 0x02,
    0x20, 0x06, 0x24, 0x01, 0x07, 0xf9, 0x11, 0x00, 0x00, 0x80, 0x10, 0x00, 0xfe, 0x80, 0x11, 0x00,
    0x4d, 0x00, 0x0f, 0x7f, 0x3d, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x7a, 0x00, 0xf4, 0x43,
    0x00, 0x12, 0x7a, 0x00, 0xf4, 0x43, 0xa3, 0x03, 0x01, 0x00, 0x20, 0x02, 0x24, 0x01,
]))

fwd_o01_reply		= bytes(bytearray([
                                        0x6f, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x0d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xd0, 0x92, 0x00, 0x00, 0x50, 0x80, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0xd4, 0x00,
    0x00, 0x00, 0x26, 0x40, 0xa3, 0xff, 0x10, 0x00, 0xfe, 0x80, 0x11, 0x00, 0x4d, 0x00, 0x0f, 0x7f,
    0x3d, 0x1e, 0x00, 0x12, 0x7a, 0x00, 0x00, 0x12, 0x7a, 0x00, 0x00, 0x00,
]))

# Initial attempts added an extra 0x52 wrapper around the forward_open:
fwd_o02_request_bad	= bytes(bytearray([
                                        0x6f, 0x00, 0x4e, 0x00, 0x05, 0x00, 0x13, 0x00, 0x00, 0x00,  #...T..o.N.......
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  #................
    0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x3e, 0x00, 0x52, 0x02,  #............>.R.
    0x20, 0x06, 0x24, 0x01, 0x05, 0xf7, 0x30, 0x00, 0x54, 0x02, 0x20, 0x06, 0x24, 0x01, 0x07, 0xf9,  # .$...0.T. .$...
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x4d, 0x00, 0x0f, 0x7f, 0x3d, 0x1e,  #..........M...=.
    0xa3, 0x00, 0x00, 0x00, 0x00, 0x12, 0x7a, 0x00, 0xf4, 0x43, 0x00, 0x12, 0x7a, 0x00, 0xf4, 0x43,  #......z..C..z..C
    0xa3, 0x03, 0x01, 0x00, 0x20, 0x02, 0x24, 0x01, 0x01, 0x00, 0x01, 0x00,                          #.... .$.....
]))

# Forward Open from RSLinx to ANC-120e DH+ interface (except w/ 0x00 for reserved padding instead of 0x01)
fwd_o02_request		= bytes(bytearray([
                                        0x6f, 0x00, 0x42, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc2, 0x0a, 0x00, 0x00, 0xa0, 0xde, 0x79, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x32, 0x00, 0x54, 0x02,
    0x20, 0x06, 0x24, 0x01, 0x07, 0x9b, 0x05, 0x00, 0x00, 0x80, 0x04, 0x00, 0x00, 0x80, 0x05, 0x00,
    0x4d, 0x00, 0x37, 0x58, 0x5a, 0x38, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x3d, 0x00, 0x02, 0x43,
    #                                           ^^    ^^    ^^
    0x00, 0x09, 0x3d, 0x00, 0x02, 0x43, 0xa3, 0x04, 0x01, 0x01, 0x20, 0xa6, 0x24, 0x01, 0x2c, 0x01,
]))

fwd_o02_reply		= bytes(bytearray([
                                        0x6f, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc2, 0x0a, 0x00, 0x00, 0xa0, 0xde, 0x79, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb2, 0x00, 0x1e, 0x00, 0xd4, 0x00,
    0x00, 0x00, 0x16, 0x00, 0xee, 0x8d, 0x04, 0x00, 0x00, 0x80, 0x05, 0x00, 0x4d, 0x00, 0x37, 0x58,
    0x5a, 0x38, 0x00, 0x09, 0x3d, 0x00, 0x00, 0x09, 0x3d, 0x00, 0x00, 0x00,
]))

fwd_c01_request			= b'o\x00(\x00g\x16\xc5H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x18\x00N\x02 \x06$\x01\x07\xf9\x01\x00M\x00\x0f\x7f=\x1e\x03\x00\x01\x00 \x02$\x01'

# Forward Open failures

# Incorrect connection path leads to a status + status_ext, w/ the optional remaining_path_size payload and without
fwd_f01_request_bad		= b'o\x00<\x00\x00b\x02\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\xb2\x00,\x00T\x02 \x06$\x01\x07\xf9\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xffxV4\x12\x00\x00\x00\x00\xf4C\x00\x00\xf4C\x80\x84\x1e\x00\xf4C\xa3\x01\x01\x00'
fwd_f01_reply			= b'o\x00\x20\x00\x00b\x02\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x10\x00\xd4\x00\x01\x01\x11\x03\x00\x00\xff\xffxV4\x12\x01\x00'
fwd_f01_reply_no_remain		= b'o\x00\x1E\x00\x00b\x02\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x0E\x00\xd4\x00\x01\x01\x11\x03\x00\x00\xff\xffxV4\x12'

# Forward close with failure status only; have seen from C*Logix
fwd_clo_reply_just_sts		= b'o\x00\x16\x00\x02\\\x02\x14\x00\x00\x00\x00open_ex.\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x06\x00\xce\x00\x01\x01\x00\x01'

# Send Unit Data for DH+ I/O: PCCC via EtherNet/IP, via the Forward Open (above)
snd_u01_req		= bytes(bytearray([
      0x70, 0x00, 0x23, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
      0xa1, 0x00, 0x04, 0x00, 0x16, 0x00, 0xee, 0x8d,
      0xb1, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
      0x4a, 0x0a, 0x03
]))

snd_u01_rpy		= bytes(bytearray([
      0x70, 0x00, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
      0xa1, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x80,
      0xb1, 0x00, 0x26, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x46, 0x00,
      0x4a, 0x0a, 0x00, 0xee, 0x31, 0x5b, 0x23, 0x35,
      0x2f, 0x30, 0x34, 0x20, 0x20, 0x20, 0x20, 0x20,
      0x20, 0x20, 0x56, 0x00, 0x91, 0x24, 0x05, 0x44,
      0x20, 0xfc
]))
 

CIP_tests			= [
            ( 
                # An empty request (usually indicates termination of session)
                b'', enip.Message_Router, {}
            ), (
                wtg_001_request, logix.Logix,
                {
                    "enip.command": 112,
                    "enip.length": 39,
                    "enip.session_handle": 335709441,
                    "enip.status": 0,
                    "enip.options": 0,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.timeout": 0,
                    "enip.CIP.send_data.CPF.count": 2,
                    "enip.CIP.send_data.CPF.item[0].type_id": 161,
                    "enip.CIP.send_data.CPF.item[0].length": 4,
                    "enip.CIP.send_data.CPF.item[0].connection_ID.connection": 26709762,
                    "enip.CIP.send_data.CPF.item[1].type_id": 177,
                    "enip.CIP.send_data.CPF.item[1].length": 19,
                    "enip.CIP.send_data.CPF.item[1].connection_data.sequence": 2,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.service": 77,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.path.size": 5,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[0].symbolic": "ITESTOP",
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.write_tag.type": 193,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.write_tag.elements": 1,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.write_tag.data": [
                        True
                    ]
                }
            ), (
                snd_u01_req, pccc.PCCC_ANC_120e,
                {
                    "enip.status": 0,
                    "enip.session_handle": 1,
                    "enip.options": 0,
                    "enip.length": 35,
                    "enip.command": 112,
                    "enip.CIP.send_data.timeout": 1,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.CPF.item[1].type_id": 177,
                    "enip.CIP.send_data.CPF.item[1].length": 15,
                    "enip.CIP.send_data.CPF.item[1].connection_data.sequence": 1,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.input":
                        array.array( cpppo.type_bytes_array_symbol, b'\x00\x00\x01\x00\x00\x00\x00\x00\x06\x00J\n\x03'),
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.status": True,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.src": 0,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.cmd": 6,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.tns": 2634,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.dst": 1,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.fnc": 3,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.sts": 0,
                    "enip.CIP.send_data.CPF.item[0].type_id": 161,
                    "enip.CIP.send_data.CPF.item[0].length": 4,
                    "enip.CIP.send_data.CPF.item[0].connection_ID.connection": 2381185046,
                    "enip.CIP.send_data.CPF.count": 2,
                }
            ),
            (
                snd_u01_rpy, pccc.PCCC_ANC_120e,
                {
                    "enip.status": 0,
                    "enip.session_handle": 1,
                    "enip.options": 0,
                    "enip.length": 58,
                    "enip.command": 112,
                    "enip.CIP.send_data.timeout": 0,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.CPF.item[1].type_id": 177,
                    "enip.CIP.send_data.CPF.item[1].length": 38,
                    "enip.CIP.send_data.CPF.item[1].connection_data.sequence": 1,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.input":
                        array.array( cpppo.type_bytes_array_symbol, b'\x00\x00\x00\x00\x00\x00\x01\x00F\x00J\n\x00\xee1[#5/04       V\x00\x91$\x05D \xfc'),
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.src": 1,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.cmd": 70, # 0x46; reply to CMD 0x06
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.tns": 2634,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.dst": 0,
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.sts": 0,
                    #"enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.fnc": 0, Reply packets do not contain FNC
                    "enip.CIP.send_data.CPF.item[1].connection_data.request.DF1.data": [
                        0,
                        238,
                        49,
                        91,
                        35,
                        53,
                        47,
                        48,
                        52,
                        32,
                        32,
                        32,
                        32,
                        32,
                        32,
                        32,
                        86,
                        0,
                        145,
                        36,
                        5,
                        68,
                        32,
                        252
                    ],
                    "enip.CIP.send_data.CPF.item[0].type_id": 161,
                    "enip.CIP.send_data.CPF.item[0].length": 4,
                    "enip.CIP.send_data.CPF.item[0].connection_ID.connection": 2147483652,
                    "enip.CIP.send_data.CPF.count": 2,
                }
            ), (
                leg_0x1_reply, enip.Message_Router, 
                {
                    "enip.command": 0x0001,
                    "enip.length": 42,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.legacy.CPF.count": 1, 
                    "enip.CIP.legacy.CPF.item[0].type_id": 1, 
                    "enip.CIP.legacy.CPF.item[0].length": 36, 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.version": 1, 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.unknown_1": 0, 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.sin_family": 2, 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.sin_port": 44818, 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.sin_addr": "192.168.5.253", 
                    "enip.CIP.legacy.CPF.item[0].legacy_CPF_0x0001.ip_address": "192.168.5.253"
                }
            ), (
                listident_1_req, enip.Message_Router, 
                {
                    "enip.command": 99,
                    "enip.length": 0,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.list_identity.CPF": {}, 
                }
            ), (
                listident_1_rpy, enip.Message_Router, 
                {
                    "enip.command": 99,
                    "enip.length": 72,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.list_identity.CPF.count": 1, 
                    "enip.CIP.list_identity.CPF.item[0].type_id": 12, 
                    "enip.CIP.list_identity.CPF.item[0].length": 66, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.status_word": 1377, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_addr": "10.161.1.5",
                    "enip.CIP.list_identity.CPF.item[0].identity_object.vendor_id": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_port": 44818, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.state": 255, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.version": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.device_type": 123, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_family": 2, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.serial_number": 2152275221, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_code": 1168, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_name": "PowerFlex 753                   ", 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_revision": 267, 
                }
            # 
            # We can handle the bad CPF framing, but won't re-generate the original message (of course)
            # 
            # ), (
            #     listident_1_rpy_bad_CPF_framing, enip.Message_Router, 
            #     {
            #         "enip.command": 99,
            #         "enip.length": 72,
            #         "enip.options": 0, 
            #         "enip.session_handle": 0, 
            #         "enip.status": 0,
            #         "enip.CIP.list_identity.CPF.count": 1, 
            #         "enip.CIP.list_identity.CPF.item[0].type_id": 12, 
            #         "enip.CIP.list_identity.CPF.item[0].length": 39,  # wildly incorrect (truncates 26 bytes); 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.status_word": 1377, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.sin_addr": "10.161.1.5", 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.vendor_id": 1, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.sin_port": 44818, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.version": 1, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.device_type": 123, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.sin_family": 2, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.serial_number": 2152275221, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.product_code": 1168, 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.product_name": "PowerF", 
            #         "enip.CIP.list_identity.CPF.item[0].identity_object.product_revision": 267, 
            #     }
            ), (
                listident_2_rpy, enip.Message_Router, 
                {
                    "enip.command": 99,
                    "enip.length": 69,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.list_identity.CPF.count": 1, 
                    "enip.CIP.list_identity.CPF.item[0].type_id": 12, 
                    "enip.CIP.list_identity.CPF.item[0].length": 63, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.status_word": 48, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_addr": "10.161.1.3",
                    "enip.CIP.list_identity.CPF.item[0].identity_object.vendor_id": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_port": 44818, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.state": 3, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.version": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.device_type": 14, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_family": 2, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.serial_number": 3223204702, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_code": 149, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_name": "1769-L24ER-QB1B/A LOGIX5324ER", 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_revision": 2843, 
                }
            ), (
                listident_3_rpy, enip.Message_Router, 
                {
                    "enip.command": 99,
                    "enip.length": 72,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.list_identity.CPF.count": 1, 
                    "enip.CIP.list_identity.CPF.item[0].type_id": 12, 
                    "enip.CIP.list_identity.CPF.item[0].length": 66, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.status_word": 48, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_addr": "10.161.1.3",
                    "enip.CIP.list_identity.CPF.item[0].identity_object.vendor_id": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_port": 44818, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.state": 3, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.version": 1, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.device_type": 14, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.sin_family": 2, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.serial_number": 3223204702, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_code": 149, 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_name": "1769-L24ER-QB1B/A LOGIX5324ER", 
                    "enip.CIP.list_identity.CPF.item[0].identity_object.product_revision": 2843, 
                }
            ), (
                gas_m01_request, enip.Message_Router, 
                {
                    "enip.status": 0, 
                    "enip.session_handle": 2, 
                    "enip.length": 54, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 38, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].get_attribute_single": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].service": 14, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].path.segment[0].class": 147, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].path.segment[1].instance": 11, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].path.segment[2].attribute": 10, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[0].path.size": 3, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].get_attribute_single": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].service": 14, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].path.segment[0].class": 147, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].path.segment[1].instance": 3, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].path.segment[2].attribute": 10, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[1].path.size": 3, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].get_attribute_single": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].service": 14, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].path.segment[0].class": 147, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].path.segment[2].attribute": 10, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request[2].path.size": 3, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.number": 3, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.offsets": [
                        8, 
                        16, 
                        24
                    ], 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 10, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 2, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.timeout": 0, 
                    "enip.command": 111, 
                    "enip.options": 0
                }
            ), (
                gas_m01_reply, enip.Message_Router, 
                {
                    "enip.status": 0, 
                    "enip.session_handle": 2, 
                    "enip.length": 20, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 4, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 8, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 138, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.timeout": 0, 
                    "enip.command": 111, 
                    "enip.options": 0
                }
            ), (
                gas_001_request, enip.Message_Router, 
                {
                    "enip.status": 0, 
                    "enip.session_handle": 2, 
                    "enip.length": 24, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 8, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attribute_single": True, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 14, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 147, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 11, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[2].attribute": 10, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 3, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.timeout": 0, 
                    "enip.command": 111, 
                    "enip.options": 0,
                }
            ), (
                gas_001_reply, enip.Message_Router, 
                {
                    "enip.status": 0, 
                    "enip.session_handle": 2, 
                    "enip.length": 24, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 8, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 142, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attribute_single.data": [
                        10, 
                        215, 
                        163, 
                        61
                    ], 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.timeout": 0, 
                    "enip.command": 111, 
                    "enip.options": 0,
                }
            ), (
                # ListServices also has a CIP payload (may be empty)
                b'\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Funstuff\x00\x00\x00\x00', enip.Message_Router,
                {
                    "enip.command": 4,
                    "enip.length": 0,
                    "enip.options": 0, 
                    "enip.session_handle": 0, 
                    "enip.status": 0,
                    "enip.CIP.list_services.CPF": {}, 
                }
            ), (
                b'\x04\x00\x19\x00\xdc\xa5\xeaN\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01\x13\x00\x01\x00 \x00Communications\x00', enip.Message_Router, 
               {
                   "enip.status": 0, 
                   "enip.session_handle": 1324000732, 
                   "enip.length": 25, 
                   "enip.CIP.list_services.CPF.count": 1, 
                   "enip.CIP.list_services.CPF.item[0].communications_service.capability": 32, 
                   "enip.CIP.list_services.CPF.item[0].communications_service.service_name": "Communications", 
                   "enip.CIP.list_services.CPF.item[0].communications_service.version": 1, 
                   "enip.CIP.list_services.CPF.item[0].length": 19, 
                   "enip.CIP.list_services.CPF.item[0].type_id": 256, 
                   "enip.command": 4, 
                   "enip.options": 0
                }
            ), (
                rss_004_request, enip.Message_Router, 
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
                gaa_008_request, enip.Message_Router, 
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
                gaa_008_reply, enip.Message_Router, 
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
                gaa_011_request, enip.Message_Router, 
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
                gaa_011_reply, enip.Message_Router, 
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
                unk_014_request, logix.Logix,
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
                unk_014_reply, logix.Logix,
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
              unk_017_request, logix.Logix, 
              {
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.elements": 20, 
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.offset": 2, 
              }
          ), (
                unk_017_reply, logix.Logix,
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
              unk_020_request, logix.Logix,
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
                unk_020_reply, logix.Logix, 
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
                unk_023_request, logix.Logix,
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
          ), (
            rtg_001_reply, logix.Logix,
            {
                "enip.session_handle": 4126743718,
                "enip.command": 111,
                "enip.status": 0,
                "enip.length": 422,
                "enip.options": 0,
                "enip.CIP.send_data.CPF.item[0].length": 0,
                "enip.CIP.send_data.CPF.item[0].type_id": 0,
                "enip.CIP.send_data.CPF.item[1].length": 406,
                "enip.CIP.send_data.CPF.item[1].type_id": 178,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 204,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_tag.type": 195,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_tag.data": [ 0 ] * 200,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0,
                "enip.CIP.send_data.CPF.count": 2,
                "enip.CIP.send_data.interface": 0,
                "enip.CIP.send_data.timeout": 0,
            }
          ), (
              fwd_o01_request, enip.Connection_Manager,
              {
                  "enip.CIP.send_data.CPF.count": 2,
                  "enip.CIP.send_data.CPF.item[0].length": 0,
                  "enip.CIP.send_data.CPF.item[0].type_id": 0,
                  "enip.CIP.send_data.CPF.item[1].length": 48,
                  "enip.CIP.send_data.CPF.item[1].type_id": 178,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.NCP": 17396,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.RPI": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 2147483665,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.size": 500,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.variable": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.priority": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.type": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 507346703,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 77,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.NCP": 17396,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.RPI": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 2164129808,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.size": 500,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.variable": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.priority": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.type": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].link": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].port": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[1].class": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[2].instance": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 17,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_timeout_multiplier": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.priority_time_tick": 7,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.timeout_ticks": 249,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.transport_class_triggers": 163,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 6,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 84,
                  "enip.CIP.send_data.interface": 0,
                  "enip.CIP.send_data.timeout": 32,
                  "enip.command": 111,
                  "enip.length": 64,
                  "enip.session_handle": 851973,
              }
          ), (
              fwd_o01_reply, enip.Connection_Manager,
              {
                  "enip.CIP.send_data.CPF.count": 2,
                  "enip.CIP.send_data.CPF.item[0].length": 0,
                  "enip.CIP.send_data.CPF.item[0].type_id": 0,
                  "enip.CIP.send_data.CPF.item[1].length": 30,
                  "enip.CIP.send_data.CPF.item[1].type_id": 178,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.API": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 4288888870,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 507346703,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 77,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.API": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 2164129808,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.application.size": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 17,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 212,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0,
                  "enip.CIP.send_data.interface": 0,
                  "enip.CIP.send_data.timeout": 0,
                  "enip.command": 111,
                  "enip.length": 46,
                  "enip.options": 0,
                  "enip.session_handle": 851973,
                  "enip.status": 0,
              }
          ), (
              fwd_o02_request_bad, enip.Connection_Manager,
              {
                  "enip.CIP.send_data.CPF.count": 2,
                  "enip.CIP.send_data.CPF.item[0].length": 0,
                  "enip.CIP.send_data.CPF.item[0].type_id": 0,
                  "enip.CIP.send_data.CPF.item[1].length": 62,
                  "enip.CIP.send_data.CPF.item[1].type_id": 178,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 48,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.NCP": 17396,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.RPI": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 507346703,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 77,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.NCP": 17396,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.RPI": 8000000,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 4294967295,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].link": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].port": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[1].class": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[2].instance": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.size": 3,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_timeout_multiplier": 163,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.priority_time_tick": 7,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.timeout_ticks": 249,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.transport_class_triggers": 163,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 6,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 84,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].link": 0,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].port": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.size": 1,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82,
                  "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 247,
                  "enip.CIP.send_data.interface": 0,
                  "enip.CIP.send_data.timeout": 8,
                  "enip.command": 111,
                  "enip.length": 78,
                  "enip.options": 0,
                  "enip.session_handle": 1245189,
                  "enip.status": 0,
              }
            ), (
                fwd_c01_request, enip.Connection_Manager,
                {
                    "enip.command": 111,
                    "enip.length": 40,
                    "enip.status": 0,
                    "enip.options": 0,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.timeout": 8,
                    "enip.CIP.send_data.CPF.count": 2,
                    "enip.CIP.send_data.CPF.item[0].type_id": 0,
                    "enip.CIP.send_data.CPF.item[0].length": 0,
                    "enip.CIP.send_data.CPF.item[1].type_id": 178,
                    "enip.CIP.send_data.CPF.item[1].length": 24,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 78,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 6,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.priority_time_tick": 7,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.timeout_ticks": 249,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_serial": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.O_vendor": 77,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.O_serial": 507346703,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_path.size": 3,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_path.segment[0].port": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_path.segment[0].link": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_path.segment[1].class": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.connection_path.segment[2].instance": 1
                }
            ), (
                fwd_o02_request, enip.Connection_Manager,
                {
                    "enip.status": 0,
                    "enip.session_handle": 1,
                    "enip.options": 0,
                    "enip.length": 66,
                    "enip.command": 111,
                    "enip.CIP.send_data.timeout": 20,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 84,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 6,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.transport_class_triggers": 163,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.timeout_ticks": 155,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.priority_time_tick": 7,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_timeout_multiplier": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 5,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.size": 4,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].port": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].link": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[1].class": 166,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[2].instance": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[3].connection": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 2147483652,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.RPI": 4000000,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.NCP": 17154,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.size": 258,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.variable": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.priority": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.type": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.redundant": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 77,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 945444919,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 2147483653,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.RPI": 4000000,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.NCP": 17154,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.size": 258,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.variable": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.priority": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.type": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.redundant": 0,
                    "enip.CIP.send_data.CPF.item[1].type_id": 178,
                    "enip.CIP.send_data.CPF.item[1].length": 50,
                    "enip.CIP.send_data.CPF.item[0].type_id": 0,
                    "enip.CIP.send_data.CPF.item[0].length": 0,
                    "enip.CIP.send_data.CPF.count": 2,
                }
            ), (
                fwd_o02_reply, enip.Connection_Manager,
                {
                    "enip.status": 0,
                    "enip.session_handle": 1,
                    "enip.options": 0,
                    "enip.length": 46,
                    "enip.command": 111,
                    "enip.CIP.send_data.timeout": 0,
                    "enip.CIP.send_data.interface": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 212,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 5,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.application.size": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 2147483652,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.API": 4000000,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 77,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 945444919,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 2381185046,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.API": 4000000,
                    "enip.CIP.send_data.CPF.item[1].type_id": 178,
                    "enip.CIP.send_data.CPF.item[1].length": 30,
                    "enip.CIP.send_data.CPF.item[0].type_id": 0,
                    "enip.CIP.send_data.CPF.item[0].length": 0,
                    "enip.CIP.send_data.CPF.count": 2,
                }
            ), (
                fwd_f01_request_bad, enip.Connection_Manager,
                {
                    "enip.status": 0, 
                    "enip.session_handle": 352477696, 
                    "enip.length": 60, 
                    "enip.CIP.send_data.interface": 0, 
                    "enip.CIP.send_data.CPF.count": 2, 
                    "enip.CIP.send_data.CPF.item[0].length": 0, 
                    "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                    "enip.CIP.send_data.CPF.item[1].length": 44, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.transport_class_triggers": 163, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.timeout_ticks": 249, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.priority_time_tick": 7, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.size": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].port": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_path.segment[0].link": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_timeout_multiplier": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 65535, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 305419896, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.NCP": 17396, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.RPI": 17396, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.connection_ID": 0, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.large": False,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.size": 500,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.variable": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.priority": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.type": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.redundant": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.NCP": 17396, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.RPI": 2000000, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.connection_ID": 4294967295, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.large": False,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.size": 500,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.variable": 1,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.priority": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.type": 2,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.T_O.redundant": 0,
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 84, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 6, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
                    "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2, 
                    "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                    "enip.CIP.send_data.timeout": 8, 
                    "enip.command": 111, 
                    "enip.options": 0
                }
              ), (
                  fwd_f01_reply, enip.Connection_Manager,
                  {
                      "enip.status": 0,
                      "enip.options": 0,
                      "enip.command": 111, 
                      "enip.session_handle": 352477696, 
                      "enip.length": 32, 
                      "enip.CIP.send_data.interface": 0, 
                      "enip.CIP.send_data.CPF.count": 2, 
                      "enip.CIP.send_data.CPF.item[0].length": 0, 
                      "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                      "enip.CIP.send_data.CPF.item[1].length": 16, 
                      "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 212, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.data": [ 785 ], 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 0, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 65535, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 305419896, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.remaining_path_size": 1, 
                      "enip.CIP.send_data.timeout": 8, 
                  }
              ), (
                  fwd_f01_reply_no_remain, enip.Connection_Manager,
                  {
                      "enip.status": 0,
                      "enip.options": 0,
                      "enip.command": 111, 
                      "enip.session_handle": 352477696, 
                      "enip.length": 30, 
                      "enip.CIP.send_data.interface": 0, 
                      "enip.CIP.send_data.CPF.count": 2, 
                      "enip.CIP.send_data.CPF.item[0].length": 0, 
                      "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                      "enip.CIP.send_data.CPF.item[1].length": 14, 
                      "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 212, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.data": [ 785 ], 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.connection_serial": 0, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_vendor": 65535, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_serial": 305419896, 
                      "enip.CIP.send_data.timeout": 8, 
                  }
              ), (
                  fwd_clo_reply_just_sts, enip.Connection_Manager,
                  {
                      "enip.status": 0,
                      "enip.options": 0,
                      "enip.command": 111, 
                      "enip.session_handle": 335698946, 
                      "enip.length": 22, 
                      "enip.CIP.send_data.interface": 0, 
                      "enip.CIP.send_data.timeout": 8, 
                      "enip.CIP.send_data.CPF.count": 2, 
                      "enip.CIP.send_data.CPF.item[0].length": 0, 
                      "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                      "enip.CIP.send_data.CPF.item[1].length": 6, 
                      "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 206, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.size": 1, 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status_ext.data": [ 256 ], 
                      "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close": True, 
                  }
              ),            (
               gal_m01_request, logix.Logix,
               {
                   "enip.command": 112,
                   "enip.length": 492,
                   "enip.session_handle": 2767474022,
                   "enip.status": 0,
                   "enip.options": 0,
                   "enip.CIP.send_data.interface": 0,
                   "enip.CIP.send_data.timeout": 0,
                   "enip.CIP.send_data.CPF.count": 2,
                   "enip.CIP.send_data.CPF.item[0].type_id": 161,
                   "enip.CIP.send_data.CPF.item[0].length": 4,
                   "enip.CIP.send_data.CPF.item[0].connection_ID.connection": 2403049854,
                   "enip.CIP.send_data.CPF.item[1].type_id": 177,
                   "enip.CIP.send_data.CPF.item[1].length": 472,
                   "enip.CIP.send_data.CPF.item[1].connection_data.sequence": 10576,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.service": 10,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.path.size": 2,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[0].class": 2,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[1].instance": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.number": 23,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.offsets": [
                       48,
                       60,
                       78,
                       96,
                       112,
                       132,
                       162,
                       182,
                       200,
                       216,
                       232,
                       250,
                       266,
                       282,
                       298,
                       316,
                       346,
                       364,
                       382,
                       400,
                       416,
                       432,
                       448
                   ],
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[0].service": 3,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[0].path.size": 2,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[0].path.segment[0].class": 172,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[0].path.segment[1].instance": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[0].get_attribute_list": [
                       1,
                       3
                   ],
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[1].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[1].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[1].path.segment[0].symbolic": "LFF26E7C",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[1].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[1].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[2].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[2].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[2].path.segment[0].symbolic": "I86LFMC",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[2].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[2].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[3].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[3].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[3].path.segment[0].symbolic": "I23LF",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[3].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[3].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[4].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[4].path.size": 6,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[4].path.segment[0].symbolic": "LFF26LF1_A",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[4].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[4].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[5].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[5].path.size": 11,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[5].path.segment[0].symbolic": "BOVMANUALSTROKE_HMI",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[5].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[5].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[6].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[6].path.size": 6,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[6].path.segment[0].symbolic": "LFF26E14C",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[6].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[6].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[7].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[7].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[7].path.segment[0].symbolic": "A63GGCD",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[7].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[7].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[8].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[8].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[8].path.segment[0].symbolic": "ACT101",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[8].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[8].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[9].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[9].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[9].path.segment[0].symbolic": "ACT100",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[9].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[9].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[10].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[10].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[10].path.segment[0].symbolic": "A26E17C",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[10].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[10].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[11].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[11].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[11].path.segment[0].symbolic": "L1ACTC",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[11].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[11].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[12].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[12].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[12].path.segment[0].symbolic": "N3OSPD",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[12].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[12].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[13].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[13].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[13].path.segment[0].symbolic": "H1ACTM",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[13].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[13].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[14].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[14].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[14].path.segment[0].symbolic": "C75QGGC",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[14].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[14].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[15].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[15].path.size": 11,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[15].path.segment[0].symbolic": "IGVMANUALSTROKE_HMI",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[15].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[15].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[16].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[16].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[16].path.segment[0].symbolic": "A26FG1_A",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[16].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[16].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[17].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[17].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[17].path.segment[0].symbolic": "A99GG2B",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[17].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[17].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[18].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[18].path.size": 5,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[18].path.segment[0].symbolic": "A99GG2A",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[18].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[18].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[19].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[19].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[19].path.segment[0].symbolic": "SSS63",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[19].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[19].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[20].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[20].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[20].path.segment[0].symbolic": "SSS62",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[20].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[20].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[21].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[21].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[21].path.segment[0].symbolic": "SSS61",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[21].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[21].read_frag.offset": 0,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[22].service": 82,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[22].path.size": 4,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[22].path.segment[0].symbolic": "TGLSET",
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[22].read_frag.elements": 1,
                   "enip.CIP.send_data.CPF.item[1].connection_data.request.multiple.request[22].read_frag.offset": 0,
               }
           )
]
  

def test_enip_CIP( repeat=1 ):
    """Most of CIP parsing run-time overhead is spent inside 'run'.
    """
    #logging.getLogger().setLevel( logging.DEBUG )
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    ENIP			= enip.enip_machine( context='enip' )
    CIP				= enip.CIP()
    for pkt,cls,tst in client.recycle( CIP_tests, times=repeat ):
        assert type( cls ) is type
        # Parse just the CIP portion following the EtherNet/IP encapsulation header
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with ENIP as machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
        # In a real protocol implementation, an empty header (EOF with no input at all) is
        # acceptable; it indicates a session closed by the client.
        if not data:
            log.normal( "EtherNet/IP Request: Empty (session terminated): %s", enip.enip_format( data ))
            continue

        if log.getEffectiveLevel() <= logging.NORMAL:
            log.normal( "EtherNet/IP Request: %s", enip.enip_format( data ))
            
        # Parse the encapsulated .input
        with CIP as machine:
            for i,(m,s) in enumerate( machine.run( path='enip', source=cpppo.peekable( data.enip.get( 'input', b'' )), data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )
                #log.normal( "CIP Parsed: %s", enip.enip_format( data ))

        if log.getEffectiveLevel() <= logging.NORMAL:
            log.normal( "EtherNet/IP CIP Request: %s", enip.enip_format( data ))

        # Assume the request in the CIP's CPF items are Logix requests.
        # Now, parse the encapsulated message(s).  We'll assume it is destined for a Logix Object.
        if 'enip.CIP.send_data' in data:
          dialect_bak,device.dialect	= device.dialect,cls # save/restore enip.dialect
          try:
            for item in data.enip.CIP.send_data.CPF.item:
                if 'unconnected_send.request' in item:
                    request		= item.unconnected_send.request
                elif 'connection_data.request' in item:
                    request		= item.connection_data.request
                else:
                    continue

                # A Connected/Unconnected Send that contained an encapsulated request (ie. not just a Get
                # Attribute All)
                with cls.parser as machine:
                    if log.getEffectiveLevel() <= logging.NORMAL:
                        log.normal( "Parsing %3d bytes using %s.parser, from %s", 
                                    len( request.input ),
                                    cls, enip.enip_format( item ))
                    # Parse the unconnected_send.request.input octets, putting parsed items into the
                    # same request context
                    for i,(m,s) in enumerate( machine.run(
                            source=cpppo.peekable( request.input ),
                            data=request )):
                        log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                                    machine.name_centered(), i, s, source.sent, source.peek(), data )
                # Post-processing of some parsed items is only performed after lock released!
                if log.getEffectiveLevel() <= logging.NORMAL:
                    log.normal( "Parsed  %3d bytes using %s.parser, into %s", 
                                len( request.input ),
                                cls, enip.enip_format( data ))
          finally:
            device.dialect	= dialect_bak

        try:
            for k,v in tst.items():
                assert data[k] == v, ( "data[%r] == %r\n"
                                       "expected:   %r" % ( k, data[k], v ))
        except:
            log.warning( "%r not in data, or != %r: data %s\n != test %s", k, v, enip.enip_format( data ), enip.enip_format( tst ))
            raise

        # Ensure that we can get the original EtherNet/IP CIP back; delete any pre-generated 'input'
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
                        item.unconnected_send.request.input	= bytearray( cls.produce( item.unconnected_send.request ))
                        log.normal("Produce %s message from: %r", cls,item.unconnected_send.request )
                    elif 'connection_data' in item:
                        item.connection_data.request.input	= bytearray( cls.produce( item.connection_data.request ))
                        log.normal("Produce %s message from: %r", cls,item.connection_data.request )

            # Next, reconstruct the CIP Register, ListIdentity, ListServices, or SendRRData.  The CIP.produce must
            # be provided the EtherNet/IP header, because it contains data (such as .command)
            # relevant to interpreting the .CIP... contents.
            data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
            # And finally the EtherNet/IP encapsulation itself
            data.input			= bytearray( enip.enip_encode( data.enip ))
            log.detail( "EtherNet/IP CIP Request produced payload: %r", bytes( data.input ))
            assert data.input == pkt, "original:\n" + hexdump( pkt ) + "\nproduced:\n" + hexdump( data.input )
        except Exception as exc:
            log.warning( "Invalid packet produced from EtherNet/IP CIP data: %s\n%s", enip.enip_format( data ), exc)
            raise


def test_enip_device_symbolic():
    enip.device.symbol['SCADA'] = {'class':0x401, 'instance':1, 'attribute':2}
    path={'segment':[{'symbolic':'SCADA'}, {'element':4}]}
    assert enip.device.resolve( path, attribute=True ) == (0x401,1,2)
    assert enip.device.resolve( path ) == (0x401,1,None)

    enip.device.symbol['Tag.Subtag'] = {'class':0x401, 'instance':1, 'attribute':3}
    path={'segment':[{'symbolic':'Tag'}, {'symbolic':'Subtag'}, {'element':4}]}
    assert enip.device.resolve( path, attribute=True ) == (0x401,1,3)

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

    try:
        result			= enip.device.resolve(
            {'segment':[{'symbolic': 'Tag'}, {'symbolic':'Incorrect'}]}, attribute=True )
        assert False, "Should not have succeeded: %r" % result
    except AssertionError as exc:
        assert "Unrecognized symbolic name 'Tag.Incorrect'" in str(exc)


def test_enip_device():
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start

    class_num			= 0xF0

    class Test_Device( enip.device.Object ):
        class_id		= class_num

    # Create an instance (creates class-level instance_id==0 automatically)
    O				= Test_Device( 'Test Class', instance_id=1 )

    # Confirm the new entries in the enip.device.directory
    assert sorted( enip.device.directory[str(O.class_id)].keys(), key=cpppo.natural ) == [
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
        for k in sorted( enip.device.directory.keys(), key=cpppo.natural)))

    Ix				= enip.device.Identity( 'Test Identity' )
    attrs			= enip.device.directory[str(Ix.class_id)+'.'+str(Ix.instance_id)]
    log.normal( "New Identity Instance directory: %s", enip.enip_format( attrs ))
    assert attrs['7'].produce() == b'\x141756-L61/B LOGIX5561'
    
    request			= cpppo.dotdict({'service': 0x01, 'path':{'segment':[{'class':Ix.class_id},{'instance':Ix.instance_id}]}})
    gaa				= Ix.request( request )
    log.normal( "Identity Get Attributes All: %r, data: %s", gaa, enip.enip_format( request ))
    assert request.input == b'\x81\x00\x00\x00\x01\x00\x0e\x006\x00\x14\x0b`1\x1a\x06l\x00\x141756-L61/B LOGIX5561\xff\x00\x00\x00'

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

    # Volume 2, Table 5-4.13 is very explicit about the expected TCP/IP Object response encoding to
    # a Get_Attributes_All request
    Tcpip			= enip.device.TCPIP( 'Test TCP/IP' )
    request			= cpppo.dotdict({'service': 0x01, 'path':{'segment':[{'class':Tcpip.class_id},{'instance':Tcpip.instance_id}]}})
    gaa				= Tcpip.request( request )
    log.normal( "TCPIP Get Attributes All: %r, data: %s", gaa, enip.enip_format( request ))
    assert request.input == b'\x81\x00\x00\x00\x02\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


def test_enip_logix():
    """The logix module implements some features of a Logix Controller."""
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start

    Obj				= logix.Logix( instance_id=1 )
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
    log.normal("Logix Request processed: %s (proceed == %s)", enip.enip_format( data ), proceed )


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
client_count, client_max	= 15, 10
#client_count, client_max	= 1, 1
charrange, chardelay		= (2,10), .1	# split/delay outgoing msgs
draindelay			= 10.  		# long in case server very slow (eg. logging), but immediately upon EOF

def enip_cli( number, tests=None ):
    """Sends a series of test messages, testing response for expected results."""
    conn			= None
    successes			= 0
    try:
        log.info( "EtherNet/IP Client %3d connecting... PID [%5d]", number, os.getpid() )
        conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        conn.connect( enip.address )
        log.normal( "EtherNet/IP Client %3d connected to server at %s", number, enip.address )

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
                            errors += 1
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
                                       number, machine.name_centered(), sta, source.sent, source.peek(), cpppo.reprlib.repr( data ))

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
        conn.close()

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

def enip_bench_basic():
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

def test_enip_bench_basic():
    assert not enip_bench_basic(), "One or more enip_bench_basic clients reported failure"

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
                    # Size depends on the Identity Object's Attributes; will
                    # change if Identity modified...
                    "response.enip.length": 		59,
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


def enip_bench_logix():
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

def test_enip_bench_logix():
    assert not enip_bench_logix(), "One or more enip_bench_logix clients reported failure"


def enip_cli_pylogix( number, tests=None ):
    """Use pylogix to access the server, using Large Forward Open session (if pull request for
    PLC.ConnectionSize merged).

    """

    tags			= [
        'SCADA',
        'SCADA[9]',
        [
            'SCADA[0]', 'SCADA[1]', 'SCADA[2]', 'SCADA[3]', 'SCADA[4]', 'SCADA[5]',
        ],
    ]
    with pylogix.PLC() as comm:
        comm.IPAddress		= enip.address[0]
        comm.ConnectionSize	= 4000
        results			= [
            comm.Read( t )
            for t in tags
        ]

    assert len( results ) == len( tags )

    def testval( tags, results, indent=0 ):
        for t,v in zip( tags, results ):
            if cpppo.is_listlike( t ) or cpppo.is_iterator( t ):
                testval( t, v, indent + 4 )
                continue
            log.detail( "{}{t!r:<20} == {v!r}".format( ' ' * indent, t=t, v=v ))
            assert v.Status == 'Success'

    testval( tags, results )


def enip_bench_pylogix():
    failed			= cpppo.server.network.bench( server_func=enip.main,
                                                              server_kwds=enip_svr_kwds_logix,
                                                              client_func=enip_cli_pylogix,
                                                              client_kwds=enip_cli_kwds_logix,
                                                              client_count=client_count,
                                                                client_max=client_max)
    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


@pytest.mark.skipif( not has_pylogix, reason="Needs pylogix" )
def test_enip_bench_pylogix():
    assert not enip_bench_pylogix(), "One or more enip_bench_pylogix clients reported failure"
    
    
if __name__ == "__main__":
    '''
    # Profile using line_profiler, and kernprof.py -v -l enip_test.py
    test_enip_CIP( 10 )
    '''

    '''
    # Profile the main thread using cProfile
    import cProfile
    import pstats
    prof_file			= "enip_test.profile"
    cProfile.run( "test_enip_CIP( 10 )", prof_file )
    prof			= pstats.Stats( prof_file )
    print( "\n\nTIME:")
    prof.sort_stats(  'time' ).print_stats( 100 )

    print( "\n\nCUMULATIVE:")
    prof.sort_stats(  'cumulative' ).print_stats( 100 )
    '''

    '''
    import yappi
    yappi.start()
    '''

    '''
    enip_bench_logix()
    '''
    '''
    print( "\nFunction Total:" )
    yappi.print_stats( sys.stdout, yappi.SORTTYPE_TTOTAL )
    print( "\nWithin Function:" )
    yappi.print_stats( sys.stdout, yappi.SORTTYPE_TSUB )
    '''
