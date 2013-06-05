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
    import reprlib
except ImportError:
    import repr as reprlib

if __name__ == "__main__" and __package__ is None:
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import cpppo
from   cpppo.server import ( enip, network )

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

eip_tests			= [
            ( b'', {} ),        # test that parsers handle/reject empty/EOF
            ( rss_004_request,	{ 'enip.header.command': 0x0065, 'enip.header.length': 4 }),
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
 
cip_tests			= [
            ( unk_014_request,	{} ),
           #( unk_017_request,	{} ),
           #( unk_020_request,	{} ),
           #( unk_023_request,	{} ),
]
  
def test_enip_header():
    for pkt,tst in eip_tests:
        # Parse just the headers, forcing non-transitions to fetch one symbol at a time.  Accepts an
        # empty header at EOF.
        data			= cpppo.dotdict()
        origin			= cpppo.chainable( pkt )
        source			= cpppo.chainable()
        with enip.enip_header( terminal=True ) as machine:
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
        with enip.enip_machine( terminal=True ) as machine:
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
   
        for k,v in tst.items():
            assert data[k] == v

        # Ensure we can reproduce the original packet from the parsed data
        if data:
            assert enip.enip_encode( data ) == pkt, "Invalid data: %r" % data

def test_enip_cip():
    for pkt,tst in cip_tests:
        # Parse just the headers
        data			= cpppo.dotdict()
        source			= cpppo.chainable( pkt )
        with enip.enip_machine() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )

        assert  data.request.enip.header.command == 0x006f # SendRRData

        '''
        # Now, parse SendRRData from EtherNet/IP encapsulated_data.input into
        #     data.request.enip.sendrrdata...
        source			= cpppo.peekable( data.request.enip.encapsulated_data.input )
        with enip.sendrrdata() as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path='request.enip', data=data )):
                log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                          machine.name_centered(), i, s, source.sent, source.peek(), data )


        # Each SendRRData CPF item may carry an encapsulated CIP frame.  Parse each
        # item[x].data.input into item[x].ucmm...  This should typically be a Null Address (0x0000)
        # CPF item type_id segment (indicating that no routing is required), followed by a
        # Unconnected Message (0x00b2) CPF item type_id.
        path		= 'request.enip.cpf.item'
        for index in range( data[path+'_count'] ):
            log.normal( "EtherNet/IP CIP: data[%r][%d]: %r", path, index, data[path][index] )
            if not data[path][index].length:
                continue
            with enip.ucmm_machine() as machine:
                source		= cpppo.peekable( data[path][index].data.input )
                for i,(m,s) in enumerate( machine.run( source=source, data=data[path][index] )):
                    log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r",
                                machine.name_centered(), i, s, source.sent, source.peek(), data )

                assert data[path][index].cip.request_service == 0x00b2, \
                    "EtherNet/IP CIP Unconnected Message (0x00b2) expected; got %r " % (
                        data[path][index] )
        '''

        log.normal( "%s: %s", machine.name_centered(), enip.enip_format( data ))



# Run the bench-test.  Sends some request from a bunch of clients to a server, testing responses

def enip_process_canned( addr, source, data ):
    """Process a request, recognizing a subset of the known requests, and returning a "canned"
    response."""
    if not data:
        log.normal( "EtherNet/IP Request Empty; end of session" )
        return

    log.detail( "EtherNet/IP Request: %s", enip.parser.enip_format( data.request ))
    if data.request.enip.header.command == 0x0065:
        source			= cpppo.chainable( rss_004_reply )
        with enip.enip_machine() as machine: # Load data.response.enip
            for m,s in machine.run( path='response', source=source, data=data ):
                pass
            if machine.terminal:
                log.debug( "EtherNet/IP Response: %s", enip.parser.enip_format( data.response ))
        return

    raise Exception( "Unrecognized request: %s" % ( enip.parser.enip_format( data )))

client_count, client_max	= 15, 10
charrange, chardelay		= (2,10), .1	# split/delay outgoing msgs
draindelay			= 5.   		# long in case server slow, but immediately upon EOF

enip_cli_kwds			= {
	'tests':	[
            ( rss_004_request, {
                'response.enip.header.command': 	0x0065,
                'response.enip.header.session_handle':	285351425,
            }),
        ]
}

enip_svr_kwds 			= { 
    'enip_process': 	enip_process_canned,
}


def enip_cli( number, tests=None ):
    """Sends a series of test messages, testing response for ) """
    log.info( "EhterNet/IP Client %3d connecting... PID [%5d]", number, os.getpid() )
    conn			= socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    conn.connect( enip.address )
    log.normal( "EtherNet/IP Client %3d connected to server at %s", number, enip.address )
        
    successes			= 0
    try:
        for req,tst in tests:
            data		= cpppo.dotdict()

            log.normal( "EtherNet/IP Client %3d req.: %5d: %s ", number, len( req ), repr( req ))
            # Await response, sending request in chunks using inter-block chardelay if output
            # remains, otherwise await response using draindelay.  Stop if EOF from server.
            eof			= False
            rpy			= b''
            while len( req ) and not eof:
                out		= min( len( req ), random.randrange( *charrange ))
                log.detail( "EtherNet/IP Client %3d send: %5d/%5d: %s", number, out, len( req ),
                            repr( req[:out] ))
                conn.send( req[:out] )
                req		= req[out:]

                rcvd		= network.recv( conn, timeout=chardelay if len( req ) else draindelay )
                if rcvd is not None:
                    log.detail( "EtherNet/IP Client %3d recv: %5d: %s", number, len( rcvd ),
                                repr( rcvd ) if len( rcvd ) else "EOF" )
                    eof		= not len( rcvd )
                    rpy	       += rcvd

            log.normal( "EtherNet/IP Client %3d rpy.: %5d: %s ", number, len( rpy ), repr( rpy ))
            # Parse response
            sta			= None
            with enip.enip_machine( terminal=True ) as machine:
                for mch,sta in machine.run( source=cpppo.peekable( rpy ), path='response', data=data ):
                    pass
                assert machine.terminal, \
                    "%3d client failed to decode EtherNet/IP response: %r\ndata: %s" % (
                        number, rpy, enip.parser.enip_format( data ))

            log.normal( "EtherNet/IP Client %3d rpy. data: %s", number, enip.parser.enip_format( data ))

            # Successfully sent request and parsed response; can continue; test req/rpy parsed data
            errors		= 0
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

def test_enip_bench():
    failed			= cpppo.server.network.bench( server_func=enip.main,
                                                              server_kwds=enip_svr_kwds,
                                                              client_func=enip_cli,
                                                              client_kwds=enip_cli_kwds,
                                                              client_count=client_count,
                                                                client_max=client_max)
    if failed:
        log.warning( "Failure" )
    else:
        log.info( "Succeeded" )

    return failed


if __name__ == "__main__":
    test_enip_bench()

