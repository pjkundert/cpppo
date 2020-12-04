# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import array
import contextlib
import json
import logging
import sys
import random

from ...automata import log_cfg
from ...dotdict import dotdict
from . import parser
from ... import misc

try:
    unicode('')
except NameError:
    unicode = str

# Set up logging to use our log format (instead of default Pytest format), while
# retaining any logging level eg. python -m pytest --log-cli-level=25 ...
logging.getLogger().handlers[0].setFormatter( logging.Formatter( log_cfg['format'] ))


log				= logging.getLogger( "parser" )

def test_enip_format():

    obj = dotdict(
        short_bytes = b'o\x00\x00\x00',
        long_bytes = b'o\x00\x00\x00\x06\x00\x00\x00RT1-17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x00\x00\x00SE4 D 48-49ct\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x0037ct E Hdg\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00CO\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x0037ct E Hdg\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x10\x00\x00333?\xd0\x07\x00\x00\x80>\x00\x00\xf0U\x00\x00\xf0U\x00\x00\xf0U\x00\x00\x00\x00\xe0@\x00\x00 A\x00\x00 A\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x07\x00\x00\x00\x00 A\x00\x00\x00\x00\xd0\x14\x08I+\x00\x00\x00\xf0M\xc0}L&\x05\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdf\x07\x00\x00\x0c\x00\x00\x00\x07\x00\x00\x00\n\x00\x00\x00(\x00\x00\x004\x00\x00\x00\xfeX\n\x00',
        some_utf8 = "The π character is called pi",
        some_ascii = "The quick brown fox \\ jumped over the \"lazy\" dog",
        boo = dotdict( foo = [
            dotdict( [(chr( 97 + i ), list( range( 0, i )))] )
            for i in range( 0, 21, 2 )
        ] ),
        empty = dotdict( something = 123, sub=[], totally_null=None, true_false=( True, False ) ),
        various = dotdict(
            ints = array.array('i', list( range( 20 ))),
            reals = array.array('d', list( map( float, range( 20 )))),
            strings = list( map( str, range( 20 ))),
        )
    )

    out				= parser.enip_format( obj, sort_keys=True )
    print( out )
    assert out == """\
{
    'boo.foo[ 0].a':                [],
    'boo.foo[ 1].c':                [0, 1],
    'boo.foo[ 2].e':                [0, 1, 2, 3],
    'boo.foo[ 3].g':                [0, 1, 2, 3, 4, 5],
    'boo.foo[ 4].i':                [0, 1, 2, 3, 4, 5, 6, 7],
    'boo.foo[ 5].k':                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    'boo.foo[ 6].m':                list(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,
    ),
    'boo.foo[ 7].o':                list(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,     12,     13,
    ),
    'boo.foo[ 8].q':                list(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,     12,     13,     14,     15,
    ),
    'boo.foo[ 9].s':                list(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,     12,     13,     14,     15,     16,     17,
    ),
    'boo.foo[10].u':                list(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,     12,     13,     14,     15,     16,     17,     18,     19,
    ),
    'empty.something':              123,
    'empty.sub':                    [],
    'empty.totally_null':           None,
    'empty.true_false':             (True, False),
    'long_bytes':                   bytes(hexload(r'''
        00000000:  6f 00 00 00 06 00 00 00  52 54 31 2d 31 37 00 00   |o.......RT1-17..|
        00000010:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000020:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000030:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000040:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000050:  00 00 00 00 00 00 00 00  00 00 00 00 0d 00 00 00   |................|
        00000060:  53 45 34 20 44 20 34 38  2d 34 39 63 74 00 00 00   |SE4 D 48-49ct...|
        00000070:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000080:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000090:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000000A0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000000B0:  00 00 00 00 0a 00 00 00  33 37 63 74 20 45 20 48   |........37ct E H|
        000000C0:  64 67 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |dg..............|
        000000D0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000000E0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000000F0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000100:  00 00 00 00 00 00 00 00  00 00 00 00 02 00 00 00   |................|
        00000110:  43 4f 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |CO..............|
        00000120:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000130:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000140:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000150:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000160:  00 00 00 00 0a 00 00 00  33 37 63 74 20 45 20 48   |........37ct E H|
        00000170:  64 67 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |dg..............|
        00000180:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000190:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000001A0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000001B0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        000001C0:  19 10 00 00 33 33 33 3f  d0 07 00 00 80 3e 00 00   |....333?.....>..|
        000001D0:  f0 55 00 00 f0 55 00 00  f0 55 00 00 00 00 e0 40   |.U...U...U.....@|
        000001E0:  00 00 20 41 00 00 20 41  00 00 00 00 00 00 00 00   |.. A.. A........|
        000001F0:  e8 03 00 00 00 00 00 00  01 00 00 00 00 00 00 00   |................|
        00000200:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
        00000210:  00 00 00 00 08 07 00 00  00 00 20 41 00 00 00 00   |.......... A....|
        00000220:  d0 14 08 49 2b 00 00 00  f0 4d c0 7d 4c 26 05 00   |...I+....M.}L&..|
        00000230:  14 00 00 00 00 00 00 00  00 00 00 00 df 07 00 00   |................|
        00000240:  0c 00 00 00 07 00 00 00  0a 00 00 00 28 00 00 00   |............(...|
        00000250:  34 00 00 00 fe 58 0a 00                            |4....X..|
    ''')),
    'short_bytes':                  bytes(hexload(r'''
        00000000:  6f 00 00 00                                        |o...|
    ''')),
    'some_ascii':                   'The quick brown fox \\\\ jumped over the "lazy" dog',
""" + ( """\
    'some_utf8':                    'The π character is called pi',
""" if sys.version_info[0] >= 3 else """\
    'some_utf8':                    u'The \u03c0 character is called pi',
""" ) + """\
    'various.ints':                 array(
              0,      1,      2,      3,      4,      5,      6,      7,      8,      9,
             10,     11,     12,     13,     14,     15,     16,     17,     18,     19,
    ),
    'various.reals':                array(
            0.0,    1.0,    2.0,    3.0,    4.0,    5.0,    6.0,    7.0,    8.0,    9.0,
           10.0,   11.0,   12.0,   13.0,   14.0,   15.0,   16.0,   17.0,   18.0,   19.0,
    ),
    'various.strings':              list(
        '0',    '1',    '2',    '3',    '4',    '5',    '6',    '7',    '8',    '9',    
        '10',   '11',   '12',   '13',   '14',   '15',   '16',   '17',   '18',   '19',   
    ),
}"""
    

def test_IPADDR():
    """IP addresses for some requests (eg. ListIdentity) are expressed as Network byte-ordered UDINTs,
    on the wire"""
    source			= parser.IPADDR_network.produce( '10.0.0.1' )
    assert source == b'\x0A\x00\x00\x01'
    # But, we parse them as Network byte-ordered UDINTs and present them as IP addresses
    result			= dotdict()
    with parser.IPADDR_network() as machine:
        with contextlib.closing( machine.run( source=source, data=result )) as engine:
            for m,s in engine:
                if s is None:
                    assert m.terminal
    assert result.IPADDR_network == '10.0.0.1'


def test_IFACEADDRS():
    """TCPIP Object Interface Addresses are in litle-endian byte order."""
    data			= dotdict()
    data.ip_address		= "10.161.1.5"
    data.network_mask		= "255.255.255.0"
    data.gateway_address	= "10.161.1.1"
    data.dns_primary		= "8.8.8.8"
    data.dns_secondary		= "8.8.4.4"
    data.domain_name		= "acme.ca"

    source			= parser.IFACEADDRS.produce( data )
    assert source == b'\x05\x01\xa1\n\x00\xff\xff\xff\x01\x01\xa1\n\x08\x08\x08\x08\x04\x04\x08\x08\x07\x00acme.ca\x00'
    result			= dotdict()
    with parser.IFACEADDRS() as machine:
        with contextlib.closing( machine.run( source=source, data=result )) as engine:
            for m,s in engine:
                pass
    assert result.IFACEADDRS == data


def test_EPATH_single():
    data			= dotdict()
    source			= b'\x12\x0810.0.7.1'
    with parser.EPATH_single() as machine:
        with contextlib.closing( machine.run( source=source, data=data )) as engine:
            for m,s in engine:
                pass

    assert data.EPATH_single.segment == [{"port": 2, "link": "10.0.7.1" }]

    result			= parser.EPATH_single.produce( data.EPATH_single )
    assert result == source

    # Try out an "extended" 16-bit port number
    # [1F][SS][PPPP]'123.123.123.123'[00]	port 0xPPPP,  link address '123.123.123.123' (pad if size SS odd)
    data.EPATH_single.segment[0]['port'] = 0x56CE # 22222
    result			= parser.EPATH_single.produce( data.EPATH_single )
    assert result == b'\x1F\x08\xCE\x5610.0.7.1'

def test_STRINGs():
    """SSTRING is 1-byte len + string; STRING is 2-byte len + string + pad (if odd len)"""
    base			= "Of the increase of His government and peace there shall be no end "
    for l in ( random.randrange( 0, 1000 ) for _ in range( 10 )):
        original		= base * ( l // len( base ) + 1 ) # always at least length l
        encoded			= parser.STRING.produce( value=original )
        assert len( encoded ) == 2 + len( original ) + len( original ) % 2

        result			= dotdict()
        with parser.STRING() as machine:
            with contextlib.closing( machine.run( source=encoded, data=result )) as engine:
                for m,s in engine:
                    pass

        assert result.STRING.length == len( original )
        assert result.STRING.string == original

        try:
            encoded		= parser.SSTRING.produce( value=original )
        except Exception as exc:
            assert len( original ) >= 256, "SSTRING failure: %s" % ( exc )
            continue
        assert len( encoded ) == 1 + len( original )

        result			= dotdict()
        with parser.SSTRING() as machine:
            with contextlib.closing( machine.run( source=encoded, data=result )) as engine:
                for m,s in engine:
                    pass
        assert result.SSTRING.length == len( original )
        assert result.SSTRING.string == original
