from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import contextlib
import logging
import random

import cpppo
from . import parser

log				= logging.getLogger( "parser" )


def test_IPADDR():
    # IP addresses are expressed as Network byte-ordered UDINTs, on the wire
    source			= parser.IPADDR.produce( '10.0.0.1' )
    assert source == b'\x0A\x00\x00\x01'
    # But, we parse them as Network byte-ordered UDINTs and present them as IP addresses
    result			= cpppo.dotdict()
    with parser.IPADDR() as machine:
        with contextlib.closing( machine.run( source=source, data=result )) as engine:
            for m,s in engine:
                if s is None:
                    assert m.terminal
    assert result.IPADDR == '10.0.0.1'


def test_IFACEADDRS():
    data			= cpppo.dotdict()
    data.ip_address		= "10.161.1.5"
    data.network_mask		= "255.255.255.0"
    data.gateway_address	= "10.161.1.1"
    data.dns_primary		= "8.8.8.8"
    data.dns_secondary		= "8.8.4.4"
    data.domain_name		= "acme.ca"

    source			= parser.IFACEADDRS.produce( data )
    assert source == b'\n\xa1\x01\x05\xff\xff\xff\x00\n\xa1\x01\x01\x08\x08\x08\x08\x08\x08\x04\x04\x07\x00acme.ca\x00'

    result			= cpppo.dotdict()
    with parser.IFACEADDRS() as machine:
        with contextlib.closing( machine.run( source=source, data=result )) as engine:
            for m,s in engine:
                pass
    assert result.IFACEADDRS == data


def test_STRINGs():
    """SSTRING is 1-byte len + string; STRING is 2-byte len + string + pad (if odd len)"""
    base			= "Of the increase of His government and peace there shall be no end "
    for l in ( random.randrange( 0, 1000 ) for _ in range( 10 )):
        original		= base * ( l // len( base ) + 1 ) # always at least length l
        encoded			= parser.STRING.produce( value=original )
        assert len( encoded ) == 2 + len( original ) + len( original ) % 2

        result			= cpppo.dotdict()
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

        result			= cpppo.dotdict()
        with parser.SSTRING() as machine:
            with contextlib.closing( machine.run( source=encoded, data=result )) as engine:
                for m,s in engine:
                    pass
        assert result.SSTRING.length == len( original )
        assert result.SSTRING.string == original
