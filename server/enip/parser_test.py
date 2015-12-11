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
    result			= cpppo.dotdict()
    with parser.IPADDR() as machine:
        for m,s in machine.run( source=source, data=result ):
            pass
    assert result.IPADDR == '10.0.0.1'

def test_IFACEADDRS():
    data			= cpppo.dotdict()
    data.ip_address		= "10.161.1.5"
    data.network_mask		= "255.255.255.0"
    data.gateway_address	= "10.161.1.1"
    data.dns_primary		= "8.8.8.8"
    data.dns_secondary		= "8.8.4.4"
    data.domain_name		= "acme.com"

    source			= parser.IFACEADDRS.produce( data )
    assert source == b'\n\xa1\x01\x05\xff\xff\xff\x00\n\xa1\x01\x01\x08\x08\x08\x08\x08\x08\x04\x04\x08acme.com'

    result			= cpppo.dotdict()
    with parser.IFACEADDRS() as machine:
        for m,s in machine.run( source=source, data=result ):
            pass
    assert result.IFACEADDRS == data
