
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import
from __future__ import print_function

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
enip.client	-- basic EtherNet/IP client API
"""

__all__				= ['client']

import argparse
import array
import logging
import select
import socket
import sys

try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
from   cpppo import misc
from   cpppo.server import network
from   cpppo.server import enip
from   cpppo.server.enip import logix

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

log				= logging.getLogger( "enip.cli" )

class client( object ):
    """Transmit request(s), and yield replies as available.  The request will fail (raise
    exception) if it cannot be sent within the specified timeout (None, if no timeout desired).
    After a session is registered, transactions may be pipelined (requests sent before
    responses to previous requests are received.)

    """
    def __init__( self, host, port=None, timeout=None ):
        """Connect to the EtherNet/IP client, waiting  """
        self.addr		= (host or address[0], port or address[1])
        self.conn		= socket.socket(  socket.AF_INET, socket.SOCK_STREAM )
        self.conn.connect( self.addr )
        self.session		= None
        self.source		= cpppo.chainable()
        self.data		= None
        # Parsers
        self.engine		= None # EtherNet/IP frame parsing in progress
        self.frame		= enip.enip_machine( terminal=True )
        self.cip		= enip.CIP( terminal=True )	# Parses a CIP   request in an EtherNet/IP frame
        self.lgx		= logix.Logix().parser		# Parses a Logix request in an EtherNet/IP CIP request

    def __iter__( self ):
        return self

    def next( self ):
        return self.__next__()

    def __next__( self ):
        """Return the next available response, or None if no complete response is available.  Raises
        StopIteration (cease iterating) on EOF.  Any other Exception indicates a client failure,
        and should result in the client instance being discarded.

        """
        # Harvest any input immediately available; terminate on EOF
        rcvd			= network.recv( self.conn, timeout=0 )
        log.detail(
            "EtherNet/IP-->%16s:%-5d rcvd %5d: %s",
            self.addr[0], self.addr[1], len( rcvd ) if rcvd is not None else 0, repr( rcvd ))
        if rcvd is not None:
            # Some input (or EOF).
            if not len( rcvd ):
                raise StopIteration
            self.source.chain( rcvd )

        # Don't create parsing engine 'til we have some I/O to process.  This
        # avoids the degenerate situation where empty I/O (EOF) always matches the
        # empty command (used to indicate the end of an EtherNet/IP session).
        if self.engine is None and self.source.peek() is None:
            return None

        # Initiate or continue parsing input using the machine's engine; discard
        # the engine at termination or on error (Exception).  Any exception
        # (including cpppo.NonTerminal) will be propogated.
        result			= None
        with self.frame as machine:
            try:
                if self.engine is None:
                    self.data	= cpppo.dotdict()
                    self.engine	= machine.run( source=self.source, data=self.data )
                    log.detail(
                        "EtherNet/IP   %16s:%-5d run.: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                        self.addr[0], self.addr[1], machine.name_centered(), machine.current, 
                        self.source.sent, self.source.peek(), self.data )
                    
                for m,s in self.engine:
                    log.detail(
                        "EtherNet/IP<--%16s:%-5d rpy.: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                        self.addr[0], self.addr[1], machine.name_centered(), s,
                        self.source.sent, self.source.peek(), self.data )
            except Exception as exc:
                log.warning( "EtherNet/IP<x>%16s:%-5d err.: %s",
                             self.addr[0], self.addr[1], str( exc ))
                self.engine		= None
                raise
            if machine.terminal:
                log.detail( "EtherNet/IP   %16s:%-5d done: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                            self.addr[0], self.addr[1], machine.name_centered(), machine.current, 
                            self.source.sent, self.source.peek(), self.data )
                # Got an EtherNet/IP frame.  Return it (after parsing its payload.)
                self.engine		= None
                result			= self.data

        # Parse the EtherNet/IP encapsulated CIP frame
        if result is not None:
            with self.cip as machine:
                for m,s in machine.run(
                        path='enip', source=cpppo.peekable( result.enip.input ), data=result ):
                    log.detail(
                        "EtherNet/IP<--%16s:%-5d CIP : %s -> %10.10s; next byte %3d: %-10.10r: %r",
                        self.addr[0], self.addr[1], machine.name_centered(), s,
                        self.source.sent, self.source.peek(), self.data )
                    pass
                assert machine.terminal, "No CIP payload in the EtherNet/IP frame: %r" % ( result )

        # Parse the Logix request responses in the EtherNet/IP CIP payload's CPF items
        if result is not None and 'enip.CIP.send_data' in result:
            for item in result.enip.CIP.send_data.CPF.item:
                if 'unconnected_send.request' in item:
                    # An Unconnected Send that contained an encapsulated request (ie. not just a
                    # Get Attribute All)
                    with self.lgx as machine:
                        for m,s in machine.run(
                                source=cpppo.peekable( item.unconnected_send.request.input ),
                                data=item.unconnected_send.request ):
                            pass
                        assert machine.terminal, "No Logix request in the EtherNet/IP CIP CPF frame: %r" % (
                            result )

        return result

    def send( self, request, timeout=None ):
        """Send encoded request data."""
        assert self.writable( timeout=timeout ), \
            "Failed to send to %r within %7.3fs: %r" % ( self.addr, timeout, request )
        self.conn.send( request )
        log.detail(
            "EtherNet/IP-->%16s:%-5d send %5d: %s",
                    self.addr[0], self.addr[1], len( request ), repr( request ))


    def writable( self, timeout=None ):
        r, w, e			= select.select( [], [self.conn.fileno()], [], timeout )
        return len( w ) > 0

    def readable( self, timeout=None ):
        r, w, e			= select.select( [self.conn.fileno()], [], [], timeout )
        return len( r ) > 0

    def register( self, timeout=None ):
        data			= cpppo.dotdict()
        data.enip		= {}
        data.enip.session_handle= 0
        data.enip.options	= 0
        data.enip.status	= 0
        data.enip.sender_context= {}
        data.enip.sender_context.input = bytearray( [0x00] * 8 )
        data.enip.CIP		= {}
        data.enip.CIP.register 	= {}
        data.enip.CIP.register.options 		= 0
        data.enip.CIP.register.protocol_version	= 1

        data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
        data.input		= bytearray( enip.enip_encode( data.enip ))

        self.send( data.input, timeout=timeout )
        return data

    def read( self, path, elements=1, offset=0, route_path=None, send_path=None, timeout=None ):
        if route_path is None:
            # Default to the CPU in chassis (link 0), port 1
            route_path		= [{'link': 0, 'port': 1}]
        if send_path is None:
            # Default to the Connection Manager
            send_path		= [{'class': 6}, {'instance': 1}]
        assert isinstance( path, list )

        data			= cpppo.dotdict()
        data.enip		= {}
        data.enip.session_handle= self.session
        data.enip.options	= 0
        data.enip.status	= 0
        data.enip.sender_context= {}
        data.enip.sender_context.input = bytearray( [0x00] * 8 )
        data.enip.CIP		= {}
        data.enip.CIP.send_data = {}

        sd			= data.enip.CIP.send_data
        sd.interface		= 0
        sd.timeout		= 0
        sd.CPF			= {}
        sd.CPF.item		= [ cpppo.dotdict(), cpppo.dotdict() ]
        sd.CPF.item[0].type_id	= 0
        sd.CPF.item[1].type_id	= 178
        sd.CPF.item[1].unconnected_send = {}

        us			= sd.CPF.item[1].unconnected_send
        us.service		= 82
        us.status		= 0
        us.priority		= 5
        us.timeout_ticks	= 157
        us.path			= { 'segment': [ cpppo.dotdict( d ) for d in send_path ]}
        us.route_path		= { 'segment': [ cpppo.dotdict( d ) for d in route_path ]}
        us.request		= {}
        us.request.path		= { 'segment': [ cpppo.dotdict( d ) for d in path ]}
        us.request.read_frag 	= {}

        rf			= us.request.read_frag
        rf.elements		= elements
        rf.offset		= offset
        rf.path			= path

        us.request.input	= bytearray( logix.Logix.produce( us.request ))
        sd.input		= bytearray( enip.CPF.produce( sd.CPF ))
        data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
        data.input		= bytearray( enip.enip_encode( data.enip ))

        self.send( data.input, timeout=timeout )
        return data


def main( argv=None ):
    """Read the specified tag(s).  Pass the desired argv (excluding the program
    name in sys.arg[0]; typically pass argv=None, which is equivalent to
    argv=sys.argv[1:], the default for argparse.  Requires at least one tag to
    be defined.

    """
    ap				= argparse.ArgumentParser(
        description = "An EtherNet/IP Client",
        epilog = "" )

    ap.add_argument( '-v', '--verbose',
                     default=0, action="count",
                     help="Display logging information." )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to connect to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )
    ap.add_argument( '-r', '--repeat',
                     default=1,
                     help="Repeat EtherNet/IP request (default: 1)" )
    ap.add_argument( 'tags', nargs="+",
                     help="Any tags to read/write, eg: SCADA[1]")

    args			= ap.parse_args( argv )

    addr			= args.address.split(':')
    assert 1 <= len( addr ) <= 2, "Invalid --address [<interface>]:[<port>}: %s" % args.address
    addr			= ( str( addr[0] ) if addr[0] else enip.address[0],
                                    int( addr[1] ) if len( addr ) > 1 and addr[1] else enip.address[1] )
    
    # Set up logging level (-v...) and --log <file>
    levelmap 			= {
        0: logging.WARNING,
        1: logging.NORMAL,
        2: logging.DETAIL,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )
    if args.log:
        cpppo.log_cfg['filename'] = args.log

    logging.basicConfig( **cpppo.log_cfg )

    timeout			= float( args.timeout )
    repeat			= int( args.repeat )

    begun			= misc.timer()
    cli				= client( host=addr[0], port=addr[1] )
    assert cli.writable( timeout=timeout )
    elapsed			= misc.timer() - begun
    log.normal( "Client Connected in  %7.3f/%7.3fs" % ( elapsed, timeout ))

    # Register, and harvest EtherNet/IP Session Handle
    begun			= misc.timer()
    request			= cli.register( timeout=timeout )
    elapsed			= misc.timer() - begun
    log.normal( "Client Register Sent %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( request )))
    for data in cli:
        elapsed			= misc.timer() - begun
        log.detail( "Client Register Resp %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
        if data is None:
            if elapsed <= timeout:
                cli.readable( timeout=timeout - elapsed )
                continue
        break
    elapsed			= misc.timer() - begun
    log.normal( "Client Register Rcvd %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
    assert data is not None and 'enip.CIP.register' in data, "Failed to receive Register response"
    assert data.enip.status == 0, "Register response indicates failure: %s" % data.enip.status

    cli.session			= data.enip.session_handle
    
    # Parse each EtherNet/IP Tag Read or Write (unsupported)
    #     TAG[0] 	(default)
    #     TAG[1-5]
    operations			= []
    for tag in args.tags:
        # Compute tag, elm, end and cnt (default elm is 0, cnt is 1)
        if '[' in tag:
            tag,elm		= tag.split( '[', 1 )
            elm,_		= elm.split( ']' )
            end			= elm
            if '-' in elm:
                elm,end		= elm.split( '-' )
            elm,end		= int(elm), int(end)
        else:
            elm,end		= 0,0
        cnt			= end + 1 - elm
        operations.append(
            {
                'path': 	[{'symbolic': tag}, {'element': elm}],
                'elements': 	cnt,
            })
            
    # Perform all specified tag operations, the specified number of repeat times.  Doesn't handle
    # writes, or fragmented reads yet.
    start			= misc.timer()
    for i in range( repeat ):
        for op in operations: # {'path': [...], 'elements': #}
            begun		= misc.timer()
            request		= cli.read( offset=0, timeout=timeout, **op )
            elapsed		= misc.timer() - begun
            log.normal( "Client ReadFrg. Sent %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( request )))
            for data in cli:
                elapsed		= misc.timer() - begun
                log.normal( "Client ReadFrg. Resp %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
                if data is None:
                    if elapsed <= timeout:
                        cli.readable( timeout=timeout - elapsed )
                        continue
                break
            elapsed		= misc.timer() - begun
            log.normal( "Client ReadFrg. Rcvd %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
            tag			= op['path'][0]['symbolic']
            elm			= op['path'][1]['element']
            cnt			= op['elements']
            try:
                res		= data.enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.data
            except Exception as exc:
                res		= str( exc )

            log.warning( "%10s[%5d-%-5d] == %r" % ( tag, elm, elm + cnt - 1, res ))


    duration			= misc.timer() - start
    log.warning( "Client ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( repeat / duration, duration / repeat ))

if __name__ == "__main__":
    sys.exit( main() )
