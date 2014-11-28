
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
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ['parse_int', 'parse_path', 'format_path',
                                   'format_context', 'parse_context', 'parse_operations',
                                   'client', 'await', 'connector', 'recycle', 'main']

"""enip.client	-- EtherNet/IP client API and module entry point

    A high-thruput pipelining API for accessing EtherNet/IP CIP Controller data via Tags or
Class/Instance/Attribute numbers.

    Module entry point process tags specified on the command-line and/or from stdin (if '-'
specified).  Optionally prints results (if --print specified).

"""

import argparse
import array
import itertools
import logging
import select
import socket
import sys
import traceback

import cpppo
from   cpppo import misc
from   cpppo.server import (network, enip)
from   cpppo.server.enip import (parser, logix)

log				= logging.getLogger( "enip.cli" )


def parse_int( x, base=10 ):
    """Try parsing in the target base, but then also try deducing the base (eg. if we are provided with
    an explicit base such as 0x..., 0o..., 0b...).

    The reason this is necessary (instead of just using int( x, base=0 ) directly) is because we
    don't want leading zeros (eg. "012") to be interpreted as indicating octal (which is the default).

    """
    try:
        return int( x, base=base )
    except ValueError:
        return int( x, base=0 )


def parse_path( path, element=None ):
    """Convert a "Tag" or "@<class>/<instance>/<attribute>" to a list of EtherNet/IP path segments (if
    a string is supplied).  If element is not None, also appends an 'element' segment.  Numeric form
    allows <class>, <class>/<instance> or <class>/<instance>/<attribute>.

    Resultant path will be a list of the form [{'symbolic': "Tag"}, {'element': 3}], or [{'class':
    511}, {'instance': 1}, {'attribute': 2}].

    If strings are supplied for path or element, any numeric data (eg. class, instance, attribute or
    element numbers) default to integer (eg. 26), but may be escaped with the normal base indicators
    (eg. 0x1A, 0o49, 0b100110).  Leading zeros do NOT imply octal.

    """
    if isinstance( path, cpppo.type_str_base ):
        if path.startswith( '@' ):
            try:
                segments	= [dict( [t] )
                                   for t in zip( ('class','instance','attribute'),
                                                 ( parse_int( i ) for i in path[1:].split('/') ))]
            except Exception as exc:
                raise Exception( "Invalid Numeric @<class>/<inst>/<attr>; 1-3 (default decimal) terms, eg. 26, 0x1A, 0o46, 0b100110: %s" % exc )
        else:
            segments		= [{'symbolic': path}]
    else:
        segments		= path
    if element is not None:
        if isinstance( element, cpppo.type_str_base ):
            element		= parse_int( element )
        segments	       += [{'element': element}]
    return segments


def format_path( segments ):
    """Format some simple path segment lists in a human-readable form.  Raises an Exception if
    unrecognized (only [{'symbolic': <tag>},...] or [{'class': ...}, {'instance': ...},
    {'attribute': ...}, ...] paths are handled.

    Any 'elements' segment is ignored (left to the caller to format appropriately).

    """
    if isinstance( segments, cpppo.type_str_base ):
        path			= segments
    else:
        symbolic		= ''
        numeric			= []
        for seg in segments:
            if 'symbolic' in seg:
                symbolic	= seg['symbolic']
                break
            elif 'class' in seg:
                assert len( numeric ) == 0, "Unformattable path; the class segment must be first"
                numeric.append( "0x%X" % seg['class'] )
            elif 'instance' in seg:
                assert len( numeric ) == 1, "Unformattable path; the instance segment must follow"
                numeric.append( "%d" % seg['instance'] )
            elif 'attribute' in seg:
                assert len( numeric ) == 2, "Unformattable path; the attribute segment must follow class and instance"
                numeric.append( "%d" % seg['attribute'] )
            elif 'element' in seg:
                pass
            else:
                symbolic 	= numeric = None
            assert bool( symbolic ) ^ bool( numeric ), \
                "Unformattable path segment: %r" % seg
        path			= symbolic if symbolic else '/'.join( numeric )
    return path


def format_context( sender_context ):
    """Produce a sender_context bytearray of exactly length 8, NUL-padding on the right."""
    assert isinstance( sender_context, (bytes,bytearray) ), \
        "Expected sender_context of bytes/bytearray, not %r" % sender_context
    return bytearray( sender_context[:8] ).ljust( 8, b'\0' )


def parse_context( sender_context ):
    """Restore a bytes string from a bytearray sender_context, stripping any NUL padding on the
    right."""
    assert isinstance( sender_context, (bytes,bytearray,array.array) ), \
        "Expected sender_context of bytes/bytearray/array, not %r" % sender_context
    return bytes( bytearray( sender_context ).rstrip( b'\0' ))


def parse_operations( tags, fragment=False ):
    """Given a sequence of tags, deduce the set of I/O desired operations, yielding each one.

    Parse each EtherNet/IP Tag Read or Write; only write operations will have 'data':

        TAG	 		read 1 value (no element index)
        TAG[0] 		read 1 value from element index 0
        TAG[1-5]		read 5 values from element indices 1 to 5
        TAG[1-5]+4		read 5 values from element indices 1 to 5, beginning at byte offset 4
        TAG[4-7]=1,2,3,4	write 4 values from indices 4 to 7
        @0x1FF/01/0x1A[99]	read the 100th element of class 511/0x1ff, instance 1, attribute 26

    To support access to scalar attributes (no element index allowed in path), we cannot default to
    supply an element index of 0; default is no element in path, and a data value count of 1.  If a
    byte offset is specified, the request is forced to use Read/Write Tag Fragmented.

    """
    for tag in tags:
        # Compute tag, elm, end and cnt (default elm is None (no element index), cnt is 1)
        val			= ''
        off			= None
        elm,lst			= None,None
        cnt			= 1
        if '=' in tag:
            # A write; strip off the values into 'val'
            tag,val		= tag.split( '=', 1 )
        if '+' in tag:
            # A byte offset (valid for Fragmented)
            tag,off		= tag.split( '+', 1 )
        if '[' in tag:
            tag,elm		= tag.split( '[', 1 )
            elm,_		= elm.split( ']' )
            lst			= elm
            if '-' in elm:
                elm,lst		= elm.split( '-' )
            elm,lst		= int( elm ),int( lst )
            cnt			= lst + 1 - elm

        opr			= {}
        opr['path']		= parse_path( tag, element=elm )
        opr['elements']		= cnt
        if off:
            opr['offset']	= int( off )

        if val:
            if '.' in val:
                opr['tag_type']	= enip.REAL.tag_type
                size		= enip.REAL().calcsize
                cast		= lambda x: float( x )
            else:
                opr['tag_type']	= enip.INT.tag_type
                size		= enip.INT().calcsize
                cast		= lambda x: int( x )
            # Allow an optional (TYPE)value,value,...
            if ')' in val:
                def int_validate( x, lo, hi ):
                    res		= int( x )
                    assert lo <= res <= hi, "Invalid %d; not in range (%d,%d)" % ( res, lo, hi)
                    return res
                typ,val		= val.split( ')' )
                _,typ		= typ.split( '(' )
                opr['tag_type'],size,cast = {
                    'REAL': 	(enip.REAL.tag_type,	enip.REAL().calcsize,	lambda x: float( x )),
                    'DINT':	(enip.DINT.tag_type,	enip.DINT().calcsize,	lambda x: int_validate( x, -2**31, 2**31-1 )),
                    'INT':	(enip.INT.tag_type,	enip.INT().calcsize,	lambda x: int_validate( x, -2**15, 2**15-1 )),
                    'SINT':	(enip.SINT.tag_type,	enip.SINT().calcsize,	lambda x: int_validate( x, -2**7,  2**7-1 )),
                }[typ.upper()]
            opr['data']		= list( map( cast, val.split( ',' )))

            if 'offset' not in opr and not fragment:
                # Non-fragment write.  The exact correct number of data elements must be provided
                assert len( opr['data'] ) == cnt, \
                    "Number of data values (%d) doesn't match element count (%d): %s=%s" % (
                        len( opr['data'] ), cnt, tag, val )
            elif elm != lst:
                # Fragmented write, to an identified range of indices, hence we can check length.
                # If the byte offset + data provided doesn't match the number of elements, then a
                # subsequent Write Tag Fragmented command will be required to write the balance.
                byte		= opr.get( 'offset' ) or 0
                assert byte % size == 0, \
                    "Invalid byte offset %d for elements of size %d bytes" % ( byte, size )
                beg		= byte // size
                end		= beg + len( opr['data'] )
                assert end <= cnt, \
                    "Number of elements (%d) provided and byte offset %d / %d-byte elements exceeds element count %d: " % (
                        len( opr['data'] ), byte, size, cnt )
                if beg != 0 or end != cnt:
                    log.detail( "Partial Write Tag Fragmented; elements %d-%d of %d", beg, end-1, cnt )
        log.detail("Tag: %r yields Operation: %r", tag, opr )
        yield opr



class client( object ):
    """Transmit request(s), and yield replies as available.  The request will fail (raise
    exception) if it cannot be sent within the specified timeout (None, if no timeout desired).
    After a session is registered, transactions may be pipelined (requests sent before
    responses to previous requests are received.)

    """
    def __init__( self, host, port=None ):
        """Connect to the EtherNet/IP client, waiting  """
        self.addr               = (host if host is not None else enip.address[0],
                                   port if port is not None else enip.address[1])
        self.conn		= socket.socket(  socket.AF_INET, socket.SOCK_STREAM )
        try:
            self.conn.connect( self.addr )
        except Exception as exc:
            log.warning( "Couldn't connect to EtherNet/IP server at %s:%s: %s",
                        self.addr[0], self.addr[1], exc )
            raise
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

    def __next__( self ):
        """Return the next available response, or None if no complete response is available.  Raises
        StopIteration (cease iterating) on EOF.  Any other Exception indicates a client failure,
        and should result in the client instance being discarded.
        
        If no input is presently available, harvest any input immediately available; terminate on EOF.

        The response may not actually contain a payload, eg. if the EtherNet/IP header contains a
        non-zero status.
        """
        if self.source.peek() is None:
            rcvd		= network.recv( self.conn, timeout=0 )
            log.info(
                "EtherNet/IP-->%16s:%-5d rcvd %5d: %s",
                self.addr[0], self.addr[1], len( rcvd ) if rcvd is not None else 0, repr( rcvd ))
            if rcvd is not None:
                # Some input (or EOF); source is empty; if no input available, terminate
                if not len( rcvd ):
                    raise StopIteration
                self.source.chain( rcvd )
            else:
                # Don't create parsing engine 'til we have some I/O to process.  This avoids the
                # degenerate situation where empty I/O (EOF) always matches the empty command (used
                # to indicate the end of an EtherNet/IP session).
                if self.engine is None:
                    return None

        # Initiate or continue parsing input using the machine's engine; discard the engine at
        # termination or on error (Exception).  Any exception (including cpppo.NonTerminal) will be
        # propagated.
        result			= None
        with self.frame as machine:
            try:
                if self.engine is None:
                    self.data	= cpppo.dotdict()
                    self.engine	= machine.run( source=self.source, data=self.data )
                    log.debug(
                        "EtherNet/IP   %16s:%-5d run.: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                        self.addr[0], self.addr[1], machine.name_centered(), machine.current, 
                        self.source.sent, self.source.peek(), self.data )
                    
                for m,s in self.engine:
                    log.debug(
                        "EtherNet/IP<--%16s:%-5d rpy.: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                        self.addr[0], self.addr[1], machine.name_centered(), s,
                        self.source.sent, self.source.peek(), self.data )
            except Exception as exc:
                log.warning( "EtherNet/IP<x>%16s:%-5d err.: %s",
                             self.addr[0], self.addr[1], str( exc ))
                self.engine		= None
                raise
            if machine.terminal:
                log.info( "EtherNet/IP   %16s:%-5d done: %s -> %10.10s; next byte %3d: %-10.10r: %r",
                            self.addr[0], self.addr[1], machine.name_centered(), machine.current, 
                            self.source.sent, self.source.peek(), self.data )
                # Got an EtherNet/IP frame.  Return it (after parsing its payload.)
                self.engine		= None
                result			= self.data

        # Parse the EtherNet/IP encapsulated CIP frame, if any.  If the EtherNet/IP header .size was
        # zero, it's status probably indicates why.
        if result is not None and 'enip.input' in result:
            with self.cip as machine:
                for m,s in machine.run(
                        path='enip', source=cpppo.peekable( result.enip.input ), data=result ):
                    log.debug(
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

    next = __next__ # Python 2/3 compatibility

    def send( self, request, timeout=None ):
        """Send encoded request data."""
        assert self.writable( timeout=timeout ), \
            "Failed to send to %r within %7.3fs: %r" % ( self.addr, timeout, request )
        self.conn.send( request )
        log.info(
            "EtherNet/IP-->%16s:%-5d send %5d: %s",
                    self.addr[0], self.addr[1], len( request ), repr( request ))


    def writable( self, timeout=None ):
        r, w, e			= select.select( [], [self.conn.fileno()], [], timeout )
        return len( w ) > 0

    def readable( self, timeout=None ):
        r, w, e			= select.select( [self.conn.fileno()], [], [], timeout )
        return len( r ) > 0

    def register( self, timeout=None, sender_context=b'' ):
        data			= cpppo.dotdict()
        data.enip		= {}
        data.enip.session_handle= 0
        data.enip.options	= 0
        data.enip.status	= 0
        data.enip.sender_context= {}
        data.enip.sender_context.input = format_context( sender_context )

        data.enip.CIP		= {}
        data.enip.CIP.register 	= {}
        data.enip.CIP.register.options 		= 0
        data.enip.CIP.register.protocol_version	= 1

        data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
        data.input		= bytearray( enip.enip_encode( data.enip ))

        self.send( data.input, timeout=timeout )
        return data

    def read( self, path, elements=1, offset=0,
              route_path=None, send_path=None, timeout=None, send=True,
              sender_context=b'' ):
        req			= cpppo.dotdict()
        req.path		= { 'segment': [ cpppo.dotdict( d ) for d in parse_path( path ) ]}
        if offset is None:
            req.read_tag	= {
                'elements':	elements
            }
        else:
            req.read_frag	= {
                'elements':	elements,
                'offset':	offset,
            }
        if send:
            self.unconnected_send(
                request=req, route_path=route_path, send_path=send_path, timeout=timeout,
                sender_context=sender_context )
        return req

    def write( self, path, data, elements=1, offset=0, tag_type=enip.INT.tag_type,
               route_path=None, send_path=None, timeout=None, send=True,
               sender_context=b'' ):
        req			= cpppo.dotdict()
        req.path		= { 'segment': [ cpppo.dotdict( d ) for d in parse_path( path )]}
        if offset is None:
            req.write_tag	= {
                'elements':	elements,
                'data':		data,
                'type':		tag_type,
            }
        else:
            req.write_frag	= {
                'elements':	elements,
                'offset':	offset,
                'data':		data,
                'type':		tag_type,
            }
        if send:
            self.unconnected_send(
                request=req, route_path=route_path, send_path=send_path, timeout=timeout,
                sender_context=sender_context )

        return req

    def multiple( self, request, path=None, route_path=None, send_path=None, timeout=None, send=True,
                          sender_context=b'' ):
        assert isinstance( request, list ), \
            "A Multiple Service Packet requires a request list"
        req			= cpppo.dotdict()
        if path:
            req.path		= { 'segment': [ cpppo.dotdict( d ) for d in parse_path( path )]}
        req.multiple		= {
            'request':		request,
        }
        if send:
            self.unconnected_send(
                request=req, route_path=route_path, send_path=send_path, timeout=timeout,
                sender_context=sender_context )
        return req

    def unconnected_send( self, request, route_path=None, send_path=None, timeout=None,
                          sender_context=b'' ):
        if route_path is None:
            # Default to the CPU in chassis (link 0), port 1
            route_path		= [{'link': 0, 'port': 1}]
        if send_path is None:
            # Default to the Connection Manager
            send_path		= [{'class': 6}, {'instance': 1}]
        assert isinstance( request, dict )

        data			= cpppo.dotdict()
        data.enip		= {}
        data.enip.session_handle= self.session
        data.enip.options	= 0
        data.enip.status	= 0
        data.enip.sender_context= {}
        data.enip.sender_context.input = format_context( sender_context )
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
        us.path			= { 'segment': [ cpppo.dotdict( d ) for d in parse_path( send_path ) ]}
        us.route_path		= { 'segment': [ cpppo.dotdict( d ) for d in route_path ]} # must be {link/port}

        us.request		= request

        log.detail( "Client Unconnected Send: %s", enip.enip_format( data ))

        us.request.input	= bytearray( logix.Logix.produce( us.request ))
        sd.input		= bytearray( enip.CPF.produce( sd.CPF ))
        data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
        data.input		= bytearray( enip.enip_encode( data.enip ))

        log.info( "EtherNet/IP: %3d + CIP: %3d + CPF: %3d + Request: %3d == %3d bytes total",
                  len( data.input ) - len( data.enip.input ),
                  len( data.enip.input ) - len( sd.input ),
                  len( sd.input ) - len( us.request.input ),
                  len( us.request.input ),
                  len( data.input ))

        self.send( data.input, timeout=timeout )
        return data


def await( cli, timeout=None ):
    """Await a response on an iterable client() instance (for timeout seconds, or forever if None).
    Returns (response,elapsed).  A 'timeout' may be supplied, of:

        0         --> Immediate timeout (response must be ready)
        None      --> No timeout (wait forever for response)
        float/int --> The specified number of seconds

    """
    response			= None
    begun			= cpppo.timer()
    for response in cli:
        if response is None:
            elapsed		= cpppo.timer() - begun
            if not timeout or elapsed <= timeout:
                if cli.readable( timeout=timeout if not timeout else timeout - elapsed ):
                    continue # Client I/O pending w/in timeout; see if response complete
        break
    elapsed			= cpppo.timer() - begun
    return response,elapsed


class connector( client ):
    """Register a connection to an EtherNet/IP controller, storing the returned session_handle in
    self.session, ready for processing further requests.

    Raises an Exception if no valid connection can be established within the supplied io_timeout.

    """
    def __init__( self, host, port=None, timeout=1, **kwds ):
        super( connector, self ).__init__( host=host, port=port, **kwds )

        begun			= cpppo.timer()
        try:
            request		= self.register( timeout=timeout )
            elapsed_req		= cpppo.timer() - begun
            data,elapsed_rpy	= await( self, timeout=max( 0, timeout - elapsed_req ))

            assert data is not None, "Failed to receive any response"
            assert 'enip.status' in data, "Failed to receive EtherNet/IP response"
            assert data.enip.status == 0, "EtherNet/IP response indicates failure: %s" % data.enip.status
            assert 'enip.CIP.register' in data, "Failed to receive Register response"

            self.session	= data.enip.session_handle
        except Exception as exc:
            logging.warning( "Connect:  Failure in %7.3fs/%7.3fs: %s", cpppo.timer() - begun, exc )
            raise

        logging.detail( "Connect:  Success in %7.3fs/%7.3fs", elapsed_req + elapsed_rpy, timeout )

    def close( self ):
        self.conn.close()

    def __del__( self ):
        self.close()

    def issue( self, operations, index=0, fragment=False, multiple=0, timeout=None ):
        """Issue a sequence of I/O operations, returning the corresponding sequence of:
        (<index>,<context>,<descr>,<op>,<request>).  If a non-zero 'multiple' is provided, bundle requests
        'til we exceed the specified multiple service packet request size limit. 

        Each op is instrumented with a sender_context based on the provided 'index', indicating the
        actual EtherNet/IP CIP request it is part of.  This can be used to detect how many actual
        I/O requests are on the wire if some are merged into Multiple Service Packet requests and
        some are single requests.

        """
        sender_context		= str( index ).encode( 'iso-8859-1' )
        requests,siz		= [],0	# If we're collecting for a Multiple Service Packet
        for op in operations:
            # Chunk up requests if using Multiple Service Request, otherwise send immediately
            descr		= "Multi. " if multiple else "Single "
            op['sender_context']= sender_context
            if 'offset' not in op:
                op['offset']	= 0 if fragment else None
            begun		= cpppo.timer()
            if 'data' in op:
                descr	       += "Write "
                req		= self.write( timeout=timeout, send=not multiple, **op )
                est		= 10 + parser.typed_data.estimate(
                    tag_type=op.get( 'tag_type', enip.INT.tag_type ), data=op['data'] )
            else:
                descr	       += "Read  "
                req		= self.read( timeout=timeout, send=not multiple, **op )
                est		= 10
            elapsed		= cpppo.timer() - begun
            descr	       += 'Frag' if op['offset'] is not None else 'Tag '
            descr	       += ' ' + format_path( op['path'] )

            if multiple:
                if siz + est < multiple or not requests:
                    # Multiple Service Packet siz OK; keep collecting (at least one!)
                    siz	       += est
                else:
                    # Multiple Service Packet siz too full w/ this req; issue requests and queue it
                    begun	= cpppo.timer()
                    mul		= self.multiple( request=[r for d,o,r in requests], timeout=timeout,
                                                 sender_context=sender_context )
                    elapsed	= cpppo.timer() - begun
                    if log.isEnabledFor( logging.DETAIL ):
                        log.detail( "Sent %7.3f/%7.3fs: %s %s", elapsed,
                            misc.inf if timeout is None else timeout, descr,
                            enip.enip_format( mul ))
                    for d,o,r in requests:
                        yield index,sender_context,d,o.r
                    index      += 1
                    requests	= []
                    siz		= est
                requests.append( (descr,op,req) )
                if log.isEnabledFor( logging.DETAIL ):
                    log.detail( "Que. %7.3f/%7.3fs: %s %s", 0, 0, descr, enip.enip_format( req ))
            else:
                # Single request issued
                if log.isEnabledFor( logging.DETAIL ):
                    log.detail( "Sent %7.3f/%7.3fs: %s %s", elapsed,
                                misc.inf if timeout is None else timeout, descr,
                                enip.enip_format( req ))
                yield index,sender_context,descr,op,req
                index	       += 1

            sender_context = str( index ).encode( 'iso-8859-1' )

        # No more operations!  Issue the (final) Multiple Service Packet w/ remaining requests
        if multiple and requests:
            begun		= cpppo.timer()
            mul			= self.multiple( request=[r for d,o,r in requests], timeout=timeout,
                                                 sender_context=sender_context )
            elapsed		= cpppo.timer() - begun
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "Sent %7.3f/%7.3fs: %s %s", elapsed,
                            misc.inf if timeout is None else timeout, "Multiple Service Packet",
                            enip.enip_format( req ))
            for d,o,r in requests:
                yield index,sender_context,d,o,r

    def collect( self, timeout=None ):
        """Yield collected request replies 'til timeout expires (raising StopIteration), or until a
        GeneratorExit is raised (no more responses expected, and generator was discarded).  Yields a
        sequence of: (<context>,<reply>,<status>,<value>).

        <context> is a bytes string (any NUL padding on the right removed); All replies in a
        Multiple Service Packet response will have the same <context>.

        <reply> is the individual parsed read/write reply, regardless of whether it came back as an
        individual response, or as part of a Multiple Service Packet payload.

        <status> may be an int or a tuple (int,[int...]) if extended status codes returned.
        Remember: Success (0x00) and Partial Data (0x06) both return valid data!

        <value> will be True for writes, a non-empty array of data for reads, None if there was a
        failure with the request (will by Truthy on Success, Falsey on Failure.)

        """
        while True:
            response,elapsed	= await( self, timeout=timeout )
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "Rcvd %7.3f/%7.3fs %s", elapsed,
                            misc.inf if timeout is None else timeout,
                            enip.enip_format( response ))

            # Find the replies in the response; could be single or multiple; should match requests!
            if response is None:
                raise StopIteration( "Response Not Received w/in %7.2fs" % ( timeout ))
            elif response.enip.status != 0:
                raise Exception( "Response EtherNet/IP status: %d" % ( response.enip.status ))
            elif 'enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request' in response:
                # Multiple Service Packet; request.multiple.request is an array of read/write_tag/frag
                replies		= response.enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request
            elif 'enip.CIP.send_data.CPF.item[1].unconnected_send.request' in response:
                # Single request; request is a read/write_tag/frag
                replies		= [ response.enip.CIP.send_data.CPF.item[1].unconnected_send.request ]
            else:
                raise Exception( "Response Unrecognized: %s" % ( enip.enip_format( response )))
            for reply in replies:
                val	= None
                sts	= reply.status			# sts = # or (#,[#...])
                if reply.status in (0x00,0x06):		# Success or Partial Data; val is Truthy
                    if 'read_frag' in reply:
                        val	= reply.read_frag.data
                    elif 'read_tag' in reply:
                        val	= reply.read_tag.data
                    elif 'write_frag' in reply:
                        val	= True
                    elif 'write_tag' in reply:
                        val	= True
                    else:
                        raise Exception( "Reply Unrecognized: %s" % ( enip.enip_format( reply )))
                else:					# Failure; val is Falsey
                    if 'status_ext' in reply and reply.status_ext.size:
                        sts	= (reply.status,reply.status_ext.data)
                yield parse_context(response.enip.sender_context.input),reply,sts,val

    def harvest( self, issued, timeout=None ):
        """As we iterate over issued requests, collect the corresponding replies, match them up, and
        yield them as: (<index>,<descr>,<request>,<reply>,<status>,<value>).

        Invoke this directly with self.issue(...) to synchronously issue requests and collect their
        responses:
            tags		= [ "SCADA[1]=99", "SCADA[0-9]" ]
            operations		= parse_operations( tags )
            for idx,dsc,req,rpy,sts,val in cli.harvest( issued=cli.issue( operations, ... ))):
                ...

        Or, arrange for 'issued' to be a container (eg. list) which supports iteration and appending
        simultaneously, and then issue multiple requests before starting to harvest the results (see
        pipeline).

        """
        for iss,col in zip( issued, self.collect( timeout=timeout )):
            index,req_ctx,descr,op,request \
				= iss
            rpy_ctx,reply,status,value \
				= col
            assert rpy_ctx == req_ctx, "Mismatched request/reply: %r vs. %r" % ( req_ctx, rpy_ctx )
            yield index,descr,request,reply,status,value

    # 
    # synchronous
    # pipeline
    # 
    #     The normal APIs for issuing transactions and harvesting the corresponding results.
    # 
    #     The <value> yielded comes from the reply, hence there is a data list for reads, but no data
    # for writes (just a True).
    #
    #     None	-- Request failure
    #     True	-- Request successful write (no resultant data)
    #     [...]	-- Request successful read data
    # 
    #     Use validate to post-process these results, to fill in data for reads (from the request).
    # 
    def synchronous( self, operations, index=0, fragment=False, multiple=0, timeout=None ):
        """Issue the requested 'operations' synchronously.  Yield each harvested record.

        """
        for col in self.harvest(
                issued=self.issue(
                    operations=operations, index=index, fragment=fragment, multiple=multiple,
                    timeout=timeout ),
                timeout=timeout ):
            yield col

    def pipeline( self, operations, index=0, fragment=False, multiple=0, timeout=None, depth=1 ):
        """Issue the requested 'operations', allowing up to 'depth' outstanding requests to be in the
        pipeline, before beginning to harvest results.  Yield each harvested record.

        """
        harvester		= None
        last			= index - 1	# The index of the last reply collected
        inflight		= []		# We iterate over this as we append to it...
        complete		= 0
        for curr,req_ctx,descr,op,req in self.issue(
                operations=operations, index=index, fragment=fragment, multiple=multiple,
                timeout=timeout ):
            inflight.append( (curr,req_ctx,descr,op,req) )
            while curr - last > depth:
                # The current outgoing request's index is more than 'depth' away from the last
                # response seen.  Soak up some responses 'til the last reaches w'in depth of curr.
                if harvester is None:
                    harvester	= self.harvest( issued=iter( inflight ), timeout=timeout )
                col		= next( harvester )
                last		= col[0]
                complete       += 1
                log.detail( "Completed %3d/%3d; curr: %3d - last: %3d == %3d depth",
                          complete, len( inflight ), curr, last, curr - last )
                yield col

        if harvester is None:
            harvester		= self.harvest( issued=iter( inflight ), timeout=timeout )
        for col in harvester:
            complete	       += 1
            last		= col[0]
            log.detail( "Draining  %3d/%3d; curr: %3d - last: %3d == %3d depth",
                        complete, len( inflight ), curr, last, curr - last )
            yield col

    def validate( self, harvested, printing=False ):
        """Iterate over the harvested (<index>,<descr>,<request>,<reply>,<status>,<value>) tuples, logging
        further details and (optionally) printing a summary to stdout if desired.  Each harvested
        record is re-yielded.

        Fill in the <value> detail from the request before re-yielding harvested tuple (records for
        both reads and writes will carry data arrays).

        """
        for index,descr,request,reply,status,val in harvested:
            log.detail( "Client %s Request: %s", descr, enip.enip_format( request ))
            log.detail( "  Yields Reply: %s", enip.enip_format( reply ))
            res			= None # result of request
            act			= "??" # denotation of request action
            try:
                # Get a symbolic "Tag" or numeric "@<class>/<inst>/<attr>" into 'tag', and optional
                # element into 'elm'.  Assumes the leading path.segment elements will be either
                # 'symbolic' or 'class', 'instance', 'attribute', and the last may be 'element'.
                tag		= format_path( request.path.segment )
                elm		= None					# scalar access
                if 'element' in request.path.segment[-1]:
                    elm		= request.path.segment[-1].element	# array access

                # The response should contain either an status code (possibly with an extended
                # status), or the read_frag request's data.  Remember; a successful response may
                # carry read_frag.data, but report a status == 6 indicating that more data remains
                # to return via a subsequent fragmented read request.  Compute any Read/Write Tag
                # Fragmented 'off'-set, in elements (the Read request and the Write response
                # contains the offset and the data type).
                if 'read_frag' in reply:
                    act	= "=="
                    off = request.read_frag.get( 'offset', 0 ) \
                          // enip.parser.typed_data.estimate( reply.read_frag['type'], [1] )
                    val	= reply.read_frag.data
                    cnt	= len( val )
                elif 'read_tag' in reply:
                    act	= "=="
                    off = 0
                    val	= reply.read_tag.data
                    cnt	= len( val )
                elif 'write_frag' in reply:
                    act	= "<="
                    off = request.write_frag.get( 'offset', 0 ) \
                          // enip.parser.typed_data.estimate( request.write_frag['type'], [1] )
                    val	= request.write_frag.data
                    cnt	= request.write_frag.elements - off
                elif 'write_tag' in reply:
                    act	= "<="
                    off = 0
                    val	= request.write_tag.data
                    cnt	= request.write_tag.elements
                if not reply.status:
                    res	= "OK"
                else:
                    res	= "Status %d %s" % ( reply.status,
                        repr( reply.status_ext.data ) if 'status_ext' in reply and reply.status_ext.size else "" )
                if reply.status:
                    if not status:
                        status	= reply.status
                    log.warning( "Client %s returned non-zero status: %s", descr, res )

            except AttributeError as exc:
                res		= "Client %s Response missing data: %s" % ( descr, exc )
                log.warning( "%s: %s", res, ''.join( traceback.format_exception( *sys.exc_info() )), )
                raise
            except Exception as exc:
                res		= "Client %s Exception: %s" % ( descr, exc )
                log.warning( "%s: %s", res, ''.join( traceback.format_exception( *sys.exc_info() )), )
                raise

            if elm is None:
                line		= "%20s              %s %r: %r" % ( tag, act, val, res ) # scalar access
            else:
                line		= "%20s[%5d-%-5d] %s %r: %r" % ( tag, elm + off, elm + off + cnt - 1, act, val, res )
            log.normal( line )
            if printing:
                print( line )
            yield index,descr,request,reply,status,val

    # 
    # process
    # 
    #     Simple, high-level API entry point that eliminates the need to process any yielded
    # sequences, and simply returns the number of (<failures>,<transactions>), optionally printing a
    # summary of I/O performed.
    # 
    def process( self, operations, depth=0, multiple=0, fragment=False, printing=False, timeout=None ):
        """Process a sequence of I/O operations.  If a non-zero 'depth' is specified, then pipeline the
        requests allowing 'depth' outstanding transactions to be in-flight; otherwise, we just issue
        the transactions synchronously.  Returns the a tuple (<failures>,<transactions>).  Raises
        Exception on catastrophic failure of the connection.

        """
        failures		= 0
        transactions		= 0
        if depth:
            harvested		= self.pipeline(
                operations=operations, multiple=multiple, fragment=fragment, timeout=timeout,
                depth=depth )
        else:
            harvested		= self.synchronous(
                operations=operations, multiple=multiple, fragment=fragment, timeout=timeout )
        validated		= self.validate( harvested=harvested, printing=printing )
        for idx,dsc,req,rpy,sts,val in validated:
            transactions       += 1
            if val is None:
                failures       += 1
        return failures,transactions


def recycle( iterable, times=None ):
    """Record and repeat an iterable x 'times'; forever if times is None (the default), not at all if
    times is 0.  Like itertools.cycle, but with an optional 'times' limit.

    """
    assert times is None or ( times // 1 == times and times >= 0 ), \
        "Invalid cycle 'times'; must be None or +'ve integer: %r" % ( times )
    saved			= []
    if times == 0:
        return
    for element in iterable:
        yield element
        saved.append( element )

    while times != 1:
        for element in saved:
              yield element
        if times is not None:
            times	       -= 1


def main( argv=None ):
    """Read the specified tag(s).  Pass the desired argv (excluding the program
    name in sys.arg[0]; typically pass argv=None, which is equivalent to
    argv=sys.argv[1:], the default for argparse.  Requires at least one tag to
    be defined.

    """
    ap				= argparse.ArgumentParser(
        description = "An EtherNet/IP Client",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """\
One or more EtherNet/IP CIP Tags may be read or written.  The full format for
specifying a tag and an operation is:

    Tag[<first>-<last>]+<offset>=(SINT|INT|DINT|REAL)<value>,<value>

All components except Tag are optional.  Specifying a +<offset> (in bytes)
forces the use of the Fragmented command, regardless of whether --[no-]fragment
was specified.  If an element range [<first>] or [<first>-<last>] was specified
and --no-fragment selected, then the exact correct number of elements must be
provided.""" )

    ap.add_argument( '-v', '--verbose',
                     default=0, action="count",
                     help="Display logging information." )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to connect to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
    ap.add_argument( '-p', '--print', default=False, action='store_true',
                     help="Print a summary of operations to stdout" )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )
    ap.add_argument( '-r', '--repeat',
                     default=1,
                     help="Repeat EtherNet/IP request (default: 1)" )
    ap.add_argument( '-m', '--multiple', action='store_true',
                     help="Use Multiple Service Packet request (default: False)" )
    ap.add_argument( '-d', '--depth', default=1,
                     help="Pipeline requests to this depth (default: 1)" )
    ap.add_argument( '-f', '--fragment', dest='fragment', action='store_true',
                     default=False,
                     help="Always use Read/Write Tag Fragmented requests (default: False)" )
    ap.add_argument( 'tags', nargs="+",
                     help="Tags to read/write (- to read from stdin), eg: SCADA[1], SCADA[2-10]+4=(DINT)3,4,5" )

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
    depth			= int( args.depth )
    multiple			= 500 if args.multiple else 0
    fragment			= bool( args.fragment )
    printing			= args.print

    if '-' in args.tags:
        # Collect tags from sys.stdin 'til EOF, at position of '-' in argument list
        minus			= args.tags.index( '-' )
        tags			= itertools.chain( args.tags[:minus], sys.stdin, args.tags[minus+1:] )
    else:
        tags			= args.tags

    # Register and EtherNet/IP CIP connection to a Controller
    begun			= misc.timer()
    connection			= connector( host=addr[0], port=addr[1], timeout=timeout )
    elapsed			= misc.timer() - begun
    log.detail( "Client Register Rcvd %7.3f/%7.3fs" % ( elapsed, timeout ))

    # Issue Tag I/O operations, optionally printing a summary
    begun			= misc.timer()
    operations			= parse_operations( recycle( tags, times=repeat ))
    failures,transactions	= connection.process(
        operations=operations, depth=depth, multiple=multiple,
        fragment=fragment, printing=printing, timeout=timeout )
    elapsed			= misc.timer() - begun
    log.normal( "Client Tag I/O  Average %7.3f TPS (%7.3fs ea)." % (
        transactions / elapsed, elapsed / transactions ))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit( main() )
