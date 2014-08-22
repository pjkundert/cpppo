
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
import traceback

try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
from   cpppo import misc
from   cpppo.server import network
from   cpppo.server import enip
from   cpppo.server.enip import logix

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

    def read( self, path, elements=1, offset=0,
              route_path=None, send_path=None, timeout=None, send=True ):
        req			= cpppo.dotdict()
        req.path		= { 'segment': [ cpppo.dotdict( d ) for d in path ]}
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
                request=req, route_path=route_path, send_path=send_path, timeout=timeout )
        return req

    def write( self, path, data, elements=1, offset=0, tag_type=enip.INT.tag_type,
               route_path=None, send_path=None, timeout=None, send=True ):
        req			= cpppo.dotdict()
        req.path		= { 'segment': [ cpppo.dotdict( d ) for d in path ]}
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
                request=req, route_path=route_path, send_path=send_path, timeout=timeout )
        return req

    def multiple( self, request, path=None, route_path=None, send_path=None, timeout=None, send=True ):
        assert isinstance( request, list ), \
            "A Multiple Service Packet requires a request list"
        req			= cpppo.dotdict()
        if path:
            req.path		= { 'segment': [ cpppo.dotdict( d ) for d in path ]}
        req.multiple		= {
            'request':		request,
        }
        if send:
            self.unconnected_send(
                request=req, route_path=route_path, send_path=send_path, timeout=timeout )
        return req

    def unconnected_send( self, request, route_path=None, send_path=None, timeout=None ):
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

        us.request		= request

        log.detail( "Client Unconnected Send: %s", enip.enip_format( data ))

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
    ap.add_argument( '-f', '--fragment', dest='fragment', action='store_true',
                     help="Use Read/Write Tag Fragmented requests (default: True)" )
    ap.add_argument( '-n', '--no-fragment', dest='fragment', action='store_false',
                     help="Use Read/Write Tag requests (default: False)" )
    ap.set_defaults( fragment=False )
    ap.add_argument( 'tags', nargs="+",
                     help="Tags to read/write, eg: SCADA[1], SCADA[2-10]+4=(DINT)3,4,5")

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
    log.detail( "Client Register Sent %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( request )))
    data			= None # In case nothing is returned by cli iterable
    for data in cli:
        elapsed			= misc.timer() - begun
        log.info( "Client Register Resp %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
        if data is None:
            if elapsed <= timeout:
                cli.readable( timeout=timeout - elapsed )
                continue
        break
    elapsed			= misc.timer() - begun
    log.detail( "Client Register Rcvd %7.3f/%7.3fs: %s" % ( elapsed, timeout, enip.enip_format( data )))
    assert data is not None, "Failed to receive any response"
    assert 'enip.status' in data, "Failed to receive EtherNet/IP response"
    assert data.enip.status == 0, "EtherNet/IP response indicates failure: %s" % data.enip.status
    assert 'enip.CIP.register' in data, "Failed to receive Register response"

    cli.session			= data.enip.session_handle
    
    # Parse each EtherNet/IP Tag Read or Write; only write operations will have 'data'
    #     TAG	 		read 1 value (no element index)
    #     TAG[0] 		read 1 value from element index 0
    #     TAG[1-5]		read 5 values from element indices 1 to 5
    #     TAG[1-5]+4		read 5 values from element indices 1 to 5, beginning at byte offset 4
    #     TAG[4-7]=1,2,3,4	write 4 values from indices 4 to 7
    # 
    # To support access to scalar attributes (no element index allowed in path), we cannot default
    # to supply an element index of 0; default is no element in path, and a data value count of 1.
    # If a byte offset is specified, the request is forced to use Read/Write Tag Fragmented
    # (regardless of whether --[no-]fragment was specified)

    operations			= []
    for tag in args.tags:
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
        opr['path']		= [{'symbolic': tag}]
        if elm is not None:
            opr['path']       += [{'element': elm}]
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

            if 'offset' not in opr and not args.fragment:
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
                    log.normal( "Partial Write Tag Fragmented; elements %d-%d of %d", beg, end-1, cnt )
        operations.append( opr )

    def output( out ):
        log.normal( out )
        if args.print:
            print( out )
            
    # Perform all specified tag operations, the specified number of repeat times.  Doesn't handle
    # fragmented reads yet.  If any operation fails, return a non-zero exit status.  If --multiple
    # specified, perform all operations in a single Multiple Service Packet request.
    
    status			= 0
    start			= misc.timer()
    for i in range( repeat ):
        requests		= []		# If --multiple, collects all requests, else one at at time
        for o in range( len( operations )):
            op			= operations[o] # {'path': [...], 'elements': #}
            begun		= misc.timer()
            if 'offset' not in op:
                op['offset']	= 0 if args.fragment else None
            if 'data' in op:
                descr		= "Write "
                req		= cli.write( timeout=timeout, send=not args.multiple, **op )
            else:
                descr		= "Read  "
                req		= cli.read( timeout=timeout, send=not args.multiple, **op )
            descr	       += "Frag" if op['offset'] is not None else "Tag "
            if args.multiple:
                # Multiple requests; each request is returned simply, not in an Unconnected Send
                requests.append( req )
                if o != len( operations ) - 1:
                    continue
                # No more operations!  Issue the Multiple Service Packet containing all operations
                descr		= "Multiple  "
                cli.multiple( request=requests, timeout=timeout )
            else:
                # Single request issued
                requests	= [ req ]

            # Issue the request(s), and get the response
            elapsed		= misc.timer() - begun
            log.detail( "Client %s Sent %7.3f/%7.3fs: %s" % ( descr, elapsed, timeout, enip.enip_format( request )))
            response			= None
            for response in cli:
                elapsed		= misc.timer() - begun
                log.debug( "Client %s Resp %7.3f/%7.3fs: %s" % ( descr, elapsed, timeout, enip.enip_format( response )))
                if response is None:
                    if elapsed <= timeout:
                        cli.readable( timeout=timeout - elapsed )
                        continue
                break
            elapsed		= misc.timer() - begun
            log.detail( "Client %s Rcvd %7.3f/%7.3fs: %s" % ( descr, elapsed, timeout, enip.enip_format( response )))

            # Find the replies in the response; could be single or multiple; should match requests!
            replies		= []
            if response.enip.status != 0:
                status		= 1
                output( "Client %s Response EtherNet/IP status: %d" % ( descr, response.enip.status ))
            elif args.multiple \
               and 'enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request' in response:
                # Multiple Service Packet; request.multiple.request is an array of read/write_tag/frag
                replies		= response.enip.CIP.send_data.CPF.item[1].unconnected_send.request.multiple.request
            elif 'enip.CIP.send_data.CPF.item[1].unconnected_send.request' in response:
                # Single request; request is a read/write_tag/frag
                replies		= [ response.enip.CIP.send_data.CPF.item[1].unconnected_send.request ]
            else:
                status		= 1
                output( "Client %s Response Unrecognized: " % ( descr, enip.enip_format( response )))

            for request,reply in zip( requests, replies ):
                log.detail( "Client %s Request: %s", descr, enip.enip_format( request ))
                log.detail( "  Yields Reply: %s", enip.enip_format( reply ))
                val		= []   # data values read/written
                res		= None # result of request
                act		= "??" # denotation of request action
                try:
                    tag		= request.path.segment[0].symbolic
                    try:
                        elm	= request.path.segment[1].element	# array access
                    except IndexError:
                        elm	= None					# scalar access
                  
                    # The response should contain either an status code (possibly with an extended
                    # status), or the read_frag request's data.  Remember; a successful response may
                    # carry read_frag.data, but report a status == 6 indicating that more data remains
                    # to return via a subsequent fragmented read request.
                    if 'read_frag' in reply:
                        act	= "=="
                        val	= reply.read_frag.data
                        cnt	= request.read_frag.elements
                    elif 'read_tag' in reply:
                        act	= "=="
                        val	= reply.read_tag.data
                        cnt	= request.read_tag.elements
                    elif 'write_frag' in reply:
                        act	= "<="
                        val	= request.write_frag.data
                        cnt	= request.write_frag.elements
                    elif 'write_tag' in reply:
                        act	= "<="
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
                    status	= 1
                    res		= "Client %s Response missing data: %s" % ( descr, exc )
                    log.detail( "%s: %s", res, ''.join( traceback.format_exception( *sys.exc_info() )), )
                except Exception as exc:
                    status	= 1
                    res		= "Client %s Exception: %s" % ( descr, exc )
                    log.detail( "%s: %s", res, ''.join( traceback.format_exception( *sys.exc_info() )), )

                if elm is None:
                    output( "%20s              %s %r: %r" % ( tag, act, val, res )) # scalar access
                else:
                    output( "%20s[%5d-%-5d] %s %r: %r" % ( tag, elm, elm + cnt - 1, act, val, res ))

    duration			= misc.timer() - start
    log.normal( "Client Tag I/O  Average %7.3f TPS (%7.3fs ea)." % (
        repeat * len( operations ) / duration, duration / repeat / len( operations )))
    return status

if __name__ == "__main__":
    sys.exit( main() )
