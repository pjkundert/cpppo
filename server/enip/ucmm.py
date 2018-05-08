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

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

_all__				= [ 'UCMM']

"""enip.ucmm -- Un-Connected Message Manager"""

import random
import contextlib
import logging
import sys
import threading
import traceback

from ...dotdict import dotdict
from . import parser, device, client

log				= logging.getLogger( "enip.ucmm" )


def port_link_expand( items ):
    """Handle any "1/1-15": ap style port/link specifications, yielding "1/1":ap, "1/2":ap, ..."""
    for pl,ap in items:
        try:
            port,lkrng		= map( str.strip, str( pl ).split( '/', 1 ))	# 1/1-15
            lklo,lkhi		= map( int,    lkrng.split( '-', 1 ))		#   1-15
            for link in range( lklo, lkhi + 1 ):				# range( 1, 16 )
                plsub		= "%s/%s" % ( port, link )
                yield plsub,ap
        except:
            yield pl,ap


def addr_port( ip, port=44818 ):
    """Split ip into ("<ip>",<port>), defaulting port to 44818, and return as tuple."""
    try:
        if ':' in ip:
            ip,port		= map( str.strip, str( ip ).split( ':', 1 ))
            port		= int( port )
    except:
        raise AssertionError( "addr[:port]: port must be :<int>" )
    return (ip,port)


class UCMM( device.Object ):
    """Un-Connected Message Manager, handling Register/Unregister of connections, and sending
    Unconnected Send messages to either directly to a local object, or to the local Connection
    Manager for parsing/processing, or to a remote EtherNet/IP CIP device via a configure Route.


    Forwards encapsulated messages to their destination port/link address, and returns the
    encapsulated response.  The Unconnected Send message contains an encapsulated message and a
    route path with 1 or more route segment groups.  If more than 1 group remains, the first group
    is removed, and the address is used to establish a connection and send the message on; the
    response is received and returned.

    When only the final route path segment remains, the encapsulated message is sent to the local
    Message Router, and its response is received and returned.

    Presently, we only respond to Unconnected Send messages with one route_path segment; a local
    port/link address, or no route_path (if configure route_path is False/0).

    """

    class_id			= 0x9999	# Not an addressable Object; should this be Class 0?
    route_path			= None		# Specify, if we want to reject invalid ones
    route			= {}		# Maps <port>/<link> --> <ip>[:<port>]

    parser			= parser.CIP()
    command			= {
        0x0065: "Register Session",
        0x0066: "Unregister Session",
        0x006f: "SendRRData",
    }
    lock			= threading.Lock()
    sessions			= {}		# All known session handles, by addr


    def __init__( self, *args, **kwds ):
        """Load any UCMM configurations (eg. route_path, routing table).   """
        super( UCMM, self ).__init__( *args, **kwds )
        if self.instance_id == 0: # meta-Object? 
            return

        # If a [UCMM] Route Path is configured, it only overrides self.route_path if it is None --
        # if no specific route_path was provided at run-time (eg. on the command line).  The provided
        # one must be valid JSON.  If it's null (None), then any route_path will be allowed.  Supports
        # "1/1", "1/1.2.3.4" or JSON '{"port":<int>, "link":<int>/"ip"}' format
        if self.route_path is None:
            self.route_path	= device.parse_route_path( self.config_str( "Route Path", None ))
        log.normal( "UCMM accepts route_path: %s",
                    "(any)" if self.route_path is None else self.route_path )

        # If a [UCMM] Route is configured, get base configuration from config file, overridden with
        # any locally specified mappings.  Then, convert all "<port>/<link>" keys to tuples, and all
        # "<ip>[:<port>]" to tuples.
        route			= self.config_json( "Route", '{}' )
        route.update( self.route )
        self.route		= { "{port}/{link}".format( **device.port_link( pl )): addr_port( ap )
                                    for pl,ap in port_link_expand( route.items() ) }
        if self.route:
            log.normal( "UCMM has %d routes: %s", len( self.route ),
                        ", ".join( "%s --> %s:%d" % ( pl, ap[0], ap[1] ) for pl,ap in self.route.items() ))

        # Each incoming request route_path {"port":<int>,"link":<int>/"<ip>"} that matches a
        # "<port>/<link>" entry in self.route will get sent to the designated target CIP device at
        # "<host>":<port>.  However, it is the *follow* route_path element (if any) that routes the
        # request in that destination device.  We'll use a enip.client.connector (to establish and
        # register an EtherNet/IP session) for each target "<host>":<port>, and arrange for a copy
        # of the request to be sent via <conn>.unconnected_send.  Then, we'll client.await a
        # response from the socket; a failure to receive a response w'in timeout will result in an
        # error status being returned.
        self.route_conn		= {}


    def request( self, data ):
        """Handles a parsed enip.* request, and converts it into an appropriate response.  For
        connection related requests (Register, Unregister), handle locally.  Return True iff request
        processed and connection should proceed to process further messages.

        """
        if log.isEnabledFor( logging.INFO ):
            log.info( "%r Request: %s", self, parser.enip_format( data ))

        proceed			= True

        assert 'addr' in data, "Connection Manager requires client address"

        # Each EtherNet/IP enip.command expects an appropriate encapsulated response
        if 'enip' in data:
            data.enip.pop( 'input', None )
        try:
            if 'enip.CIP.register' in data:
                # Allocates a new session_handle, and returns the register.protocol_version and
                # .options_flags unchanged (if supported)
        
                with self.lock:
                    session	= random.randint( 0, 2**32 )
                    while not session or session in self.__class__.sessions:
                        session	= random.randint( 0, 2**32 )
                    self.__class__.sessions[data.addr] = session
                data.enip.session_handle = session
                log.detail( "EtherNet/IP (Client %r) Session Established: %r", data.addr, session )
                data.enip.input	= bytearray( self.parser.produce( data.enip ))
                data.enip.status= 0x00

            elif 'enip.CIP.unregister' in data or 'enip' not in data:
                # Session being closed.  There is no response for this command; return False
                # inhibits any EtherNet/IP response from being generated, and closes connection.
                with self.lock:
                    session	= self.__class__.sessions.pop( data.addr, None )
                log.detail( "EtherNet/IP (Client %r) Session Terminated: %r", data.addr, 
                            session or "(Unknown)" )
                proceed		= False
            
            elif 'enip.CIP.send_data' in data:
                # An Unconnected Send (SendRRData) message may be to a local object, eg:
                # 
                #     "enip.CIP.send_data.CPF.count": 2, 
                #     "enip.CIP.send_data.CPF.item[0].length": 0, 
                #     "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                #     "enip.CIP.send_data.CPF.item[1].length": 6, 
                #     "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 102, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 1, 
                #     "enip.CIP.send_data.interface": 0, 
                #     "enip.CIP.send_data.timeout": 5, 
                
                # via the Message Router (note the lack of ...unconnected_send.route_path), or
                # potentially to a remote object, via the backplane or a network link route path:

		#     "enip.CIP.send_data.CPF.count": 2, 
		#     "enip.CIP.send_data.CPF.item[0].length": 0, 
		#     "enip.CIP.send_data.CPF.item[0].type_id": 0, 
		#     "enip.CIP.send_data.CPF.item[1].length": 20, 
		#     "enip.CIP.send_data.CPF.item[1].type_id": 178, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 6, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', '\\x01\\x02 \\x01$\\x01')", 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].link": 0, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].port": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.size": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 250, 
                # which carries:
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.get_attributes_all": true, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].class": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].instance": 1, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 2, 
		#     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 1, 
                # or:
                #     "enip.CIP.send_data.CPF.count": 2, 
                #     "enip.CIP.send_data.CPF.item[0].length": 0, 
                #     "enip.CIP.send_data.CPF.item[0].type_id": 0, 
                #     "enip.CIP.send_data.CPF.item[1].length": 32, 
                #     "enip.CIP.send_data.CPF.item[1].type_id": 178, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.length": 18, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.priority": 5, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.input": "array('c', 'R\\x05\\x91\\x05SCADA\\x00(\\x0c\\x01\\x00\\x00\\x00\\x00\\x00')", 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[0].class": 6, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.segment[1].instance": 1, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.path.size": 2, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].link": 0, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.segment[0].port": 1, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.route_path.size": 1, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 82, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.timeout_ticks": 157, 
                #     "enip.CIP.send_data.interface": 0, 
                #     "enip.CIP.send_data.timeout": 5,
                # which encapsulates:
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[0].symbolic": "SCADA", 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.segment[1].element": 12, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.path.size": 5, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.elements": 1, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.read_frag.offs et": 0, 
                #     "enip.CIP.send_data.CPF.item[1].unconnected_send.request.service": 82, 

                # which must (also) be processed by the Message Router at the end of all the address
                # or backplane hops.

                # All Unconnected Requests have a NULL Address in CPF item 0.
                assert 'enip.CIP.send_data.CPF' in data \
                    and data.enip.CIP.send_data.CPF.count == 2 \
                    and data.enip.CIP.send_data.CPF.item[0].length == 0, \
                    "EtherNet/IP UCMM remote routed requests unimplemented"
                unc_send	= data.enip.CIP.send_data.CPF.item[1].unconnected_send

                # See what the request's parsed route_path segment(s) contains.  It might not be
                # there (no route_path at all; no routing encapsulation, etc. MicroLogix simple
                # request), it may containing a single route_path element(s) (which we will test,
                # below).  However, if it contains A) at least 1 route_path element, and B) this
                # element matches one of our self.route entries, then we'll establish/use a
                # connection to the target EtherNet/IP CIP host, and transmit the request (minus the
                # matching layer of the route_path) to the target.
                route_path	= unc_send.get( 'route_path.segment' )

                def find_route():
                    if self.route and route_path and "port" in route_path[0] and "link" in route_path[0]:
                        pl	= "{port}/{link}".format( **route_path[0] )
                        return pl,self.route.get( pl ) # "1/2",None or "1/2",("hostname",44818)
                    return None,None
                portlink,target	= find_route()
                if portlink and target:
                    # port/link --> target found: Remote request.  Get the request timeout from the
                    # unconnected_send.priority/timeout_ticks.  As per Vol 1.3-4.4.1.4, the top 4
                    # bits (reserved, priorty) shall be 0, and the low 4 bits is the tick value N,
                    # in milliseconds == 2^N.
                    timeoutms	= ( 1 << unc_send.priority ) * unc_send.timeout_ticks
                    timeout	= timeoutms / 1000.0
                    data.enip.status = 0x65
                    try:
                        if target not in self.route_conn:
                            log.normal( "UCMM: port/link %s --> %r; creating route", portlink, target )
                            self.route_conn[target] \
                               	= client.connector( host=target[0], port=target[1], timeout=timeout )
                        with self.route_conn[target] as conn:
                            # Trim route_path; if empty, send with no route_path (Simple; no routing
                            # encapsulation).  Otherwise, send with remaining route_path.
                            sub_rp	= route_path[1:] or []
                            sub_sp	= unc_send.path.segment if sub_rp else ''
                            if log.isEnabledFor( logging.DETAIL ):
                                log.detail( "%r Route %s --> %s Request (RP: %s, SP: %s) %s", self, portlink,
                                            self.route_conn[target], sub_rp, sub_sp,
                                            parser.enip_format( unc_send.request ) if log.isEnabledFor( logging.INFO ) else "" )
                            conn.unconnected_send( request=unc_send.request,
                                route_path=sub_rp, send_path=sub_sp, timeout=timeout,
                                sender_context=data.enip.sender_context.input )
                            rsp,ela	= client.await_response( conn, timeout=timeout )
                            assert rsp, \
                                "No response from %s --> %s:%s within %sms timeout" % (
                                    portlink, target[0], target[1], timeoutms )
                            assert rsp.enip.status == 0, \
                                "Error status %s in EtherNet/IP Response from Route %s --> %s" % (
                                    rsp.enip.status, portlink, self.route_conn[target] )
                            # Return the unconnected_send response from the client, as our own.
                            if log.isEnabledFor( logging.DETAIL ):
                                log.detail( "%r Route %s --> %s Response %s", self, portlink,
                                            self.route_conn[target],
                                            parser.enip_format( rsp ) if log.isEnabledFor( logging.INFO ) else "" )
                            unc_send	= rsp.enip.CIP.send_data.CPF.item[1].unconnected_send
                    except Exception as exc:
                        # Failure
                        log.normal( "UCMM: port/link %s --> %r; closing route due to: %s", portlink, target, exc )
                        del self.route_conn[target] # will close()
                        raise
                    else:
                        # Successful
                        data.enip.status = 0
                else:
                    # No route_path, or port/link not in self.route.  Local request.

                    # Make sure the route_path matches what we've been configured w/; the supplied
                    # route_path.segment list must match the configured self.route_path, eg:
                    # {'link': 0, 'port': 1}.  Thus, if a non-empty route_path is supplied in
                    # Unconnected Send request, it will not match any differing configured
                    # route_path.  Also, if we've specified a Falsey (eg. 0, False) UCMM object
                    # .route_path, we'll only accept requests with an empty route_path. However: any
                    # "Simple" (non route_path encapsulated) request will be allowed by any device
                    # (self.route_path configured or not).
                    if self.route_path is not None: # may be [{"port"}...]}, or 0/False
                        assert ( not route_path			# Request has no route_path (Simple Request); its to some Object known to this simulator
                                 or ( not self.route_path	# Our specified route_path is Falsey (Simple Device)
                                      and route_path is None )	#   and the incoming request had not route_path
                                 or route_path == self.route_path # Or they match
                        ),  "Unconnected Send route path %r differs from configured: %r" % (
                                route_path, self.route_path )

                    # If the standard Connection Manager isn't addressed, that's strange but, OK...
                    ids		= (0x06, 1) # Connection Manager default address
                    if 'path' in unc_send:
                        ids	= device.resolve( unc_send.path )
                        if ( ids[0] != 0x06 or ids[1] != 1 ):
                            log.warning( "Unconnected Send targeted Object other than Connection Manager: 0x%04x/%d", ids[0], ids[1] )
                    CM		= device.lookup( class_id=ids[0], instance_id=ids[1] )
                    CM.request( unc_send )
                    
                # After successful processing of the Unconnected Send on the target node, we
                # eliminate the Unconnected Send wrapper (the unconnected_send.service = 0x52,
                # route_path, etc, by eliminating the route_path, send_path, priority, etc.), and
                # replace it with a simple encapsulated raw request.input.  We do that by emptying
                # out the unconnected_send, except for the bare request.  Basically, all the
                # Unconnected Send encapsulation and routing is used to deliver the request to the
                # target Object, and then is discarded and the EtherNet/IP envelope is simply
                # returned directly to the originator carrying the response payload.
                if log.isEnabledFor( logging.DEBUG ):
                    log.debug( "%s Repackaged: %s", self, parser.enip_format( data ))
                
                data.enip.CIP.send_data.CPF.item[1].unconnected_send  = dotdict()
                data.enip.CIP.send_data.CPF.item[1].unconnected_send.request = unc_send.request
                
                # And finally, re-encapsulate the CIP SendRRData, with its (now unwrapped)
                # Unconnected Send request response payload.
                if log.isEnabledFor( logging.DEBUG ):
                    log.debug( "%s Regenerating: %s", self, parser.enip_format( data ))
                data.enip.input	= bytearray( self.parser.produce( data.enip ))
            else:
                # See if we can identify the method to invoke based on the contents of the CIP
                # request.  The data.enip.CIP better have a single dict key (its probably a
                # dotdict, derived from dict; we want to get just one layer of keys...).
                if log.isEnabledFor( logging.DEBUG ):
                    log.debug( "%s CIP Request: %s", self, parser.enip_format( data ))
                cip		= data.get( 'enip.CIP' )
                assert isinstance( cip, dict ) and len( cip ) == 1, "Indeterminate CIP request: %r" % ( cip )
                key		= next( iter( dict.keys( cip )))
                method		= getattr( self, key, None )
                assert method, "CIP request %r unsupported: %r" % ( key, cip )

                # Finally, use the method to process the request data
                proceed		= method( data )

        except Exception as exc:
            # On Exception, if we haven't specified a more detailed error code, return Service not
            # supported.
            log.normal( "%r Command 0x%04x %s failed with Exception: %s\nRequest: %s\n%s", self,
                         data.enip.command if 'enip.command' in data else 0,
                         ( self.command[data.enip.command]
                           if 'enip.command' in data and data.enip.command in self.command
                           else "(Unknown)"), exc, parser.enip_format( data ),
                         ''.join( traceback.format_exception( *sys.exc_info() )))
            if 'enip.status' not in data or data.enip.status == 0x00:
                data['enip.status']= 0x08 # Service not supported

        # The enip.input EtherNet/IP encapsulation is assumed to have been filled in.  Otherwise, no
        # encapsulated response is expected.
        if log.isEnabledFor( logging.INFO ):
            log.info( "%s Response: %s", self, parser.enip_format( data ))
        return proceed

    def list_interfaces( self, data ):
        """List Interfaces returns zero encapsulated CPF items."""
        cpf			= data.enip.CIP.list_interfaces.CPF
        cpf.count		= 0 # sufficient to produce a CPF encapsulation with zero entries

        data.enip.input		= bytearray( self.parser.produce( data.enip ))

        return True

    LISTSVCS_CIP_ENCAP		= 1 << 5
    LISTSVCS_CIP_UDP		= 1 << 8 # Transport Class 0 or 1 packets (no encapsulation header)
    def list_services( self, data ):
        """List Services returns a communications_service CPF item.  We support CIP encapsulation, but do
        not support unencapsulated UDP data.

        """
        cpf			= data.enip.CIP.list_services.CPF
        cpf.item		= [ dotdict() ]
        cpf.item[0].type_id	= 0x0100
        cpf.item[0].communications_service \
			= c_s	= dotdict()
        c_s.version		= 1
        c_s.capability		= self.LISTSVCS_CIP_ENCAP
        c_s.service_name	= 'Communications'

        data.enip.input		= bytearray( self.parser.produce( data.enip ))

        return True

    def list_identity( self, data ):
        """The List Identity response consists of the IP address we're bound to from the TCP/IP Object,
        plus some Attribute data from the Identity object.  Look up these Objects at their
        traditional CIP Class and Instance numbers; if they exist, use their values to populate the
        response.  Then, produce the wire-protocol EtherNet/IP response message.

        We'll get each Attribute to produce its serialized representation, and then parse itself, in
        order to satisfy any default values, and produce any complex structs (eg. IPADDR,
        IFACEADDRS).  From this, we can extract the values we wish to return.

        """
        cpf			= data.enip.CIP.list_identity.CPF
        cpf.item		= [ dotdict() ]
        cpf.item[0].type_id	= 0x000C
        cpf.item[0].identity_object \
			= ido	= dotdict()
        ido.version		= 1

        for nam,dfl,ids,get in [
                ( 'sin_addr',		'127.0.0.1',	( device.TCPIP.class_id, 1, 5 ),	lambda d: d.IFACEADDRS.ip_address ),
                ( 'sin_family',		2,		None,					None ),
                ( 'sin_port',		44818, 		None,					None),
                ( 'vendor_id',		0,		( device.Identity.class_id, 1, 1 ),	lambda d: d.INT ),
                ( 'device_type',	0,		( device.Identity.class_id, 1, 2 ),	lambda d: d.INT ),
                ( 'product_code',	0,		( device.Identity.class_id, 1, 3 ),	lambda d: d.INT ),
                ( 'product_revision',	0,		( device.Identity.class_id, 1, 4 ),	lambda d: d.INT ),
                ( 'status_word',	0,		( device.Identity.class_id, 1, 5 ),	lambda d: d.WORD ),
                ( 'serial_number',	0,		( device.Identity.class_id, 1, 6 ),	lambda d: d.UDINT ),
                ( 'product_name',	0,		( device.Identity.class_id, 1, 7 ),	lambda d: d.SSTRING ),
                ( 'state',		0xff,		( device.Identity.class_id, 1, 8 ),	lambda d: d.USINT ),
        ]:
            val			= dfl
            if ids:
                att		= device.lookup( *ids )
                if att:
                    raw		= att.produce( 0, 1 )
                    val		= dotdict()
                    with att.parser as mch:
                        with contextlib.closing( mch.run( source=raw, data=val )) as eng:
                            for m,s in eng:
                                pass
                            log.info( "Parsed using %r; %r from %r", mch, val, raw )
                    if get:
                        val	= get( val )
            ido[nam]		= val

        data.enip.input		= bytearray( self.parser.produce( data.enip ))

        return True

    def legacy( self, data ):
        """A subset of undocumented EtherNet/IP CIP "Legacy" commands are supported."""
        if data.enip.command == 0x0001:
            # A command which seems to return network information similar to List Interfaces
            return self._legacy_0x0001( data )
        else:
            raise AssertionError( "Unimplemented EtherNet/IP CIP Legacy command: %r" % ( data ))

    def _legacy_0x0001( self, data ):
        cpf			= data.enip.CIP.legacy.CPF
        cpf.item		= [ dotdict() ]
        cpf.item[0].type_id	= 0x0001
        cpf.item[0].legacy_CPF_0x0001 \
                        = leg   = dotdict()

        for nam,dfl,ids,get in [
                ( 'sin_addr',		'127.0.0.1',	( device.TCPIP.class_id, 1, 5 ),	lambda d: d.IFACEADDRS.ip_address ),
                ( 'sin_family',		2,		None,					None ),
                ( 'sin_port',		44818, 		None,					None),
        ]:
            val			= dfl
            if ids:
                att		= device.lookup( *ids )
                if att:
                    raw		= att.produce( 0, 1 )
                    val		= dotdict()
                    with att.parser as mch:
                        with contextlib.closing( mch.run( source=raw, data=val )) as eng:
                            for m,s in eng:
                                pass
                            log.info( "Parsed using %r; %r from %r", mch, val, raw )
                    if get:
                        val	= get( val )
            leg[nam]		= val

        data.enip.input		= bytearray( self.parser.produce( data.enip ))

        return True

