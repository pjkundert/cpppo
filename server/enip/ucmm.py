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

__all__				= [ 'UCMM' ]

"""enip.ucmm -- Un-Connected Message Manager"""

import random
import contextlib
import logging
import sys
import threading
import traceback

from ...dotdict import dotdict
from . import parser, device

log				= logging.getLogger( "enip.ucmm" )


class UCMM( device.Object ):
    """Un-Connected Message Manager, handling Register/Unregister of connections, and sending
    Unconnected Send messages to either directly to a local object, or to the local Connection
    Manager for parsing/processing.


    Forwards encapsulated messages to their destination port and link address, and returns the
    encapsulated response.  The Unconnected Send message contains an encapsulated message and a
    route path with 1 or more route segment groups.  If more than 1 group remains, the first group
    is removed, and the address is used to establish a connection and send the message on; the
    response is received and returned.

    When only the final route path segment remains, the encapsulated message is sent to the local
    Message Router, and its response is received and returned.

    Presently, we only respond to Unconnected Send messages with one route path segment; a local
    port/link address.

    """

    class_id			= 0x9999	# Not an addressable Object
    route_path			= None		# Specify, if we want to reject invalid ones

    parser			= parser.CIP()
    command			= {
        0x0065: "Register Session",
        0x0066: "Unregister Session",
        0x006f: "SendRRData",
    }
    lock			= threading.Lock()
    sessions			= {}		# All known session handles, by addr

    def request( self, data, addr=None ):
        """Handles a parsed enip.* request, and converts it into an appropriate response.  For
        connection related requests (Register, Unregister), handle locally.  Return True iff request
        processed and connection should proceed to process further messages.

        """
        if log.isEnabledFor( logging.INFO ):
            log.info( "%r Request: %s", self, parser.enip_format( data ))

        proceed			= True

        assert addr is not None, "Connection Manager requires client address"
        if not data:
            # Termination signal. Give the Connection_Manager an opportunity to clean up,
            # eg. close all Forward Open data associated with the TCP/IP session.
            CM			= device.lookup( class_id=0x06, instance_id=1 ) # Connection Manager default address
            CM.request( data, addr=addr ) # just the 2-segment addr, not including any T_O_connection_ID
            return

        # A non-empty request. Each EtherNet/IP enip.command expects an appropriate encapsulated response
        if 'enip' in data:
            data.enip.pop( 'input', None )
        try:
            if 'enip.CIP.register' in data:
                # Allocates a new session_handle, and returns the register.protocol_version and
                # .options_flags unchanged (if supported)

                with self.lock:
                    session	= random.randint( 0, 2**32-1 )
                    while not session or session in self.__class__.sessions:
                        session	= random.randint( 0, 2**32-1 )
                    self.__class__.sessions[addr] = session
                data.enip.session_handle = session
                log.detail( "EtherNet/IP (Client %r) Session Established: %r", addr, session )
                data.enip.input	= bytearray( self.parser.produce( data.enip ))
                data.enip.status= 0x00

            elif 'enip.CIP.unregister' in data or 'enip' not in data:
                # Session being closed.  There is no response for this command; return False
                # inhibits any EtherNet/IP response from being generated, and closes connection.
                with self.lock:
                    session	= self.__class__.sessions.pop( addr, None )
                log.detail( "EtherNet/IP (Client %r) Session Terminated: %r", addr,
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
                # TODO: Connected (Implicit) sessions have a Forward Open connection_ID in CPF.item[0]
                assert 'enip.CIP.send_data.CPF' in data \
                    and data.enip.CIP.send_data.CPF.count == 2, \
                    "EtherNet/IP CIP CPF encapsulation required"
                if data.enip.CIP.send_data.CPF.item[0].length == 0:
                    # Unconnected session
                    unc_send	= data.enip.CIP.send_data.CPF.item[1].unconnected_send

                    # Make sure the route_path matches what we've been configured w/; the supplied
                    # route_path.segment list must match the configured self.route_path, eg: {'link': 0,
                    # 'port': 1}.  Thus, if an empty route_path supplied in Unconnected Send request, it
                    # will not match any configured route_path.  Also, if we've specified a Falsey
                    # (eg. 0, False) UCMM object .route_path, we'll only accept requests with an empty
                    # route_path.
                    if self.route_path is not None: # may be [{"port"}...]}, or 0/False
                        route_path = unc_send.get( 'route_path.segment' )
                        assert ( not self.route_path and not route_path # both Falsey, or match
                                 or route_path == self.route_path ), \
                            "Unconnected Send route path %r differs from configured: %r" % (
                                route_path, self.route_path )

                    # If the standard Connection Manager isn't addressed, that's strange but, OK...
                    ids		= (0x06, 1) # Connection Manager default address
                    if 'path' in unc_send:
                        ids		= device.resolve( unc_send.path )
                        if ( ids[0] != 0x06 or ids[1] != 1 ):
                            log.warning( "Unconnected Send targeted Object other than Connection Manager: 0x%04x/%d", ids[0], ids[1] )
                    CM		= device.lookup( class_id=ids[0], instance_id=ids[1] )
                    CM.request( unc_send, addr=addr )

                    # After successful processing of the Unconnected Send on the target node, we
                    # eliminate the Unconnected Send wrapper (the unconnected_send.service = 0x52,
                    # route_path, etc), and replace it with a simple encapsulated raw request.input.  We
                    # do that by emptying out the unconnected_send, except for the bare request.
                    # Basically, all the Unconnected Send encapsulation and routing is used to deliver
                    # the request to the target Object, and then is discarded and the EtherNet/IP
                    # envelope is simply returned directly to the originator carrying the response
                    # payload.
                    if log.isEnabledFor( logging.DEBUG ):
                        log.debug( "%s Repackaged: %s", self, parser.enip_format( data ))

                    data.enip.CIP.send_data.CPF.item[1].unconnected_send  = dotdict()
                    data.enip.CIP.send_data.CPF.item[1].unconnected_send.request = unc_send.request
                else:
                    # Connected session; extract connection_data.request.input payload
                    con_id	= data.enip.CIP.send_data.CPF.item[0].connection_ID.connection
                    con_data	= data.enip.CIP.send_data.CPF.item[1].connection_data
                    CM		= device.lookup( class_id=0x06, instance_id=1 ) # Connection Manager default address
                    CM.request( con_data, addr=(addr[0],addr[1],con_id) ) # Converts request to reply

                # And finally, re-encapsulate the CIP SendRRData/SendUnitData, with its (now
                # unwrapped) Unconnected Send / Connection Data request response payload.
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
            pass


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
