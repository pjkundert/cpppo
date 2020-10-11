
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


"""
enip.logix	-- Implements a Logix-like PLC subset

"""

import json
import logging
import sys
import threading
import traceback

from ...dotdict import dotdict
from ... import automata, misc
from .device import ( Object, Attribute,
                      Message_Router, Connection_Manager, Identity, TCPIP, Logical_Segments,
                      resolve_element, resolve_tag, resolve, redirect_tag, lookup )
from . import ucmm
from .parser import ( BOOL, UDINT, DINT, UINT, INT, USINT, SINT, REAL, EPATH, typed_data,
                      move_if, octets_drop, octets_noop, enip_format, status )

log				= logging.getLogger( "enip.lgx" )

# Unknown Object, Class 102, Instance 1.  This Object is unknown, but it returns data equivalent to
# the following Attributes, when queried.
# Request:
#     # pkt8
#     # "8","0.153249000","192.168.222.128","10.220.104.180","CIP","100","Get Attribute All"
#     gaa_008_request 		= bytes(bytearray([
#                                             0x6f, 0x00, #/* 9.w...o. */
#         0x16, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0xb2, 0x00, 0x06, 0x00, 0x01, 0x02, #/* ........ */
#         0x20, 0x66, 0x24, 0x01                          #/*  f$. */
#     ]))
# 
#     Parsed:
#     {
#         "enip.CIP.send_data.CPF.count": 2, 
#         "enip.CIP.send_data.CPF.item[0].length": 0, 
#         "enip.CIP.send_data.CPF.item[0].type_id": 0, 
#         "enip.CIP.send_data.CPF.item[1].length": 6, 
#         "enip.CIP.send_data.CPF.item[1].type_id": 178, 
#         "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 102, 
#         "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
#         "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
#         "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 1, 
#         "enip.CIP.send_data.interface": 0, 
#         "enip.CIP.send_data.timeout": 5, 
#         "enip.command": 111, 
#         "enip.length": 22, 
#         "enip.options": 0, 
#         "enip.session_handle": 285351425, 
#         "enip.status": 0,
#     }
# 
# Response:
#     # pkt10
#     # "10","0.247332000","10.220.104.180","192.168.222.128","CIP","116","Success"
#     gaa_008_reply 		= bytes(bytearray([
#                                             0x6f, 0x00, #/* ..T...o. */
#         0x26, 0x00, 0x01, 0x1e, 0x02, 0x11, 0x00, 0x00, #/* &....... */
#         0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, #/* ........ */
#         0x00, 0x00, 0xb2, 0x00, 0x16, 0x00, 0x81,
# 
#                                                   0x00, #/* ........ */
# >       0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, #/* ........ */
# >       0x2d, 0x00, 0x01, 0x00, 0x01, 0x01, 0xb1, 0x2a, #/* -......* */
# >       0x1b, 0x00, 0x0a, 0x00                          #/* .... */
#     ]))
class Unknown_Object( Object ):
    class_id			= 0x66 # 102

    def __init__( self, name=None, **kwds ):
        super( Unknown_Object, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes (these example defaults are from a Rockwell Logix PLC)
            self.attribute['1']	= Attribute( 'Unknown 1', 		UDINT, default=0x00000000 )
            self.attribute['2']	= Attribute( 'Unknown 2', 		UDINT, default=0x00000008 )
            self.attribute['3']	= Attribute( 'Unknown 3', 		USINT, default=0x00 )
            self.attribute['4']	= Attribute( 'Unknown 4', 		UINT,  default=0x002d )
            self.attribute['5']	= Attribute( 'Unknown 5', 		UINT,  default=0x0001 )
            self.attribute['6']	= Attribute( 'Unknown 6', 		USINT, default=0x01 )
            self.attribute['7']	= Attribute( 'Unknown 7', 		USINT, default=0x01 )
            self.attribute['8']	= Attribute( 'Unknown 8', 		USINT, default=0x01 )
            self.attribute['9']	= Attribute( 'Unknown 9', 		USINT, default=0xb1 )
            self.attribute['10']= Attribute( 'Unknown 10', 		USINT, default=0x2a )
            self.attribute['11']= Attribute( 'Unknown 11', 		UINT,  default=0x001b )
            self.attribute['12']= Attribute( 'Unknown 12', 		UINT,  default=0x000a )


class Logix( Message_Router ):
    """A Logix Controller implementation of the CIP Message Router (Class 0x02, Instance 1).  This
    object is targeted by the Connection Manager, to parse and process incoming requests.  

    The target Object of the command may not be an Instance of this Object; however, for the
    Logix-specific commands (eg. Read/Write Tag [Fragmented]), it should be (or it won't be able to
    process the request or produce the reply).

    """

    # TODO: MAX_BYTES is arbitrary.  We're supposed to be able to return data sufficient to fill the
    # remaining reply package size, but how can we do that?  We'd have to be informed of the
    # remaining packet size available, as an argument to the produce method...
    MAX_BYTES			= 500

    RD_TAG_NAM			= "Read Tag"
    RD_TAG_CTX			= "read_tag"
    RD_TAG_REQ			= 0x4c
    RD_TAG_RPY			= RD_TAG_REQ | 0x80
    RD_FRG_NAM			= "Read Tag Fragmented"
    RD_FRG_CTX			= "read_frag"
    RD_FRG_REQ			= 0x52
    RD_FRG_RPY			= RD_FRG_REQ | 0x80
    WR_TAG_NAM			= "Write Tag"
    WR_TAG_CTX			= "write_tag"
    WR_TAG_REQ			= 0x4d
    WR_TAG_RPY			= WR_TAG_REQ | 0x80
    WR_FRG_NAM			= "Write Tag Fragmented"
    WR_FRG_CTX			= "write_frag"
    WR_FRG_REQ			= 0x53
    WR_FRG_RPY			= WR_FRG_REQ | 0x80

    def reply_elements( self, attribute, data, context ):
        """Given an attribute, a data.service specifying a Read/Write Tag [Fragmented] reply, a
        data.path (perhaps containing an element offset) and a data.<context>.elements (optional)
        count to read and (optional) data.<context>.offset byte offset into the result to begin
        returning data after, compute the attribute elements to (begin,end] the result.
    
        Find the actual beginning/ending element, and check data.read_{t,fr}ag.data.  For example,
        we could read 1000 elements starting at element 30, then starting at requested offset of 900
        (bytes); assuming a maximum element capacity of 150, the actual beginning element would be
        30 + 450 == 480, and the ending element would be 480 + 150 == 630 (the element beyond ).
    
        Ensure we reduce the requested elements count as we advance due to byte offset.
    
        Basically, the number of bytes returned using this service is calculated by taking the
        Number of elements to read and subtracting the byte offset. As an example I am going to
        request elements 0-29 and 40-69 from an array of 16 bit integers.
    
        To request elements 0-29 the offset starts at 0 and the number of elements to read is 30.
        To request elements 40-69 the offset starts at 80 and the number of elements to read is 70
        (the offset is 80 because we are doing 2 byte data types).
    
        *Logix internally determines the correct number of elements to return by subtracting the
        offset from the number of elements requested.

        """
        assert data.service in (self.RD_TAG_RPY,self.RD_FRG_RPY,self.WR_TAG_RPY,self.WR_FRG_RPY), \
            "Unable to calculate element range for unknown service: %d" % ( data.service )
        index			= resolve_element( data.path )	
        assert type( index ) is tuple and len( index ) == 1, \
            "Unsupported/Multi-dimensional index: %s" % index
        siz			= attribute.parser.struct_calcsize
        off			= 0
        if data.service in (self.RD_FRG_RPY, self.WR_FRG_RPY):
            off			= data[context].get( 'offset' ) or 0 # nonexistent/None/0 --> 0
        assert siz and off % siz == 0, \
            "Requested byte offset %d is not on a %d-byte data element boundary" % ( off, siz )

        # Compute the extents of the full reply, given no byte offset, unlimited reply size and
        # complete data.  If no 'elements' has been provided (only possible when hand-forming a
        # request, not via EtherNet/IP CIP protocol), default to all Attribute elements (after
        # element indexed).
        beg			= index[0]
        cnt			= len( attribute )
        elm			= data[context].get( 'elements', cnt - beg ) # Read/Write Tag defaults to all
        endactual		= beg + elm
        assert 0 < endactual <= cnt, \
            "Attribute %s ending element invalid: %r" % ( attribute, (beg, endactual) )

        # Maximum elements for read is the capacity of the reply message, for write is the number
        # actually provided in request.  Compute this from the beginning element deduced from the
        # byte offset of this request.  This will reduce the scope of the reply by A) advancing
        # 'beg' by a byte offset, and/or B) reducing 'end' due to reply size limitations or
        # an incomplete number of data elements provided.  The 'end' can only get smaller
        # than the (known valid) 'endactual'.
        beg		       += off // siz
        if data.service in (self.RD_TAG_RPY, self.RD_FRG_RPY):
            endmax 		= beg + self.MAX_BYTES // siz
        else:
            endmax		= beg + len( data[context].data )
            assert endmax <= endactual, \
                "Attribute %s capacity exceeded; writing %d elements beginning at index %d" % (
                    attribute, len( data[context].data ), beg )
        end			= min( endactual, endmax )
        assert 0 <= beg < cnt, \
            "Attribute %s initial element invalid: %r" % ( attribute, (beg, end) )
        assert beg < end, \
            "Attribute %s ending element before beginning: %r" % ( attribute, (beg, end) )
        return (beg,end,endactual)

    def request( self, data, addr=None ):
        """Any exception should result in a reply being generated with a non-zero status."""

        # See if this request is for us; if not, route to the correct Object, and return its result.
        # If the resolution/lookup fails (eg. bad symbolic Tag); ignore it (return False on error)
        # and continue processing, so we can return a proper .status error code from the actual
        # request, below.
        target			= self.route( data, fail=Message_Router.ROUTE_FALSE )
        if target:
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Routing to %s: %s", self, target, enip_format( data ))
            return target.request( data, addr=addr )

        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Request: %s", self, enip_format( data ))
        # This request is for this Object.
        
        # Pick out our services added at this level.  If not recognized, let superclass try; it'll
        # return an appropriate error code if not recognized.
        if ( data.get( 'service' ) == self.RD_TAG_REQ
             or 'read_tag' in data and data.setdefault( 'service', self.RD_TAG_REQ ) == self.RD_TAG_REQ ):
            # Read Tag --> Read Tag Reply.
            pass
        elif ( data.get( 'service' ) == self.RD_FRG_REQ
               or 'read_frag' in data and data.setdefault( 'service', self.RD_FRG_REQ ) == self.RD_FRG_REQ ):
            # Read Tag Fragmented --> Read Tag Fragmented Reply.
            pass
        elif ( data.get( 'service' ) == self.WR_TAG_REQ
             or 'write_tag' in data and data.setdefault( 'service', self.WR_TAG_REQ ) == self.WR_TAG_REQ ):
            # Write Tag --> Write Tag Reply.
            pass
        elif ( data.get( 'service' ) == self.WR_FRG_REQ
               or 'write_frag' in data and data.setdefault( 'service', self.WR_FRG_REQ ) == self.WR_FRG_REQ ):
            # Write Tag Fragmented --> Write Tag Fragmented Reply.
            pass
        else:
            # Not recognized; more generic command?
            return super( Logix, self ).request( data, addr=addr )

        # It is a recognized request.  Set the data.status to the appropriate error code, should a
        # failure occur at that location during processing.  We will be returning a reply beyond
        # this point; any exceptions generated will be captured, logged and an appropriate reply
        # .status error code returned.  

        # For Reads:
        # Error Code	Extended Error	Description of Error
        # 0x04		0x0000 		A syntax error was detected decoding the Request Path.
        # 0x05		0x0000		Request Path destination unknown: Probably instance number is not present.
        # 0x06		N/A		Insufficient Packet Space: Not enough room in the response buffer for all the data.
        # 0x13		N/A		Insufficient Request Data: Data too short for expected parameters.
        # 0x26		N/A 		The Request Path Size received was shorter or longer than expected.
        # 0xFF		0x2105 		General Error: Access beyond end of the object.

        # For Writes:
        # 0x04		0x0000		A syntax error was detected decoding the Request Path.
        # 0x05		0x0000		Request Path destination unknown: Probably instance number is not present.
        # 0x10		0x2101		Device state conflict: keyswitch position: The requestor is attempting to change force information in HARD RUN mode.
        # 0x10		0x2802		Device state conflict: Safety Status: The controller is in a state in which Safety Memory cannot be modified.
        # 0x13		N/A		Insufficient Request Data: Data too short for expected parameters.
        # 0x26		N/A		The Request Path Size received was shorter or longer than expected.
        # 0xFF		0x2104		General Error: Offset is beyond end of the requested tag (fragmented only)
        # 0xFF		0x2105		General Error: Number of Elements extends beyond the end of the requested tag.
        # 0xFF		0x2107		General Error: Tag type used n request does not match the target tag's data type.

        data.service           |= 0x80
        try:
            # We need to find the attribute for all requests, and it better be ours!
            data.status		= 0x05 # On Failure: Request Path destination unknown
            data.status_ext	= {'size': 1, 'data':[0x0000]}
            clid, inid, atid	= resolve( data.path, attribute=True )
            attribute		= lookup( clid, inid, atid )
            assert clid == self.class_id and inid == self.instance_id, \
                "Path %r processed by wrong Object %r" % ( data.path['segment'], self )
            assert attribute is not None, \
                "Path %r did not identify attribute in %r" % ( data.path['segment'], self )
            assert attribute.parser.tag_type, \
                "Invalid EtherNet/IP type %s for %s; must have a non-zero type ID" % (
                    attribute.parser.__class__.__name__, self.service[data.service] )

            if data.service in (self.RD_TAG_RPY, self.RD_FRG_RPY):
                # Read Tag [Fragmented] Reply.  Fill in .data and .type 
                context		= 'read_frag' if data.service == self.RD_FRG_RPY else 'read_tag'
                data[context].type= attribute.parser.tag_type
            elif data.service in (self.WR_TAG_RPY, self.WR_FRG_RPY):
                # Write Tag [Fragmented] Reply.  We'll allow data payloads of more restricted signed
                # types into Attributes of a more spacious signed type (eg. writing SINT values into
                # INT, or REAL Attribute).  Otherwise, the data types must match exactly.
                context		= 'write_frag'	 if data.service == self.WR_FRG_RPY else 'write_tag'
                data.status	= 0xFF
                data.status_ext= {'size': 1, 'data':[0x2107]}
                allowed_tag_types = {
                    BOOL.tag_type:      (BOOL.tag_type,),
                    REAL.tag_type:	(BOOL.tag_type,
                                         SINT.tag_type, USINT.tag_type,
                                          INT.tag_type,  UINT.tag_type,
                                         DINT.tag_type, UDINT.tag_type,
                                         REAL.tag_type),
                    DINT.tag_type:	(BOOL.tag_type,
                                         SINT.tag_type, USINT.tag_type,
                                          INT.tag_type,  UINT.tag_type,
                                         DINT.tag_type, UDINT.tag_type),
                    INT.tag_type:	(BOOL.tag_type,
                                         SINT.tag_type, USINT.tag_type,
                                         INT.tag_type,   UINT.tag_type),
                    SINT.tag_type:	(BOOL.tag_type,
                                         SINT.tag_type, USINT.tag_type),
                }
                assert data[context].type in allowed_tag_types.get(
                    attribute.parser.tag_type, (attribute.parser.tag_type,) ), \
                    "Tag type %d in request doesn't fit within Attribute type %d" % ( 
                        data[context].type, attribute.parser.tag_type )
            else:
                raise AssertionError( "Unhandled Service Reply" )

            data.status		= 0xFF # On Failure: General Error
            data.status_ext	= {'size': 1, 'data': [ 0x2105 ]} # Number of elements beyond end of tag

            # Compute (beg,end] for this reply, given data.path...element, data.elements/offset.
            # The end element of the full request (not the size/data-limited end) is in endactual
            beg,end,endactual	= self.reply_elements( attribute, data, context )
            log.debug( "Replying w/ elements [%3d-%-3d/%3d] for %r", beg, end, endactual, data )
            if data.service in (self.RD_TAG_RPY, self.RD_FRG_RPY):
                # Read Tag [Fragmented]
                data[context].data	= attribute[beg:end]
                log.detail( "%s Reading %3d elements %3d-%3d from %s: %s",
                            self, end - beg, beg, end-1, attribute, data[context].data )
                # Final .status is 0x00 if all requested elements were shipped; 0x06 if not
                data.status		= 0x00 if end == endactual else 0x06
                data.pop( 'status_ext' ) # non-empty dotdict level; use pop instead of del
            else:
                # Write Tag [Fragmented].  We know the type is right.
                log.detail( "%s Writing %3d elements %3d-%3d into %s: %r",
                            self, end - beg, beg, end-1, attribute, data[context].data )
                attribute[beg:end]	= data[context].data
                data.status		= 0x00
                data.pop( 'status_ext' )

            # Successful completion; return any desired error code (normally should be 0)
            if attribute.error:
                data.status		= attribute.error
                raise AssertionError( "Forced failure due to configured Attribute error code %r" % attribute.error )

        except Exception as exc:
            # On Exception, if we haven't specified a more detailed error code, return General
            # Error.  Remember: 0x06 (Insufficent Packet Space) is a NORMAL response to a successful
            # Read Tag Fragmented that returns a subset of the requested data.
            log.normal( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s", self,
                         data.service if 'service' in data else 0,
                         ( self.service[data.service]
                           if 'service' in data and data.service in self.service
                           else "(Unknown)"), exc, enip_format( data ),
                         ( '' if log.getEffectiveLevel() >= logging.NORMAL
                           else ''.join( traceback.format_exception( *sys.exc_info() ))))
            assert data.status not in (0x00, 0x06), \
                "Implementation error: must specify .status not in (0x00, 0x06) before raising Exception!"
            pass

        # Always produce a response payload; if a failure occurred, will contain an error status
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Response: Service 0x%02x %s %s", self,
                        data.service if 'service' in data else 0,
                        ( self.service[data.service]
                          if 'service' in data and data.service in self.service
                          else "(Unknown)"), enip_format( data ))
        data.input		= bytearray( self.produce( data ))
        return True

    @classmethod
    def produce( cls, data ):
        """Expects to find .service and/or .<logix-command>, and produces the request/reply encoded to
        bytes.  Defaults to produce the request, if no .service specified, and just
        .read/write_tag/frag found.
         
        A .status of 0x06 in the read_tag/frag reply indicates that more data is available; it is
        not a failure.

        """
        result			= b''
        if ( data.get( 'service' ) == cls.RD_TAG_REQ
             or 'read_tag' in data and data.setdefault( 'service', cls.RD_TAG_REQ ) == cls.RD_TAG_REQ ):
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.read_tag.elements )
        elif ( data.get( 'service' ) == cls.RD_FRG_REQ
               or 'read_frag' in data and data.setdefault( 'service', cls.RD_FRG_REQ ) == cls.RD_FRG_REQ ):
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.read_frag.elements )
            result	       += UDINT.produce(	data.read_frag.offset )
        elif ( data.get( 'service' ) == cls.WR_TAG_REQ
               or 'write_tag' in data and data.setdefault( 'service', cls.WR_TAG_REQ ) == cls.WR_TAG_REQ ):
            # We can deduce the number of elements from len( data )
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.write_tag.type )
            result	       += UINT.produce(		data.write_tag.setdefault( 
                'elements', len( data.write_tag.data )))
            result	       += typed_data.produce(	data.write_tag )
        elif ( data.get( 'service') == cls.WR_FRG_REQ
               or 'write_frag' in data and data.setdefault( 'service', cls.WR_FRG_REQ ) == cls.WR_FRG_REQ ):
            # We can NOT deduce the number of elements from len( write_frag.data );
            # write_frag.elements must be the entire number of elements being shipped, while
            # write_frag.data contains ONLY the elements being shipped in this Write Tag Fragmented
            # request!  We will default offset to 0 for you, though...
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.write_frag.type )
            result	       += UINT.produce(		data.write_frag.elements )
            result	       += UDINT.produce(	data.write_frag.setdefault(
                'offset', 0x00000000 ))
            result	       += typed_data.produce(	data.write_frag )
        elif ( data.get( 'service' ) == cls.WR_TAG_RPY
               or data.get( 'service' ) == cls.WR_FRG_RPY ):
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce(	data )
        elif data.get( 'service' ) == cls.RD_TAG_RPY:
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce(	data )
            if data.status in (0x00, 0x06):
                result	       += UINT.produce(		data.read_tag.type )
                result	       += typed_data.produce(	data.read_tag )
        elif data.get( 'service' ) == cls.RD_FRG_RPY:
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce(	data )
            if data.status in (0x00, 0x06):
                result	       += UINT.produce(		data.read_frag.type )
                result	       += typed_data.produce(	data.read_frag )
        else:
            result		= super( Logix, cls ).produce( data )
        return result


def __read_tag():
    # Read Tag Service
    srvc			= USINT(	 	  	context='service' )
    srvc[True]		= path	= EPATH(			context='path' )
    path[True]			= UINT(		'elements', 	context='read_tag',   extension='.elements',
                                        terminal=True )
    return srvc
Logix.register_service_parser( number=Logix.RD_TAG_REQ, name=Logix.RD_TAG_NAM,
                               short=Logix.RD_TAG_CTX, machine=__read_tag() )

def __read_tag_reply():
    # Read Tag Service (reply).  Remainder of symbols are typed data.
    srvc			= USINT(		 	context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= schk	= octets_noop(	'check',
                                                terminal=True )

    dtyp			= UINT( 	'type',   	context='read_tag',  extension='.type' )
    dtyp[True]			= typed_data( 	'data',   	context='read_tag',
                                        tag_type='.type',
                                        terminal=True )
    # For status 0x00 (Success) and 0x06 (Not all data returned), type/data follows.
    schk[None]			= automata.decide( 'ok',	state=dtyp,
        predicate=lambda path=None, data=None, **kwds: data[path+'.status' if path else 'status'] in (0x00, 0x06) )
    schk[None]			= move_if(	'mark',		initializer=True,
                                                destination='read_tag' )
    return srvc
Logix.register_service_parser( number=Logix.RD_TAG_RPY, name=Logix.RD_TAG_NAM + " Reply",
                               short=Logix.RD_TAG_CTX, machine=__read_tag_reply() )

def __read_frag():
    # Read Tag Fragmented Service
    srvc			= USINT(			context='service' )
    srvc[True]	= path		= EPATH(			context='path' )
    path[True]	= elem		= UINT(		'elements',	context='read_frag',  extension='.elements' )
    elem[True]			= UDINT( 	'offset',   	context='read_frag',  extension='.offset',
                                        terminal=True )
    return srvc
Logix.register_service_parser( number=Logix.RD_FRG_REQ, name=Logix.RD_FRG_NAM,
                               short=Logix.RD_FRG_CTX, machine=__read_frag() )

def __read_frag_reply():
    # Read Tag Fragmented Service (reply).  Remainder of symbols are typed data.
    # If no data returned (hence no 'read_frag' sub-dotdict), create one using a
    # move_if initializer.
    srvc			= USINT(			context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= schk	= octets_noop(	'check',
                                                terminal=True )

    dtyp			= UINT( 	'type',   	context='read_frag',  extension='.type' )
    dtyp[True]			= typed_data( 	'data',   	context='read_frag',
                                        tag_type='.type',
                                        terminal=True )
    # For status 0x00 (Success) and 0x06 (Not all data returned), type/data follows.
    schk[None]			= automata.decide( 'ok',	state=dtyp,
        predicate=lambda path=None, data=None, **kwds: data[path+'.status' if path else 'status'] in (0x00, 0x06) )
    schk[None]			= move_if(	'mark',		initializer=True,
                                                destination='read_frag' )
    return srvc
Logix.register_service_parser( number=Logix.RD_FRG_RPY, name=Logix.RD_FRG_NAM + " Reply",
                               short=Logix.RD_FRG_CTX, machine=__read_frag_reply() )

def __write_tag():
    # Write Tag Service
    srvc			= USINT(		  	context='service' )
    srvc[True]		= path	= EPATH(			context='path' )
    path[True]		= dtyp	= UINT(		'type',   	context='write_tag', extension='.type' )
    dtyp[True]		= delm	= UINT(		'elements', 	context='write_tag', extension='.elements' )
    delm[True]			= typed_data( 	'data',		context='write_tag' ,
                                        tag_type='.type',
                                        terminal=True )
    return srvc
Logix.register_service_parser( number=Logix.WR_TAG_REQ, name=Logix.WR_TAG_NAM,
                               short=Logix.WR_TAG_CTX, machine=__write_tag() )

def __write_tag_reply():
    # Write Tag Service (reply).  In order to ensure we have a '.write_tag'
    # attribute in the the reply dotdict, use a move_if w/ no source or
    # destination, just an initializer; it'll initialize an attribute at the
    # mark's context ('write_tag') to True.
    srvc			= USINT(		  	context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= mark	= octets_noop(			context='write_tag',
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )

    return srvc
Logix.register_service_parser( number=Logix.WR_TAG_RPY, name=Logix.WR_TAG_NAM + " Reply",
                               short=Logix.WR_TAG_CTX, machine=__write_tag_reply() )

def __write_frag():
    # Write Tag Fragmented Service
    srvc			= USINT(		  	context='service' )
    srvc[True]		= path	= EPATH(			context='path' )
    path[True]		= dtyp	= UINT(		'type',     	context='write_frag', extension='.type' )
    dtyp[True]		= delm	= UINT(		'elements', 	context='write_frag', extension='.elements' )
    delm[True]		= doff	= UDINT( 	'offset',   	context='write_frag', extension='.offset' )
    doff[True]			= typed_data( 	'data',  	context='write_frag',
                                        tag_type='.type',
                                        terminal=True )
    return srvc
Logix.register_service_parser( number=Logix.WR_FRG_REQ, name=Logix.WR_FRG_NAM,
                               short=Logix.WR_FRG_CTX, machine=__write_frag() )

def __write_frag_reply():
    # Write Tag Fragmented Service (reply)
    srvc			= USINT(			context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= mark	= octets_noop(			context='write_frag',
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )
    return srvc
Logix.register_service_parser( number=Logix.WR_FRG_RPY, name=Logix.WR_FRG_NAM + " Reply",
                               short=Logix.WR_FRG_CTX, machine=__write_frag_reply() )



def setup_tag( key, val ):
    """Find (or create) the Tag with the given key, and assign val.attribute or val.error to it."""
    res				= resolve_tag( key )
    new				= not res
    if new:
        # A new tag!  Allocate a new attribute ID in the Logix (Message Router) by default,
        # or at the specified path.  If a path specified, find the Object, creating it if it
        # doesn't exist.  Then, find the Attribute, ensuring it is consistent if it exists.
        cls,ins,att		= 0x02,1,None # The (Logix?) Message Router, by default
        if 'path' in val and val['path']:
            cls,ins,att	= resolve( val['path'], attribute=True )
        # See if the tag's Instance exists.  If not, we'll need to create it.  If the Class'
        # "meta" Instance exists, we'll use it to create the Instance (its always at
        # Instance 0).  Otherwise, we'll create an Object class with the appropriate
        # class_id to use.
        instance		= lookup( cls, ins )
        if instance is None:
            # Instance doesn't exist; we'll need to instantiate the right Object Class.
            class_meta		= lookup( cls )
            if class_meta:
                class_type 	= class_meta.__class__
            else:
                # Nope, no Class "meta" object.  Create class Object on-the-fly, derived
                # from our Message Router CIP Object's class.  Thus, these dynamically
                # created Objects will understand all of the esoteric *Logix (or whatever
                # Message Router's) services (eg. Read Tag [Fragmented]).
                class_type	= type( 'Class %5d/0x%04X' % ( cls, cls ),
                                  ( lookup( 0x02, 0 ).__class__,),
                                  {'class_id': cls} )
            instance		= class_type( instance_id=ins )
            log.normal( "Set Tag %-14s%-10s: %-24s Instance %3d created", key,
                        "@%s/%s/%s" % ( cls, ins, '?' if att is None else att ), instance, ins )

        # We know that the required Instance of the designated Class now exists.  Now, if
        # we've been given an tag address, see if the attribute is known; use it, if so (and
        # compatible w/ the supplied one), or use the supplied Attribute.
        attribute		= None
        if att: # not None, must be > 0
            attribute		= lookup( cls, ins, att )
            if attribute:
                # The Attribute is known.  Better be consistent w/ the required one!
                assert attribute.parser.__class__ is val.attribute.parser.__class__ \
                    and len( attribute ) == len( val.attribute ), \
                    "Incompatible Attribute types for tag %r: %s and %s" % (
                        key, attribute, val.attribute )
        else:
            # No required Attribute number assigned.  Find the next available one in the
            # Class Instance.  Start at the largest Attribute index.  Indices are stored as
            # str, so use 'natural' ordering so they end up sorted numerically.
            att			= int( sorted( instance.attribute, key=misc.natural )[-1] ) if instance.attribute else 0
            att                += 1

        if not attribute:
            # No Attribute found; either specified path but no Attribute yet at that path,
            # or no specified path. 
            attribute		= instance.attribute[str(att)] \
                                = val.attribute
        log.normal( "Set Tag %-14s%-10s: %-24s Instance Added: %s",
                    key, "@%s/%s/%s" % ( cls, ins, att ), instance, 
                    attribute if log.isEnabledFor( logging.INFO ) else misc.reprlib.repr( attribute ))

        # Finally, set tag 'key' to point to the (now existing) Class, Instance, Attribute
        redirect_tag( key, {'class': cls, 'instance': ins, 'attribute': att })
        res			= resolve_tag( key )
    assert res, "Unable to find Tag %r" % ( key )

    # Attribute (now) exists; find it, and make sure its error code is right.  If no error (or it is
    # Falsey, ie. 0), then assign any different val.attribute provided (ie. if this Attribute left
    # over from prior configuraiton), or do nothing if we've already just newly configured it above.
    attribute			= lookup( *res )
    assert attribute is not None, "Failed to find existing tag: %r" % key
    if 'error' in val and val['error']:
        if attribute.error != val['error']:
            log.warning( "Set Tag %24: Attribute %s error code changed: 0x%02x", key, attribute, val['error'] )
            attribute.error	= val['error']
    else:
        # OK, either a newly set attribute (which may replace some Attribute set up before a
        # 'lookup_reset'), or replacing an existing Attribute with a new one.  We won't try to
        # compare values or types; just atomically replace the Instance's Attribute w/ the new one.
        assert 'attribute' in val, "Failed to provide attribute for %r" % key
        if val['attribute'] is not attribute:
            cls,ins,att		= res
            instance		= lookup( cls, ins )
            if not new: # if new (since a reset), we don't really care about the old attribute
                log.detail( "Set Tag %-14s%-10s: %-24s Instance Replacing:   %s", key, "@%s/%s/%s" % res, instance,
                            attribute if log.isEnabledFor( logging.INFO ) else misc.reprlib.repr( attribute ))
            log.normal(     "Set Tag %-14s%-10s: %-24s Instance Replaced w/: %s", key, "@%s/%s/%s" % res, instance,
                        val['attribute'] if log.isEnabledFor( logging.INFO ) else misc.reprlib.repr( val['attribute'] ))
            instance.attribute[str(att)] \
                                = attribute


def setup( **kwds ):
    """Create the required CIP device Objects (if they don't exist, and the specified class is not
    None), returning UCMM.  First one in initialize, and don't let anyone else proceed 'til
    complete.  The UCMM isn't really an addressable CIP Object, so we just have to return it.

    If an {identity,message_router,connection_manager,UCMM}_class keyword has been supplied, use it;
    otherwise, use the default Identity (of a *Logix PLC).

    If a tags dict (or dotdict) is supplied, its key: { 'attribute': <Attribute>, 'error': <int> }
    items are used to initialize the given Tag names.

    """
    with setup.lock:
        if not lookup( 0x01, 1 ):
            identity		= kwds.get( 'identity_class',		Identity )
            if identity:
                identity( instance_id=1 )	# Class 0x01, Instance 1
        if not lookup( 0x02, 1 ):
            mr			= kwds.get( 'message_router_class',	Logix )
            if mr:
                mr( instance_id=1 )		# Class 0x02, Instance 1 -- Message Router; knows Logix Tag requests
        if not lookup( 0x06, 1 ):
            cm			= kwds.get( 'connection_manager_class',	Connection_Manager )
            if cm:
                cm( instance_id=1 )		# Class 0x06, Instance 1
        
        if not lookup( 0x66, 1 ):
            Unknown_Object( instance_id=1 )	# Class 0x66, Instance 1 -- Unknown purpose in Logix Controller

        if not lookup( 0xF5, 1 ):
            tcpip		= kwds.get( 'tcpip_class', 		TCPIP )
            if tcpip:
                tcpip( instance_id=1 )		# Class 0xF5, Instance 1

        if not lookup( 0xAC, 1 ):
            logsegs		= kwds.get( 'logical_segments',		Logical_Segments )
            if logsegs:
                logsegs( instance_id=1 )	# Class 0xAC, Instance 1 -- Logical Segments

        if not setup.ucmm:
            setup.ucmm		= kwds.get( 'UCMM_class', 		ucmm.UCMM )()
            if setup.ucmm.route_path:
                log.normal( "UCMM is restricting request route_path to match: %r",
                            str( json.dumps( setup.ucmm.route_path )))

        # If tags are specified, check that we've got them all set up right.  If the tag doesn't
        # exist, add it.  If it's error code doesn't match, change it.  Since it is possible that
        # the Tags and/or their Error codes could change between calls, we check them.  If a
        # tags[name].path is provided, then we'll try to place the Attribute at that path
        # (eg. {'segment':[{'class':123},...]})
        for key,val in dict.items( kwds.get( 'tags', {} )): # Don't want dotdict depth-first iteration...
            setup_tag( key, val )

    return setup.ucmm

setup.lock			= threading.Lock()
setup.ucmm			= None


def process( addr, data, **kwds ):
    """Processes an incoming parsed EtherNet/IP encapsulated request in data.request.enip.input, and
    produces a response with a prepared encapsulated reply, in data.response.enip.input, ready for
    re-encapsulation and transmission as a response.

    Returns True while session lives, False when the session is cleanly terminated.  Raises an
    exception when a fatal protocol processing error occurs, and the session should be terminated
    forcefully.

    When a connection is closed, a final invocation with 

    This roughly corresponds to the CIP Connection "client" object functionality.  We parse the raw
    EtherNet/IP encapsulation to get something like this Register request, in data.request:

        "enip.command": 101, 
        "enip.input": "array('c', '\\x01\\x00\\x00\\x00')",
        "enip.length": 4, 
        "enip.options": 0, 
        "enip.session_handle": 0, 
        "enip.status": 0
        "enip.length": 4


    This is parsed by the Connection Manager:

        "enip.CIP.register.options": 0, 
        "enip.CIP.register.protocol_version": 1, 

    Other requests such as:

        "enip.command": 111, 
        "enip.input": "array('c', '\\x00\\x00\\x00\\x00\\x05\\x00\\x02\\x00\\x00\\x00\\x00\\x00\\xb2\\x00\\x06\\x00\\x01\\x02 f$\\x01')", 
        "enip.length": 22, 
        "enip.options": 0, 
        "enip.sender_context.input": "array('c', '\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00')", 
        "enip.session_handle": 285351425, 
        "enip.status": 0

    are parsed by the Connection Manager, and contain CPF entries requiring further processing by the Unconnected Message
    Manager (UCMM):

        "enip.CIP.send_data.CPF.count": 2, 
        "enip.CIP.send_data.CPF.item[0].length": 0, 
        "enip.CIP.send_data.CPF.item[0].type_id": 0, 
        "enip.CIP.send_data.CPF.item[1].length": 6, 
        "enip.CIP.send_data.CPF.item[1].type_id": 178, 
        "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[0].class": 102, 
        "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.segment[1].instance": 1, 
        "enip.CIP.send_data.CPF.item[1].unconnected_send.request_path.size": 2, 
        "enip.CIP.send_data.CPF.item[1].unconnected_send.service": 1, 
        "enip.CIP.send_data.interface": 0, 
        "enip.CIP.send_data.timeout": 5,



    """
    ucmm			= setup( **kwds )

    source			= automata.rememberable()
    try:
        # Find the Connection Manager, and use it to parse the encapsulated EtherNet/IP request.  We
        # pass an additional request.addr, to allow the Connection Manager to identify the
        # connection, in the case where the connection is closed spontaneously (no request, no
        # request.enip.session_handle).  We'll pass this along explicitly to every request( ... ).

        # TODO: remove? Some API users may depend on it... Yes; also, we want to retain the ability
        # to transport in an empty request, indicating the termination of a session! However, we'll
        # promote an empty data to contain empty data.request, and (hence) empty data.response.
        # Only transport data.request.addr if data/data.request is not empty.
        if 'request' not in data:
            data.request	= {}
        if data.request:
            data.request.addr	= addr
        
        if 'enip' in data.request:
            # Some requests have no encapsulated CIP payload (eg. empty ListServices requests)
            if 'input' in data.request.enip:
                source.chain( data.request.enip.input )
            with ucmm.parser as machine:
                for i,(m,s) in enumerate( machine.run( path='request.enip', source=source, data=data )):
                    #log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %s",
                    #            machine.name_centered(), i, s, source.sent, source.peek(),
                    #            repr( data ) if log.getEffectiveLevel() < logging.DETAIL else misc.reprlib.repr( data ))
                    pass
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "EtherNet/IP CIP Request  (Client %16s): %s", addr, enip_format( data.request ))

        # Create a data.response with a structural copy of the data.request.enip.  This means that
        # the dictionary structure is new (we won't alter the request.enip... when we add entries in
        # the resonse...), but the actual mutable values (eg. bytearray ) are shared.  If we need to
        # change any values, replace them with new values instead of altering them!
        data.response		= dotdict( data.request )
        if 'enip' in data.request:
            data.response.enip	= dotdict( data.request.enip )

        # Get rid of our raw request encapsulated enip.input; we'll generate a new one for the
        # response, and we don't want to ever be accidentally returning our request as our response
        # if we returned unexpectedly.  This is where we'll enforce (arbitrary) limits on incoming
        # request size; an otherwise correctly parsed request can be rejected here due to size.
        # This should probably kill the connection, but we'll let the higher level protocol elements
        # decide that; since we parsed the request and returned a valid response, the channel is
        # still theoretically good.
        if 'enip.input' in data.response:
            del data.response.enip['input']
            if 'size' in kwds and kwds['size'] is not None and len( data.request.enip.input ) > int( kwds['size'] ):
                log.warning( "EtherNet/IP encapsulated request of length %d exceeds specified size limit %s",
                             len( data.request.enip.input ), kwds['size'] )
                data.response.enip.status = 0x65
                return True

        # Let the Connection Manager process the (copied) request in response.enip, producing the
        # appropriate data.response.enip.input encapsulated EtherNet/IP message to return, along
        # with other response.enip... values (eg. .session_handle for a new Register Session).  The
        # enip.status should normally be 0x00; the encapsulated response will contain appropriate
        # error indications if the encapsulated request failed.
        proceed			= ucmm.request( data.response, addr=addr )
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "EtherNet/IP CIP Response (Client %16s): %s", addr, enip_format( data.response ))

        return proceed
    except:
        # Parsing failure.  We're done.  Suck out some remaining input to give us some context.
        processed		= source.sent
        memory			= bytes(bytearray(source.memory))
        pos			= len( source.memory )
        future			= bytes(bytearray( b for b in source ))
        where			= "at %d total bytes:\n%s\n%s (byte %d)" % (
            processed, repr(memory+future), '-' * (len(repr(memory))-1) + '^', pos )
        log.error( "EtherNet/IP CIP error %s\n%s", where,
                   ( '' if log.getEffectiveLevel() >= logging.NORMAL
                     else ''.join( traceback.format_exception( *sys.exc_info() ))))
        raise
