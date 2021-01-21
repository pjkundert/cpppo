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
enip/parser.py	-- The EtherNet/IP CIP protocol parsers

"""

import array
import contextlib
import logging
import struct
import sys

import ipaddress

from ...dotdict import dotdict
from ...automata import ( type_str_base, type_bytes_iter, type_bytes_array_symbol, is_listlike,
                          dfa_base, dfa, decide,
                          state, state_struct, state_drop, state_input, string_bytes )
from ... import misc

log				= logging.getLogger( "enip.srv" )

# 
# octets_base	-- A dfa_base that defaults to scan octets from bytes data
# octets	-- Scans octets to <context>.input array
# octets_encode	--   and converts array of octets back to a bytes string
# octets_struct	-- Scans octets sufficient to fulfill struct 'format', and parses
# words_base	-- A dfa_base that default to scan octet pairs (words) from bytes data
# words		-- Scands words into <context>.input array
# 
#     You must provide either a name or a context; if you provide neither, then both default to the
# name of the class.
# 
class octets_base( dfa_base ):
    """Scan 'repeat' octets (default: 1), using an instance of the provided octets_state class as the
    sub-machine 'initial' state.  The sub-machine has no outgoing transitions, and will terminate
    after accepting and processing exactly one symbol.  Only after all 'repeat' loops will
    self.terminal be True."""
    def __init__( self, name=None, initial=None,
                  octets_name="byte",
                  octets_extension=None, # .input is state_input's default
                  octets_state=state_input,
                  octets_alphabet=type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, initial=octets_state(
            name=octets_name, terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode, extension=octets_extension ), **kwds )
   

class octets( octets_base, state ):
    """Scans 'repeat' octets into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


def octets_encode( value ):
    """Convert various containers to bytes"""
    if isinstance( value, array.array ) and value.typecode == type_bytes_array_symbol:
        return value.tostring() if sys.version_info[0] < 3 else value.tobytes()
    elif isinstance( value, bytearray ):
        return bytes( value )
    elif isinstance( value, bytes ):
        return value
    raise AssertionError( "Unrecognized octets type: %r" % value )


class octets_struct( octets_base, state_struct ):
    """Scans octets sufficient to satisfy the specified struct 'format', and then parses it according
    to the supplied struct 'format' (default is class-level struct_format attribute)."""
    def __init__( self, name=None, format=None, **kwds ):
        if format is not None:
            assert isinstance( format, type_str_base ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, format=format, 
            repeat=struct.calcsize( self.struct_format if format is None else format ),
                                               **kwds )


class octets_noop( octets_base, state ):
    """Does nothing with an octet."""
    def __init__( self, name=None, octets_state=state, **kwds ):
        super( octets_noop, self ).__init__(
            name=name, octets_name="noop", octets_state=octets_state, **kwds )


class octets_drop( octets_base, state ):
    """Scans 'repeat' octets and drops them."""
    def __init__( self, name=None, octets_state=state_drop, **kwds ):
        super( octets_drop, self ).__init__(
            name=name, octets_name="drop", octets_state=octets_state, **kwds )
        

class words_base( dfa_base ):
    """Scan 'repeat' 2-byte words (default: 1), convenient when sizes are specified in words."""
    def __init__( self, name=None, initial=None,
                  words_state=state_input,
                  words_alphabet=type_bytes_iter,
                  words_encoder=None,
                  words_typecode=type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        byt0			= words_state(
            name="byte0", alphabet=words_alphabet, encoder=words_encoder,
            typecode=words_typecode )
        byt0[True]		= words_state(
            name="byte1", alphabet=words_alphabet, encoder=words_encoder,
            typecode=words_typecode, terminal=True )
        super( words_base, self ).__init__( name=name, initial=byt0, **kwds )
   

class words( words_base, state ):
    """Scans 'repeat' words into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


# 
# The basic EtherNet/IP CIP protocol data types
# 
# USINT		-- Parse an 8-bit EtherNet/IP unsigned int 
# USINT.produce	--   and convert a value back to a 8-bit EtherNet/IP unsigned int
# ...
# 
#     You must provide either a name or a context; if you provide neither, then both default to the
# name of the class.  An instance of any of these types "is" a parser state machine, and has a
# produce method that will re-produce the bytes stream from a (previously parsed) structure.  All
# the simple data types are derived from TYPE, and simply drive from state_struct to directly
# parse the data value into the provided context (using the python struct module).
# 
#     More complex data types are derived from STRUCT, are derived from dfa, and require a
# state machine to be constructed to parse the data.
# 
#     Any EtherNet/IP type based on TYPE has class-level .struct_format and a
# .struct_calcsize attribute; its size in bytes (we do not employ the capability
# of octets_struct and state_struct to have a custom instance-level format).
# 
class TYPE( octets_struct ):
    """An EtherNet/IP data type"""
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        super( TYPE, self ).__init__( name=name, **kwds )

    @classmethod
    def produce( cls, value ):
        return struct.pack( cls.struct_format, value )

class BOOL( TYPE ):
    """An EtherNet/IP BOOL; 8-bit boolean

    Surprisingly, the struct '?' format does *not* work as you might expect.  the value b'\x00'
    converts to False reliably.  However, only b'\x01' converts to True reliably; any other value
    may or may not result in True, depending on the version of Python being used!  Python 2.7/3.9
    return False for eg. b'\x02', while Pypy 3.6.9 return True.

    Therefore, we will convert octets to unsigned integer via 'B', and then post-process to bool.
    """
    tag_type                    = 0x00c1 # 193
    struct_format               = 'B' # do not use '?'!
    struct_calcsize             = struct.calcsize( struct_format )

    def terminate( self, exception, machine=None, path=None, data=None ):
        super( BOOL, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        if exception is not None:
            return
        ours			= self.context( path=path )
        if is_listlike( data[ours] ):
            data[ours]		= list( map( bool, data[ours] ))
        else:
            data[ours]		= bool( data[ours] )

    @classmethod
    def produce( cls, value ):
        """Historically, a 0xFF has been used to represent an EtherNet/IP CIP BOOL Truthy value."""
        encoding		= super( BOOL, cls ).produce( value )
        return encoding if encoding == b'\x00' else b'\xff'

class USINT( TYPE ):
    """An EtherNet/IP USINT; 8-bit unsigned integer"""
    tag_type			= 0x00c6
    struct_format		= 'B'
    struct_calcsize		= struct.calcsize( struct_format )

class SINT( TYPE ):
    """An EtherNet/IP SINT; 8-bit signed integer"""
    tag_type			= 0x00c2
    struct_format		= 'b'
    struct_calcsize		= struct.calcsize( struct_format )

class UINT( TYPE ):
    """An EtherNet/IP UINT; 16-bit unsigned integer"""
    tag_type			= 0x00c7
    struct_format		= '<H'
    struct_calcsize		= struct.calcsize( struct_format )

class INT( TYPE ):
    """An EtherNet/IP INT; 16-bit signed integer"""
    tag_type			= 0x00c3
    struct_format		= '<h'
    struct_calcsize		= struct.calcsize( struct_format )

class WORD( UINT ):
    tag_type			= 0x00D2

class UDINT( TYPE ):
    """An EtherNet/IP UDINT; 32-bit unsigned integer"""
    tag_type			= 0x00c8
    struct_format		= '<I'
    struct_calcsize		= struct.calcsize( struct_format )

class DWORD( UDINT ):
    tag_type			= 0x00D3

class DINT( TYPE ):
    """An EtherNet/IP DINT; 32-bit signed integer"""
    tag_type			= 0x00c4
    struct_format		= '<i'
    struct_calcsize		= struct.calcsize( struct_format )

class ULINT( TYPE ):
    """An EtherNet/IP ULINT; 64-bit unsigned integer"""
    tag_type			= 0x00c9
    struct_format		= '<Q'
    struct_calcsize		= struct.calcsize( struct_format )

class LINT( TYPE ):
    """An EtherNet/IP LINT; 64-bit signed integer"""
    tag_type			= 0x00c5
    struct_format		= '<q'
    struct_calcsize		= struct.calcsize( struct_format )

class REAL( TYPE ):
    """An EtherNet/IP REAL; 32-bit float"""
    tag_type			= 0x00ca
    struct_format		= '<f'
    struct_calcsize		= struct.calcsize( struct_format )

class LREAL( TYPE ):
    """An EtherNet/IP LREAL; 64-bit float"""
    tag_type			= 0x00cb
    struct_format		= '<d'
    struct_calcsize		= struct.calcsize( struct_format )

# Some network byte-order types that are occasionally used in parsing
class UINT_network( TYPE ):
    """An EtherNet/IP UINT; 16-bit unsigned integer, but in network byte order"""
    struct_format		= '>H'
    struct_calcsize		= struct.calcsize( struct_format )

class INT_network( TYPE ):
    """An EtherNet/IP INT; 16-bit integer, but in network byte order"""
    struct_format		= '>h'
    struct_calcsize		= struct.calcsize( struct_format )

class UDINT_network( TYPE ):
    """An EtherNet/IP UDINT; 32-bit unsigned integer, but in network byte order"""
    struct_format		= '>I'
    struct_calcsize		= struct.calcsize( struct_format )

class DINT_network( TYPE ):
    """An EtherNet/IP DINT; 32-bit integer, but in network byte order"""
    struct_format		= '>i'
    struct_calcsize		= struct.calcsize( struct_format )

class REAL_network( TYPE ):
    """An EtherNet/IP INT; 32-bit float, but in network byte order"""
    struct_format		= '>f'
    struct_calcsize		= struct.calcsize( struct_format )

class STRUCT( dfa, state ):
    """An EtherNet/IP STRUCT; By default, a 2-byte UINT .structure_tag, followed by arbitrarily encoded
    raw .data.input.  We'll generally use this as a base class for types requiring custom parser
    state machinery and produce methods; the default will be an unparsed raw CIP STRUCT w/ a
    .structure_tag value.

    To parse just the .structure_tag, establish the STRUCT parser w/ limit=2.

    If a structure_tag is supplied (as either a string or numeric value), then we assume it has
    already been parsed and only the raw data is to be parsed.

    """
    tag_type			= 0x02a0

    def __init__( self, name=None, initial=None, structure_tag=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        if initial is None:
            strt		= UINT(				context='structure_tag',
                                                terminal=True)
            # Any remaining data into .data.input (only if input remains!)
            strt[True]	= pyld	= octets(	'payload',	context='data',
                                                terminal=True )
            pyld[True]		= pyld

            initial		= strt if structure_tag is None else pyld

        super( STRUCT, self ).__init__( name=name, initial=initial, **kwds )

    @classmethod
    def produce( cls, value, structure_tag=None ):
        """We need to be able to produce the result with and without a UINT .structure_tag encoded
        before it.  If None/False, the default is to produce no UINT structure tag prefix.

        It is assumed that the encoded structure data payload is in .input.
        """
        if structure_tag is None:
            structure_tag	= False			# default: No UINT structure_tag prefix
        if isinstance( structure_tag, bool ) and structure_tag:
            structure_tag	= value.structure_tag	# True: Use the known structure_tag
        result			= b''
        if structure_tag:
            result	       += UINT.produce( structure_tag )
        # A single UDT record's worth of raw payload is assumed to be available in .data.input;
        # derived classes should pre-encode their value.
        encoded			= octets_encode( value.data.input )
        result		       += encoded
        return result


class SSTRING( STRUCT ):
    """Parses/produces a EtherNet/IP Short String:

        .SSTRING.length			USINT		1
        .SSTRING.string			octets[*]	.length

    The produce classmethod accepts this structure, or just a plain Python str, and will output the
    equivalent length+string.  If a zero length is provided, no string is parsed, and an empty
    string returned.

    """
    tag_type			= 0x00DA
    struct_calcsize		= 80 # Average SSTRING size used for estimations

    def __init__( self, name=None, **kwds):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        leng			= USINT(		'length', context='length' )
        leng[None]		= move_if(		'empty',  destination='.string', initializer='',
                                    predicate=lambda path=None, data=None, **kwds: not data[path].length,
                                                        state=octets_noop( 'done', terminal=True ))
        leng[None]		= string_bytes(		'string',
                                                        limit='..length',
                                                        initial='.*',	decode='iso-8859-1',
                                                        terminal=True )

        super( SSTRING, self ).__init__( name=name, initial=leng, **kwds )

    @classmethod
    def produce( cls, value ):
        """Truncate or NUL-fill the provided .string to the given .length (if provided and not None).
        Then, emit the (one byte) length+string.  Accepts either a {.length: ..., .string:... }
        dotdict, or a plain string.

        """
        result			= b''
        
        if isinstance( value, type_str_base ):
            value		= dotdict( {'string': value } )

        encoded			= value.string.encode( 'iso-8859-1' )
        # If .length doesn't exist or is None, set the length to the actual string length
        actual			= len( encoded )
        desired			= value.setdefault( 'length', actual )
        if desired is None:
            value.length 	= actual
        assert value.length < 1<<8, "SSTRING must be < 256 bytes in length; %r" % value

        result		       += USINT.produce( value.length )
        result		       += encoded[:value.length]
        if actual < value.length:
            result	       += b'\x00' * ( value.length - actual )
        return result


class STRING( STRUCT ):
    """Parses/produces a EtherNet/IP String:

        .STRING.length			UINT		2
        .STRING.string			octets[*]	.length+.length%2

    The produce classmethod accepts this structure, or just a plain Python str, and will output the
    equivalent length+string.  If a zero length is provided, no string is parsed, and an empty
    string returned.  Much like SSTRING, except:

    - a 2-byte UINT specifies the length
    - the string is padded to an even number of words with a NUL byte, if necessary

    """
    tag_type			= 0x00D0
    struct_calcsize		= 80 # Average STRING size used for estimations

    def __init__( self, name=None, **kwds):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        leng			= UINT(			'length', context='length' )
        leng[None]		= move_if(		'empty',  destination='.string', initializer='',
                                    predicate=lambda path=None, data=None, **kwds: 0 == data[path].length,
                                    state=octets_noop(	'done',
                                                        terminal=True ))
        leng[None] = sbdy	= string_bytes(		'string',
                                                        limit='..length',
                                                        initial='.*',	decode='iso-8859-1' )
        sbdy[None]		= decide(		'string_even',
                                    predicate=lambda path=None, data=None, **kwds: 0 == data[path].length % 2,
                                    state=octets_noop(	'done',
                                                        terminal=True ))
        sbdy[None]		= octets_drop(		'pad', repeat=1,
                                                	terminal=True )

        super( STRING, self ).__init__( name=name, initial=leng, **kwds )

    @classmethod
    def produce( cls, value ):
        """Truncate or NUL-fill the provided .string to the given .length (if provided and not None).
        Then, emit the (two byte) length+string+pad.  Accepts either a {.length: ..., .string:... }
        dotdict, or a plain string.  

        """
        result			= b''
        
        if isinstance( value, type_str_base ):
            value		= dotdict( {'string': value } )

        encoded			= value.string.encode( 'iso-8859-1' )
        # If .length doesn't exist or is None, set the length to the actual string length
        actual			= len( encoded )
        desired			= value.setdefault( 'length', actual )
        if desired is None:
            value.length 	= actual
        assert value.length < 1<<16, "STRING must be < 65536 bytes in length; %r" % value

        result		       += UINT.produce( value.length )
        result		       += encoded[:value.length]
        if actual < value.length:
            result	       += b'\x00' * ( value.length - actual )
        if value.length % 2:
            result	       += b'\x00' # pad, if length is odd
        return result


class IPADDR( UDINT ):
    """Acts alot like a UDINT, but .produce takes an optional string value, and parses a
    UDINT to produce an IPv4 dotted-quad address string.

    """
    def terminate( self, exc, machine, path, data ):
        """Post-process a parsed UDINT IP address to produce it in dotted-quad string form"""
        super( IPADDR, self ).terminate( exc, machine=machine, path=path, data=data )
        ours			= self.context( path )
        ipaddr			= ipaddress.ip_address( data[ours] )
        log.info( "Converting %d --> %r", data[ours], ipaddr )
        data[ours]		= str( ipaddr )

    @classmethod
    def produce( cls, value ):
        if isinstance( value, type_str_base ):
            # Parse the supplied IP address string to an integer.  ip_address requires unicode
            # value, even in Python2; there is no Python2/3 agnostic method for casting to unicode!
            ipaddr		= ipaddress.ip_address(
                ( unicode if sys.version_info[0] < 3 else str )( value ))
            value		= int( ipaddr )
            log.info( "Converted IP %r --> %d", ipaddr, value )
        return UDINT.produce( value )


class IPADDR_network( UDINT_network ):
    """Some CIP requests return network-ordered IPADDRs (eg. ListIdentity).

    """
    def terminate( self, exc, machine, path, data ):
        """Post-process a parsed UDINT_netowrk IP address to produce it in dotted-quad string form"""
        super( IPADDR_network, self ).terminate( exc, machine=machine, path=path, data=data )
        ours			= self.context( path )
        ipaddr			= ipaddress.ip_address( data[ours] )
        log.info( "Converting %d --> %r (network byte ordered)", data[ours], ipaddr )
        data[ours]		= str( ipaddr )

    @classmethod
    def produce( cls, value ):
        if isinstance( value, type_str_base ):
            ipaddr		= ipaddress.ip_address(
                ( unicode if sys.version_info[0] < 3 else str )( value ))
            value		= int( ipaddr )
            log.info( "Converted IP %r --> %d (network byte ordered)", ipaddr, value )
        return UDINT_network.produce( value )


class IFACEADDRS( STRUCT ):
    """Parses/produces a struct of TCP/IP interface IP address data, as per. Attribute 5 of the TCPIP
    Interface Object.  Takes a dict, eg.: {
        'ip_address': 		0x0201000A,	# or '10.0.1.2'
        'network_mask':		0x0000FFFF,	# or '255.255.0.0'
        'gateway_address':	0x0100000A,	# or '10.0.0.1'
        'dns_primary':		0x0100000A,	# or '10.0.0.1'
        'dns_secondary':	0x0200000A,	# or '10.0.0.2'
        'domain_name':		'acme.ca',
    }

    and produces a network byte-ordered encoding, and can parse such an encoding to restore the IP
    addresses and domain_name.

    """
    tag_type			= None
    def __init__( self, name=None, **kwds):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        ipad			= IPADDR(	context='ip_address' )
        ipad[True] = nmsk	= IPADDR(	context='network_mask' )
        nmsk[True] = gwad	= IPADDR(	context='gateway_address' )
        gwad[True] = dns1	= IPADDR(	context='dns_primary' )
        dns1[True] = dns2	= IPADDR(	context='dns_secondary' )
        dns2[True] = domn	= STRING(	context='domain_name',
                                                terminal=True )
        domn[None]		= move_if( 'movsstring', source='.domain_name.string',
                                                    destination='.domain_name' )

        super( IFACEADDRS, self ).__init__( name=name, initial=ipad, **kwds )

    @classmethod
    def produce( cls, value ):
        """Emit the binary representation (always in Network byte-order) of the supplied IFACESADDRS value dict.
        Allows strings, which are assumed to be textual representations of IP addresses.

        """
        result			= b''
        result		       += IPADDR.produce( value.get( 'ip_address', 0 ))
        result		       += IPADDR.produce( value.get( 'network_mask', 0 ))
        result		       += IPADDR.produce( value.get( 'gateway_address', 0 ))
        result		       += IPADDR.produce( value.get( 'dns_primary', 0 ))
        result		       += IPADDR.produce( value.get( 'dns_secondary', 0 ))
        result		       += STRING.produce( value.get( 'domain_name', '' ))
        return result


# 
# enip_header	-- Parse an EtherNet/IP header only 
# enip_machine	-- Parses an EtherNet/IP header and encapsulated data payload
# enip_encode	--   and convert parsed EtherNet/IP data back into a message
# 
class enip_header( dfa ):
    """Scans either a complete EtherNet/IP encapsulation header, or nothing (EOF), into the context
    (default 'header'):
    
        .header.command			UINT         2
        .header.length			UINT         2
        .header.session_handle		UDINT        4
        .header.status			UDINT        4
        .header.sender_context		octets[8]    8
        .header.options			UDINT        4
                                                    --
                                                    24

    Does *not* scan the command-specific data which (normally) follows the header.

    Each protocol element transitions to the next required element on any (non-None) symbol; we
    don't use None (no-input) transition, because we don't want to skip thru the state machine
    when no input is available.

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', 'header' )
        init			= state(  "empty",  terminal=True )
        init[True] = cmnd	= UINT(		"command",	context="command" )
        cmnd[True] = leng	= UINT(		"length",	context="length" )
        leng[True] = sess	= UDINT(	"sess_hdl",	context="session_handle" )
        sess[True] = stat	= UDINT(	"status",	context="status" )
        stat[True] = ctxt	= octets(	"sndr_ctx",	context="sender_context",
                                    repeat=8 )
        ctxt[True] 		= UDINT( 	"options",	context="options", terminal=True )

        super( enip_header, self ).__init__( name=name, initial=init, **kwds )


class enip_machine( dfa ):
    """Parses a complete EtherNet/IP message, including header (into <context> and command-specific
    encapsulated payload (into <context>.input).  Note that this does *not* put the EtherNet/IP
    header in a separate '.header' context.  '<context>.input'.  Context defaults to 'enip'
    (unless explicitly set to '').

        .enip.command			(from enip_header)
        .enip.length
        ...
        .enip.input			octets[*]	.length

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', 'enip' )
        hedr			= enip_header(	'header' ) # NOT in a separate context!
        hedr[None]		= octets(	'payload',
                                                repeat=".length",
                                                terminal=True )

        super( enip_machine, self ).__init__( name=name, initial=hedr, **kwds )

def enip_encode( data ):
    """Produce an encoded EtherNet/IP message from the supplied data; assumes any encapsulated data has
    been encoded to enip.input and is already available.  Assumes a data artifact is supplied like
    the one produced by enip_machine.  If no encapsulated message available in data.input, then a
    payload size of 0 is returned; normally, this should be accompanied by a non-zero status, but we
    don't check here.

    """
    result			= b''.join([
        UINT.produce(	data.command ),
        UINT.produce( len(data.input ) if 'input' in data else 0 ),
        UDINT.produce(	data.session_handle ),
        UDINT.produce(	data.status ),
        octets_encode(	data.sender_context.input ),
        UDINT.produce(	data.options ),
        octets_encode(	data.input ) if 'input' in data else b'',
    ])
    return result
    

def enip_format( data, sort_keys=False, indent=4 ):
    """Format a decoded EtherNet/IP data bundle in a (more) human-readable form.

    There is no means by which to specify a custom sorting function.  The cpppo.dotdict outputs keys
    with formatting that tries to retain sorting order of lists of sub-dotdict indices.

    In Python2, we need to specially handle str/bytes vs. unicode strings; we need to avoid
    enip_format attempting to decode str as utf-8.

    """
    assert isinstance( data, dict ), \
        "Unknown data type {data!r}".format( data=data )
    pairs			= data.items()
    if sort_keys:
        pairs			= sorted( pairs )
    prefix			= ' ' * indent
    newline			= '\n' + prefix
    result			= '{'
    for key,val in pairs:
        result		       += newline + "{key:32}".format( key=repr( key ) + ': ' )
        if isinstance( val, bytes ) and sys.version_info[0] < 3: # Python2: str; very ambiguous
            if not any( c < ' ' or c > '~' for c in val ):
                result += repr( val ) + ',' # '...',
                continue
            try:
                if not any( c < ' ' for c in val ):
                    result     += repr( val.decode( 'utf-8' )) + ',' # Python2: u"...", Python3: "..."
                    continue
            except:
                pass
            # Probably binary data in bytes; fall thru...
        try:
            binary		= octets_encode( val )
        except:
            pass
        else:
            # Yes, some binary data container
            if isinstance( val, array.array ):
                beg,end		= 'array( {val.typecode!r}, '.format( val=val ),')'
            elif isinstance( val, bytearray ):
                beg,end		= 'bytearray(',')'
            else:
                beg,end		= 'bytes(',')'
            result	       += "{beg}hexload(r'''".format( beg=beg )
            result	       += ''.join( newline + prefix + row for row in misc.hexdumper( val ))
            result	       += newline + "'''){end},".format( end=end )
            continue

        if is_listlike( val ) and len( val ) > 10:
            # Try to tabularize large lists of data
            try:
                beg,end		= getattr( getattr( val, '__class__' ), '__name__' ) + '(',')'
            except:
                pass
            else:
                result	       += beg
                for i,v in enumerate( val ):
                    if i%10 == 0:
                        result += newline + prefix
                    fmt		= "{v:<8}" if isinstance( v, type_str_base ) else "{v:>8}"
                    result     += fmt.format( v=repr( v )+',' )
                result	       += newline + end + ','
                continue

        # Other data types
        result		       += repr( val )
        result		       += ','
    result		       += '\n}'
    return result

# 
# EtherNet/IP CIP Parsing
# 
# See Vol2_1.14.pdf, Chapter 3-2.1 Unconnected Messages, for a simplified overview of parsing.  We
# parse the SendRRData, the CPF encapsulation, and the CPF Null Address and [Un]connected Data
# items, and finally the CIP Message Router Request from the second CPF item.
# 

class move_if( decide ):
    """If the predicate is True (the default), then move (either append or assign) data[path+source]
    to data[path+destination], assigning init to it first if the target doesn't yet exist.  Then,
    proceed to the target state.  If no source is provided, only the initialization (if not None)
    occurs.  The destination defaults to the plain path context.

    If the destination ends in a relative path signifier '.', then the original basename is
    appended.  This allows us to move named things around into relative locations while retaining
    their original names.

    If desired, you can disable the 'tidy' step at the end which eliminates empty src dicts, if you're
    using multi-step move_if actions, and need to retain intermediate empty dicts.
    """
    def __init__( self, name, source=None, destination=None, initializer=None, **kwds ):
        super( move_if, self ).__init__( name=name, **kwds )
        self.src		= source
        self.dst		= destination if destination else ''
        self.ini		= initializer

    def execute( self, truth, machine=None, source=None, path=None, data=None ):
        target			= super( move_if, self ).execute(
            truth, machine=machine, source=source, path=path, data=data )
        if not truth:
            return target

        pathsrc			= path + ( self.src or '' )
        pathdst			= path + self.dst
        #log.normal( "%s -- moving data[%r] to data[%r], in %r", self, pathsrc, pathdst, data )
        if self.ini is not None and pathdst not in data:
            ini			= ( self.ini
                                    if not hasattr( self.ini, '__call__' )
                                    else self.ini(
                                            machine=machine, source=source, path=path, data=data ))
            assert pathdst, \
                "%s -- cannot assign from {pathsrc!r} to {pathdst!r} = {ini!r} in {data!r}".format(
                    pathsrc=pathsrc, pathdst=pathdst, ini=ini, data=data )
            try:
                data[pathdst]	= ini
            finally:
                log.debug( "%s -- init. data[%r] to %r in data: %s", self, pathdst, ini, data )
        if self.src is not None:
            assert pathsrc, \
                "%s -- cannot assign from {pathsrc!r} to {pathdst!r} = {ini!r} in {data!r}".format(
                    pathsrc=pathsrc, pathdst=pathdst, ini=ini, data=data )
            try:
                src		= data.pop( pathsrc )
            except Exception as exc:
                raise AssertionError( "Could not find %r to move to %r in %r: %r" % (
                    pathsrc, pathdst, data, exc ))
            dst			= data.get( pathdst ) # May be None, if no self.ini...
            if hasattr( dst, 'append' ):
                # We're supposed to append to an existing destination list-like thing...
                log.debug( "%s -- append data[%r] == %r to data[%r]", self, pathsrc, src, pathdst )
                dst.append( src )
            else:
                # We're supposed to replace an existing destination object
                log.debug( "%s -- assign data[%r] == %r to data[%r]", self, pathsrc, src, pathdst )
                data[pathdst]	= src

        return target


class EPATH( dfa ):
    """Parses an Extended Path of .size (in words), path_data and path segment list

        .EPATH.size
        .EPATH.segment [
            { 'class':      # },
            { 'instance':   # },
            { 'attribute':  # },
            { 'element':    # },
            { 'symbolic':   '...' }, [{ 'symbolic': '...' }, ...]
            { 'port':       #, link #/'1.2.3.4' },
         ]
         .EPATH.segment__... temp 

    Also works as a Route Path (which has a pad after size), by setting padsize=True.

    The path logical segments are encoded as follows (from Volume 1: CIP Common Specification,
    C=1.4.2 Logical Segment):


    Segment Type    Logical Type    Logical Format
    +---+---+---+   +---+---+---+   +---+---+
    | 0 | 0 | 1 |   |   |   |   |   |   |   |
    +---+---+---+   +---+---+---+   +---+---+

    Class ID          0   0   0       0   0   8-bit logical address
    Instance ID       0   0   1       0   1  16-bit logical address
    Element/Member ID 0   1   0       1   0  32-bit logical address (element Id's only?)
    Connection Point  0   1   1       1   1  (reserved for future use)
    Attribute ID      1   0   0
    Special*          1   0   1
    Service ID*       1   1   0
    Reserved          1   1   1

    *The Special and Service ID Logical Types do not use the logical addressing definition for the Logical Format

    The 8-bit logical address format is allowed for use with all Logical Types.

    The 16-bit logical address format is only allowed for use with Logical Types Class ID,
    Instance ID, Member ID, and Connection Point.

    The 32-bit logical address format is not allowed (reserved for future use).

    The Connection Point Logical Type provides additional addressing capabilities beyond the
    standard Class ID/Instance ID/Attribute ID/Member ID Object Address. Object Classes shall
    define when and how this addressing component is utilized.

    The Service ID Logical Type has the following definition for the Logical Format:
        0 0 8-Bit Service ID Segment (0x38)
        0 1 Reserved for future use (0x39)
        1 0 Reserved for future use (0x3A)
        1 1 Reserved for future use (0x3B)

    The Special Logical Type has the following definition for the Logical Format:
        0 0 Electronic Key Segment (0x34)
        0 1 Reserved for future use (0x35)
        1 0 Reserved for future use (0x36)
        1 1 Reserved for future use (0x37)

    The Electronic Key segment shall be used to verify/identify a device. Possible uses include
    verification during connection establishment and identification within an EDS file. This segment
    has the format as shown in the table below.


    From Volume 1, Common Industrial Protocol Specification, 5-5.5.3:

    Connection Points within the Assembly Object are identical to Instances. For example, Connection
    Point 4 of the Assembly Object is the same as Instance 4. Specifying a path of "20 04 24 VV 30
    03" is the same as "20 04 2C VV 30 03".

    """
    PADSIZE			= False
    SINGLE			= False # True --> a single EPATH segment (w/ no SIZE)
    SEGMENTS			= {
        'symbolic':	0x91,
        'class':	0x20,
        'instance':	0x24,
        'connection':	0x2c, # In Assembly Class 0x0004, is like instance
        'attribute':	0x30,
        'element':	0x28,
        'port':		0x00,
    }

    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        # Get the size, and chain remaining machine onto rest.  When used as a Route Path, the size
        # is padded, so insert a state to drop the pad, and chain rest to that instead.  We handle a
        # Route Path with a zero size; it'll be empty, except for the size.
        if not self.SINGLE:
            size		= rest	= USINT(			context='size' )
            if self.PADSIZE:
                size[True]	= rest	= octets_drop( 	'pad', 		repeat=1 )

        # After capturing each segment__ (pseg), move it onto the path segment list
        pseg			= octets_noop(	'type',		terminal=True )
        # ...segment parsers..., and loop (unless SINGLE)
        pmov			= move_if( 	'move',		initializer=lambda **kwds: [],
                                            source='..segment__', destination='..segment',
                                    state=octets_noop( 'done', terminal=True ) if self.SINGLE else pseg )

        # Wire each different segment type parser between pseg and pmov
        
        # 0x28 == 001 010 00 Class ID,  8-bit
        # 0x29 == 001 010 01 Class ID, 16-bit
        # 0x2A == 001 010 11 Class ID, 32-bit
        pseg[b'\x28'[0]]= e_8t	= octets_drop(	'type',		repeat=1 )
        e_8t[True]	= e_8v	= USINT( 	'elem_8bit',	context='element')
        e_8v[None]		= pmov

        pseg[b'\x29'[0]]= e16t	= octets_drop(	'type',		repeat=2 )
        e16t[True]	= e16v	= UINT(		'elem16bit',	context='element')
        e16v[None]		= pmov

        pseg[b'\x2a'[0]]= e32t	= octets_drop(	'type',		repeat=2 )
        e32t[True]	= e32v	= UDINT(	'elem32bit',	context='element')
        e32v[None]		= pmov

        # 0x20 == 001 000 00 Class ID,  8-bit
        # 0x21 == 001 000 01 Class ID, 16-bit
        pseg[b'\x20'[0]]= c_8t	= octets_drop(	'type',		repeat=1 )
        c_8t[True]	= c_8v	= USINT(	'clas_8bit',	context='class')
        c_8v[None]		= pmov

        pseg[b'\x21'[0]]= c16t	= octets_drop(	'type',		repeat=2 )
        c16t[True]	= c16v	= UINT(		'clas16bit',	context='class')
        c16v[None]		= pmov

        # 0x24 == 001 001 00 Instance ID,  8-bit
        # 0x25 == 001 001 01 Instance ID, 16-bit
        pseg[b'\x24'[0]]= i_8t	= octets_drop(	'type',		repeat=1 )
        i_8t[True]	= i_8v	= USINT(	'inst_8bit',	context='instance')
        i_8v[None]		= pmov

        pseg[b'\x25'[0]]= i16t	= octets_drop(	'type',		repeat=2 )
        i16t[True]	= i16v	= UINT(		'inst16bit',	context='instance')
        i16v[None]		= pmov

        # 0x2C == 001 011 00 Connection Point,  8-bit
        # 0x2D == 001 011 01 Connection Point, 16-bit
        pseg[b'\x2c'[0]]= p_8t	= octets_drop(	'type',		repeat=1 )
        p_8t[True]	= p_8v	= USINT(	'cnpt_8bit',	context='connection')
        p_8v[None]		= pmov

        pseg[b'\x2d'[0]]= p16t	= octets_drop(	'type',		repeat=2 )
        p16t[True]	= p16v	= UINT(		'cnpt16bit',	context='connection')
        p16v[None]		= pmov

        # 0x30 == 001 100 00 Attribute ID,  8-bit
        # 0x31 == 001 100 01 Attribute ID, 16-bit
        pseg[b'\x30'[0]]= a_8t	= octets_drop(	'type',		repeat=1 )
        a_8t[True]	= a_8v	= USINT(	'attr_8bit',	context='attribute')
        a_8v[None]		= pmov

        pseg[b'\x31'[0]]= a16t	= octets_drop(	'type',		repeat=2 )
        a16t[True]	= a16v	= UINT(		'attr16bit',	context='attribute')
        a16v[None]		= pmov

        # 0x90 == 100 100 01 Symbolic
        pseg[b'\x91'[0]]= symt	= octets_drop(	'type',		repeat=1 )
        symt[True]	= syml	= USINT(	'sym_len',	context='symbolic.length' )
        syml[None]	= symv	= string_bytes(	'symbolic',	context='symbolic', limit='.length',
                                                initial='.*',	decode='iso-8859-1' )

        # An odd-length ANSI Extended Symbolic name means an odd total.  Pad
        symo			= octets_drop(	'pad', 		repeat=1 )
        symo[None]		= pmov

        symv[None]		= decide(	'odd',
                predicate=lambda path=None, data=None, **kwds: len( data[path].symbolic ) % 2,
                                                state=symo )
        symv[None]		= pmov


        # Route Path port/link-address.  See Vol 1-3.13, Table C-1.3 Port Segment Encoding.
        # segment:  0b000spppp 
        #                |\\\\+-> port number 0x01-0x0E; 0x0F=>extended
        #                |
        #                +------> link size+address; 0=>numeric, 1=>size+string
        # 
        def port_fix( path=None, data=None, **kwds ):
            """Discard port values above 0x0F; return True (transition) if remaining port value is 0x0F
            (Optional Extended port number > 0x0E)"""
            data[path].port    &= 0x0F
            if data[path].port == 0x0F:
                # Port is extended; discard and prepare to collect new port number
                data[path].port	= dotdict()
                return True
            # Port is OK; don't transition
            return False

        # [01-0E][LL] 				port 01-0E, link-address #LL
        pseg[b'\x01'[0]]= pnum	= USINT(	'port_num',	context='port' )
        pseg[b'\x02'[0]]	= pnum
        pseg[b'\x03'[0]]	= pnum
        pseg[b'\x04'[0]]	= pnum
        pseg[b'\x05'[0]]	= pnum
        pseg[b'\x06'[0]]	= pnum
        pseg[b'\x07'[0]]	= pnum
        pseg[b'\x08'[0]]	= pnum
        pseg[b'\x09'[0]]	= pnum
        pseg[b'\x0a'[0]]	= pnum
        pseg[b'\x0b'[0]]	= pnum
        pseg[b'\x0c'[0]]	= pnum
        pseg[b'\x0d'[0]]	= pnum
        pseg[b'\x0e'[0]]	= pnum

        # [0F][PPPP][LL]			port 0xPPPP,  link-address 0xLL
        pseg[b'\x0f'[0]]	= pnum

        # A big port#; re-scan a UINT into .port (won't work 'til port_fix is called)
        pnbg			= UINT(		'port_nbg',	context='port' )
        pnbg[True]	= pnlk	= USINT(	'link_num',	context='link' )

        # Fix the port#; if 0x0F, setup for extended port and transition to pnbg.  Otherwise,
        # (not extended port), just go the the port numeric link.
        pnum[None]		= decide(	'port_nfix',	predicate=port_fix,
                                                state=pnbg )
        pnum[None]		= pnlk
        pnlk[None]		= pmov	 	# and done; move segment, get next

        # [11-1E][SS]'123.123.123.123'[00]	port 0x01-0E, link address '123.123.123.123' (pad if size 0xSS odd)
        pseg[b'\x11'[0]]= padr	= USINT(	'port_adr',	context='port' )
        pseg[b'\x12'[0]]	= padr
        pseg[b'\x13'[0]]	= padr
        pseg[b'\x14'[0]]	= padr
        pseg[b'\x15'[0]]	= padr
        pseg[b'\x16'[0]]	= padr
        pseg[b'\x17'[0]]	= padr
        pseg[b'\x18'[0]]	= padr
        pseg[b'\x19'[0]]	= padr
        pseg[b'\x1a'[0]]	= padr
        pseg[b'\x1b'[0]]	= padr
        pseg[b'\x1c'[0]]	= padr
        pseg[b'\x1d'[0]]	= padr
        pseg[b'\x1e'[0]]	= padr

        # [1F][SS][PPPP]'123.123.123.123'[00]	port 0xPPPP,  link address '123.123.123.123' (pad if size SS odd)
        pseg[b'\x1f'[0]]	= padr

        # Harvest the addresses into .link
        adrv			= string_bytes(	'link_add',	context='link',	limit='.length',
                                                initial='.*',	decode='iso-8859-1' )

        # An odd-length link address means an odd total.  Pad
        adro			= octets_drop(	'link_pad', 		repeat=1 )
        adro[None]		= pmov

        adrv[None]		= decide(	'link_odd',
                predicate=lambda path=None, data=None, **kwds: len( data[path+'.link'] ) % 2,
                                                state=adro )
        adrv[None]		= pmov

        # A big port#; re-scan a UINT into .port (won't work 'til port_fix is called)
        pabg			= UINT(		'port_abg',	context='port' )
        pabg[None]		= adrv

        # 
        padr[True]	= adrl	= USINT(	'link_len',	context='link.length' )
        adrl[None]		= decide(	'port_afix', 	predicate=port_fix,
                                                state=pabg )
        adrl[None]	= adrv

        # Parse all segments in a sub-dfa limited by the parsed path.size (in words; double)
        # If the size is zero, we won't be parsing anything; initialize segment to []
        def size_init( path=None, data=None, **kwds ):
            octets		= data[path+'..size'] * 2
            log.info( "Size of EPATH in octets: %d", octets )
            if not octets:
                data[path+'..segment'] = []
            return octets

        each			= dfa(		'seg',		context='segment__',
                                                initial=pseg,	terminal=True,
                                                limit=None if self.SINGLE else size_init )
        if self.SINGLE:
            init		= each
        else:
            # if sized (not SINGLE), then the parser starts with parsing a size, and continues
            # parsing each segment after either the size or its pad (rest, set above).
            init		= size
            rest[None]		= each

        super( EPATH, self ).__init__( name=name, initial=init, **kwds )

    @classmethod
    def produce( cls, data ):
        """Produce an encoded EtherNet/IP EPATH message from the supplied path data.  For example,
        here is an encoding a 8-bit instance ID 0x06, and ending with a 32-bit element ID
        0x04030201:
    
           byte:	0	1	2    ... N-6	N-5	N-4	N-3	N-2	N-1	N
                    <N/2>	0x24	0x06 ... 0x25	0x00	0x01	0x02	0x03	0x04
    
        Optionally pad the size (eg. for Route Paths).

        An Falsey 'data' results in an EPATH indicating a 0 size.

        Supports either { "segment": [<path>] } or just [<path>].

        """
        segment			= data # default to iterable of path elements
        if hasattr( data, 'get' ):
            segment		= data.get( 'segment', [] ) # handles dict w/ empty path

        result			= b''
        for seg in segment:
            found			= False
            for segnam, segtyp in cls.SEGMENTS.items():
                if segnam not in seg:
                    continue
                found		= True
                segval		= seg[segnam]
                # An ANSI Extended Symbolic segment?
                if segnam == 'symbolic':
                    result     += USINT.produce( segtyp )
                    encoded     = segval.encode( 'iso-8859-1' )
                    seglen	= len( encoded )
                    result     += USINT.produce( seglen )
                    result     += encoded
                    if seglen % 2:
                        result += USINT.produce( 0 )
                    break

                # A Port/Link segment?  Ensure port is in the proper (1,0x0F) or (0x10,0xFFFF)
                if segnam == 'port':
                    assert 'link' in seg, \
                        "A path port segment requires a link #/address: %s" % ( seg )
                    assert seg.port > 0, \
                        "A path port must be greater than zero"
                    port, pext	= (seg.port, 0) if seg.port < 0x0F else (0x0F, seg.port)
                    assert isinstance( seg.link, ( int, type_str_base )), \
                        "A path port link must be either an integer or a address string: % ( seg )"
                    if type( seg.link ) is int:
                        # 0x0_ port, optional extended port#, int link
                        result += USINT.produce( port )
                        if pext:
                            result += UINT.produce( pext )
                        result += USINT.produce( seg.link )
                    else:
                        # 0x1_ port, link size, optional extended port, link string, optional pad
                        result += USINT.produce( port | 0x10 )
                        encoded	= seg.link.encode( 'iso-8859-1' )
                        result += USINT.produce( len( encoded ))
                        if pext:
                            result += UINT.produce( pext )
                        result += encoded
                        if len( encoded ) % 2:
                            result += b'\00'
                    break

                # A numeric path segment; class, instance/connection, attribute, element:
                if segval <= 0xff:
                    result     += USINT.produce( segtyp )
                    result     += USINT.produce( segval )
                elif segval <= 0xffff:
                    result     += USINT.produce( segtyp + 1 )
                    result     += USINT.produce( 0 )
                    result     += UINT.produce( segval )
                elif segval <= 0xffffffff and segnam == 'element':
                    result     += USINT.produce( segtyp + 2 )
                    result     += USINT.produce( 0 )
                    result     += UDINT.produce( segval )
                else:
                    assert False, "Invalid value for numeric EPATH segment %r == %d: %r" % (
                        segnam, segval, data )
                break
            assert found, "Invalid EPATH segment %r found in %r" % ( segnam, data )
            assert len( result ) % 2 == 0, \
                "Failed to retain even EPATH word length after %r in %r" % ( segnam, data )

        if cls.SINGLE:
            return result
        return USINT.produce( len( result ) // 2 ) + ( b'\x00' if cls.PADSIZE else b'' ) + result


class EPATH_padded( EPATH ):
    PADSIZE			= True


class EPATH_single( EPATH ):
    """Sometimes it is known that an EPATH contains only a single segment (eg. a single port/link
    specification).  In these cases, the parser doesn't require an EPATH size to limit the number of
    EPATH segments to parse.

    """
    SINGLE			= True


class route_path( EPATH_padded ):
    """Unconnected message route path.  

        .route_path.size		USINT		1 (in words)
        (pad)				USINT		1 (pad)
        .route_path.segment 		...

    """


class unconnected_send( dfa ):
    """See CIP Specification, Vol. 1, Chapter 3, 3-5.26.  A Message Router object must process
    Unconnected Send (0x52) requests, which carry a message and a routing path, allowing delivery
    of the message to a port.  When the route_path contains only a port, then the message is
    delivered the attached processor; otherwise, it needs to be forwarded; we do not handle these
    cases yet.

        .unconnected_send.service	USINT 		0x52
        .unconnected_send.path		EPATH		? object handling parsing (message router)
        .unconnected_send.priority	USINT
        .unconnected_send.timeout_ticks	USINT
        .unconnected_send.length	UINT
        .unconnected_send.<parser>      ...	     .length
                                        USINT		1 	optional pad, if length is odd)
        .unconnected_send.route_path	EPATH (padded; one byte between EPATH size and EPATH payload)


    We cannot parse the encapsulated message, because it may not be destined for local Objects, so
    we may not have the correct parser; leave it in .octets.

    If we see a C*Logix 0x52 Unconnected Send encapsulation, parse it routing.  Otherwise, any other
    requests/replies (eg. simple Get Attributes All Request (0x01) and Reply (0x81) to non-routing
    CIP devices) are passed through unparsed.

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        slct			= octets_noop(	'sel_unc' )

        usnd			= USINT(	context='service' )
        usnd[True]	= path	= EPATH(	context='path' )
        # All Unconnected Send (0x52) encapsulated request.input have a length, followed by an
        # optional pad, and then a route path.
        path[True]	= prio	= USINT(	context='priority' )
        prio[True]	= timo	= USINT(	context='timeout_ticks' )
        timo[True]	= leng	= UINT(		context='length' )
        leng[None]	= mesg	= octets( 	context='request', repeat='..length' )

        # Route segments, like path but for hops/links/keys...
        rout			= route_path( terminal=True )

        # If length is odd, drop the pad byte after the message, and then parse the route_path
        pad0			= octets_drop( 'pad', 	repeat=1 )
        pad0[None]		= rout

        mesg[None]		= decide(	'pad',	state=pad0,
                            predicate=lambda path=None, data=None, **kwds: data[path+'.length'] % 2 )

        # But, if no pad, go parse the route path
        mesg[None]		= rout

        # So; 0x52 Unconnected Send parses a request with a Route Path, but anything else is just
        # an opaque encapsulated request; just copy all remaining bytes to the request.input.
        slct[b'\x52'[0]]	= usnd
        slct[True]	= othr	= octets(	context='request', terminal=True )
        othr[True]		= othr

        super( unconnected_send, self ).__init__( name=name, initial=slct, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        if data.get( 'service' ) == 0x52:
            result	       += USINT.produce( data.service )
            result	       += EPATH.produce( data.path )
            result	       += USINT.produce( data.priority )
            result	       += USINT.produce( data.timeout_ticks )
            result	       += UINT.produce( len( data.request.input ))
            result	       += octets_encode( data.request.input )
            if len( data.request.input ) % 2:
                result	       += b'\x00'
            result	       += route_path.produce( data.get( 'route_path', {} ))
        else:
            # Not an Unconnected Send; just return the encapsulated request.input payload
            result	       += octets_encode( data.request.input )
        return result


class communications_service( dfa ):
    """The ListServices response contains a CPF item list containing one item: a "Communications"
    type_id 0x0100, indicating that the device supports encapsulation of CIP packets.  These CPF
    items contain the standard type_id and length, followed by:

       .CPF.item[0].version		UINT		2	Version of protocol (shall be 1)
       .CPF.item[0].capability		UINT		2	Capability flags
       .CPF.item[0].service_name	USINT[*]    .length-8	Name of service + NUL (eg. "Communications\0")

    +-------------+---------------------------------------------------------------+
    | Flag        | Description                                                   |
    +-------------+---------------------------------------------------------------+
    | Bits 0 - 4  | Reserved for legacy usage 1                                   |
    | Bit 5       | If the device supports EtherNet/IP encapsulation of CIP       |
    |             | this bit shall be set (=1); otherwise, it shall be clear (=0) |
    | Bits 6 - 7  | Reserved for legacy usage 1                                   |
    | Bit 8       | Supports CIP transport class 0 or 1 UDP-based connections     |
    | Bits 9 - 15 | Reserved for future expansion                                 |
    +-------------+---------------------------------------------------------------+


    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        vers			= UINT(	context='version' )
        vers[True]	= capa	= UINT(	context='capability' )

        capa[True]	= svnm	= string_bytes( 'service_name',
                                        context='service_name', greedy=True,
                                        initial='[^\x00]*', decode='iso-8859-1' )
        svnm[b'\0'[0]]		= octets_drop( 'NUL', repeat=1, terminal=True )

        super( communications_service, self ).__init__( name=name, initial=vers, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result	       	       += UINT.produce( data.version )
        result	               += UINT.produce( data.capability )
        result		       += data.service_name.encode( 'iso-8859-1' )
        result		       += b'\0'
        return result


class identity_object( dfa ):
    """The ListIdentity response contains a CPF item list containing one item: an "Identity Object "
    type_id 0x000C.

    The Identity Item in the CPF list consists of the standard .type_id of 0x000C, a .length, and
    then a payload containing a protocol version and socket address, and then identity data that
    follows the format of a Get Attributes All of the Identity Object, instance 1, thus containing
    at least (could be more, if the Identity Object's Get Attributes All returns more):

    | Parameter              | Type      | Description                                      |
    |------------------------+-----------+--------------------------------------------------|
    | Item Type Code         | UINT      | 0x000C                                           |
    | Item Length            | UINT      | Bytes to follow                                  |
    | Encap. Proto. Version  | UINT      | Version supported (same as Register Session)     |
    | Socket Address         | STRUCT OF | (big-endian)                                     |
    |                        | INT       | sin_family                                       |
    |                        | UINT      | sin_port                                         |
    |                        | UDINT     | sin_addr                                         |
    |                        | USINT[8]  | sin_zero                                         |
    | Vendor ID              | UINT      | Device manufacturer's Vendor ID                  |
    | Device Type            | UINT      | Device Type of product                           |
    | Product Code           | UINT      | Produce Code assigned, w/ respect to Device Type |
    | Revision               | UINT      | Device Revision                                  |
    | Status                 | WORD      | Current status of device                         |
    | Serial Number          | UDINT     | Serial number of device                          |
    | Product Name           | SSTRING   | Human readable description of device             |
    | State                  | USINT     | Current state of device                          |

    Here is a UDP ListIdentity 0x0063 == 'c\x00...' request (spaced with _ so that each symbol takes
    4 spaces):

        c___\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00

    And a response from a PowerFlex 753 AC Drive Controller:

                  ------- incorrect EtherNet/IP CIP payload size: should be \x48\x00 == 72!
                  ||
                  vv
        c___\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
                        -- incorrect EtherNet/IP CIP CPF item payload size: should b <___\x00 == 60!
                        |
                        v
        \x01\x00\x0c\x00'___\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00
        \x01\x00{___\x00\x90\x04\x0b\x01a___\x05\x15\x1dI___\x80 ___P___o___w___e___r___F___l___e___x___
         ___7___5___3___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___ ___\xff

    Note that this EtherNet/IP CIP response encapsulation is, in fact, incorrect: it specifies a 0
    length.  It is from an official Allen Bradley PowerFlex 753 product, with a 20-COMM-E
    EtherNet/IP CIP interface card.  Since it is sent via UDP, the entire request appears in a
    single indivisible packet, so we can deduce the actual message payload size from the total size
    of the UDP datagram, minus the 24-byte EtherNet/IP encapsulation header.  This is, however, not
    documented EtherNet/IP CIP protocol behaviour (perhaps since it's insane).  So, its just a bug.
    It prevents a correctly implemented parser from receiving the List Identity reply, though...

    Here's a response from a Logix 1769 PLC, with correct EtherNet/IP CIP frame sizes:

        c___\x00E___\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
        \x01\x00\x0c\x00?___\x00\x01\x00\x00\x02\xaf\x12\n__\xa1\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00
        \x01\x00\x0e\x00\x95\x00\x1b\x0b0___\x00^___3___\x1e\xc0\x1d1___7___6___9___-___L___2___4___E___
        R___-___Q___B___1___B___/___A___ ___L___O___G___I___X___5___3___2___4___E___R___\x03

    """
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        vers			= UINT(	context='version' )
        vers[True]	= sfam	= INT_network(
                                        context='sin_family' )
        sfam[True]	= sprt	= UINT_network(
                                        context='sin_port' )
        sprt[True]	= sadd	= IPADDR_network(
                                        context='sin_addr' )
        sadd[True]	= szro	= octets_drop( context='sin_zero', repeat=8 )
        szro[True]	= vndr	= UINT(	context='vendor_id' )
        vndr[True]	= dvtp	= UINT(	context='device_type' )
        dvtp[True]	= prod	= UINT( context='product_code' )
        prod[True]	= revi	= UINT( context='product_revision' )
        revi[True]	= stts	= WORD(	context='status_word' )		# Should be WORD
        stts[True]	= srnm	= UDINT( context='serial_number' )
        srnm[True]	= prnm	= SSTRING( context='product_name' )

        # May end here, b/c of CPF framing errors (eg. PowerFlex)!  However, may continue on.
        # Either way, we want to move the parsed SSTRING product_name.string up one level, so that
        # product_name is a string.  So, prepare to parse whatever is after product_name...
        more			= state( 'done',
                                               terminal=True )		# We're OK with ending here...
        more[True]	= stat	= USINT( context='state',		# May end here, too...
                                         terminal=True )
        stat[True]	= xtra	= octets( context='extra', octets_extension='',	# ... any extra data are ignored
                                          terminal=True )
        xtra[True]	= xtra

        # so, handle moving .product_name.string up to product_name, then try for more
        prnm[None]		= move_if( 'movsstring',source='.product_name.string',
                                                   destination='.product_name',
                                           state=more )

        super( identity_object, self ).__init__( name=name, initial=vers, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result	       	       += UINT.produce( data.version )
        result	               += INT_network.produce( data.sin_family )
        result	               += UINT_network.produce( data.sin_port )
        result	               += IPADDR_network.produce( data.sin_addr )
        result		       += b'\0' * 8
        result		       += UINT.produce( data.vendor_id )
        result		       += UINT.produce( data.device_type )
        result		       += UINT.produce( data.product_code )
        result		       += UINT.produce( data.product_revision )
        result		       += WORD.produce( data.status_word )
        result		       += UDINT.produce( data.serial_number )
        result		       += SSTRING.produce( data.product_name )
        result		       += USINT.produce( data.state		# EtherNet/IP CIP Vol 2, Table 2-4.4:
                                                 if 'state' in data	# If not implemented,
                                                 else 0xFF )		# the value shall be 0xFF
        if 'extra' in data and data.extra:
            result	       += bytes(bytearray( data.extra ))
        return result


class legacy_CPF_0x0001( dfa ):
    """EtherNet/IP CIP command 0x0001 carries A CPF payload with one entry -- this undocumented
    structure carries the IP address of the host.  It might be an early, undocumented version of
    List Identity's IP address payload?

        0030                     01 00 2a 00 00 00 00 00 00 00        ..*.......
        0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00  ................
                                                         ^^^^^ -- 1 CPF element
        0050   01 00 24 00 01 00 00 00 00 02 af 12 c0 a8 05 fd  ..$.............
               ^^^^^ -- type 1
                     ^^^^^ -- length 0x24
                           ^^^^^ -- version 1?
                                 ^^^^^ -- protocol 0?
                                       ^^^^^ -- family 2 AF_INET
                                             ^^^^^ -- port 44818
                                                   ^^^^^ -- 192.168.5.253 in binary, big-endian
        0060   00 00 00 00 00 00 00 00 31 39 32 2e 31 36 38 2e  ........192.168.
               ^^^^^^^^^^^^^^^^^^^^^^^ -- 8 bytes of 0x00 fill
                                       ^^... -- 16 byte ASCII dotted-quad, 0-padded on end
        0070   35 2e 32 35 33 00 00 00                          5.253...

    It seems to contain the binary big-endian byte ordered struct sockaddr_in (sin_family, sin_port,
    sin_addr and sin_zero[8]), followed by the ASCII dotted-quad interpretation of the sin_addr of
    up to 15 bytes (eg. "123.123.123.123", NUL-padded on end if less than 15 bytes).

    The only indeterminate part is the first 4 bytes following the length: 0x0001 (little-endian 1)
    and 0x0000.  This could be a version number, but the meaning of the following zero is unknown.

    """
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        vers			= UINT(	context='version' )
        vers[True]	= unkn	= UINT(	context='unknown_1' )
        unkn[True]	= sfam	= INT_network(
                                        context='sin_family' )
        sfam[True]	= sprt	= UINT_network(
                                        context='sin_port' )
        sprt[True]	= sadd	= IPADDR_network(
                                        context='sin_addr' )
        sadd[True]	= szro	= octets_drop( context='sin_zero', repeat=8 )
        szro[True]	= addr	= string_bytes( 'ip_address', context='ip_address',
                                        greedy=True, initial='[^\x00]*', decode='iso-8859-1',
                                        terminal=True )
        addr[True]	= nuls	= octets_drop( 'NUL', repeat=1,
                                        terminal=True )
        nuls[True]	= nuls

        super( legacy_CPF_0x0001, self ).__init__( name=name, initial=vers, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result	       	       += UINT.produce( data.get( 'version', 1 ))
        result	       	       += UINT.produce( data.get( 'unknown_1', 0 ))
        result	               += INT_network.produce( data.sin_family )
        result	               += UINT_network.produce( data.sin_port )
        # Contains IP information in sin_addr (network byte-order) and/or ip_address (string).
        # Accept both/either in data (eg. product sin_addr from ip_address or vice versa)
        sin_addr		= data.sin_addr if 'sin_addr' in data else data.ip_address
        sin_addr_octets		= IPADDR_network.produce( sin_addr ) # accept 32-bit int or IP address string
        result	               += sin_addr_octets
        result		       += b'\0' * 8 # sin_zero

        # If data.ip_address not supplied, convert the 32-bit host-ordered IP address in ip_octets
        # to a string using the IPADDR_network parser.
        ip_address		= data.get( 'ip_address' )
        if ip_address is None:
            ip_address_data	= dotdict()
            with IPADDR_network() as machine:
                with contextlib.closing( machine.run(
                        source=sin_addr_octets, data=ip_address_data )) as engine:
                    for m,s in engine:
                        pass
            ip_address		= ip_address_data.IPADDR_network

        # Use the SSTRING producer to properly encode and NUL-pad the string to 16 characters.
        # We'll use the produced SSTRING, discarding the length.
        sstring_data		= dotdict( length=16, string=ip_address )
        sstring_octets		= SSTRING.produce( sstring_data )

        result		       += sstring_octets[1:]
        return result


class connection_ID( dfa ):
    """EtherNet/IP CIP command 0x00a1 carries a CPF payload with one entry -- a 4-byte 'connection' ID.

    """
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        addr			= UDINT( context='connection',
                                         terminal=True )
        super( connection_ID, self ).__init__( name=name, initial=addr, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result	       	       += UDINT.produce( data.get( 'connection', 0 ))
        return result


class connection_data( dfa ):
    """EtherNet/IP CIP command 0x00b1 carries a CPF payload with a number of payload bytes of
    'request.input' data, after a 2-byte sequence number.

    """
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        sequ			= UINT( 	context='sequence' )
        sequ[True]	= data	= octets( 	context='request', # repeat='..length', # length - 2, actually: so don't check
                                                terminal=True )
        data[True]		= data # all remaining data...

        super( connection_data, self ).__init__( name=name, initial=sequ, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result		       += UINT.produce( data.sequence )
        result		       += octets_encode( data.request.input )
        return result


class CPF( dfa ):

    """A SendRRData Common Packet Format specifies the number and type of the encapsulated CIP
    address items or data items that follow:

    	.CPF.count			UINT		2 	Number of items
        .CPF.item[0].type_id		UINT		2	Type ID of item encapsulated
        .CPF.item[0].length		UINT		2	Length of item encapsulated
        .CPF.item[0].<parser>...

    Parse the count, and then each CPF item into CPF.item_temp, and (after parsing) moves it to
    CPF.item[x].  If count is 0, then no items are parsed, and an empty item == [] list is returned.
    

    A dictionary of parsers for various CPF types must be provided.  Any CPF item with a length > 0
    will be parsed using the instance of the parser appropriate to its type: { 0x00b2: <class>, }

    Here is a subset of the types of CPF items to expect:

        0x0000: 	NULL Address (used w/Unconnected Messages)
        0x0001:		EtherNet/IP CIP Legacy command 0x0001 (undocumented) reply
        0x00b2:		Unconnected Messages (eg. used within CIP command SendRRData)
        0x00a1:		Address for connection based requests
        0x00b1:		Connected Transport packet (eg. used within CIP command SendUnitData)
        0x0100:		ListServices response
        0x000C:		ListIdentity response
    
    Presently we only handle NULL Address and Unconnected Messages, and ListServices
    (communications_service), and ListIdentity (identity_object).

    """
    ITEM_PARSERS		= {
        0x0001:	legacy_CPF_0x0001,	# used in EtherNet/IP Legacy command 0x0001
        0x00a1:	connection_ID,		# Connected session ID; used in PCCC transport, for example
        0x00b1:	connection_data,	#   Payload data for a connected session; sequence count + request.input
        0x00b2:	unconnected_send,	# used in SendRRData request/response
        0x0100:	communications_service, # used in ListServices response
        0x000c:	identity_object,	# used in ListIdentity response
    }

    def __init__( self, name=None, **kwds ):
        """Parse CPF list items 'til .count reached, which should be simultaneous with symbol exhaustion, if
        caller specified a symbol limit.

        A CPF list may be completely empty (ie. not even a 0 count), for certain use-cases.  For
        example, a EtherNet/IP CIP ListServices request consists solely of a CIP frame consisting of
        a CPF list containing a Communications Service item.  However, the request is simply missing
        the CPF list -- completely.  So, make the initial state produce an empty CPF dotdict.

        """
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        # A number, and then each CPF item consistes of a type, length and then parsable data.  
        ityp			= UINT( 			context='type_id' )
        ityp[True]	= ilen	= UINT( 			context='length' )
        ilen[None]		= decide(	'empty',
                                predicate=lambda path=None, data=None, **kwds: not data[path].length,
                                                state=octets_noop( 'done', terminal=True ))

        # Prepare a parser for each recognized CPF item type.  It must establish one level of
        # context, because we need to pass it a limit='..length' denoting the length we just parsed.
        # Note that we must capture the value of 'typ' in the lambda definition as a keyword
        # parameter (which is evaluated at once), or it will take the final value of outer 'typ'
        for typ,cls in self.ITEM_PARSERS.items():
            ilen[None]		= decide( cls.__name__, state=cls( terminal=True, limit='..length' ),
                        predicate=lambda path=None, data=None, typ=typ, **kwds: data[path].type_id == typ )

        # If we don't recognize the CPF item type, just parse remainder into .input (so we could re-generate)
        ilen[None]	= urec	= octets( 	'unrecognized',	context=None,
                                                terminal=True )
        urec[True]		= urec

        # Each item is collected into '.item__', 'til no more input available, and then moved into
        # place into '.item' (init to [])
        item			= dfa(		'each', 	context='item__',
                                                initial=ityp )
        item[None] 		= move_if( 	'move', 	source='.item__',
                                           destination='.item', initializer=lambda **kwds: [] )
        item[None]		= state( 	'done', terminal=True )

        # Parse count, and then exactly .count CPF items (or just an empty dict, if nothing).  If
        # .count is 0, we're done (we don't even initialize .items to []).
        emty			= octets_noop(	'empty',	terminal=True )
        emty.initial[None]	= move_if( 	'mark',		initializer={} )
        emty[True]	= loop	= UINT( 			context='count' )
        loop[None]		= decide(	'empty',
                        state=state( 'done', terminal=True ),
                        predicate=lambda path=None, data=None, **kwds: data[path+'.count'] == 0 )
        loop[None]		= dfa(		'all',
                                                initial=item,	repeat='.count',
                                                terminal=True )

        super( CPF, self ).__init__( name=name, initial=emty, **kwds )

    @classmethod
    def produce( cls, data ):
        """Regenerate a CPF message structure.  An empty CPF indicates no CPF at all.  If there's a .item
        list; any provided .count is ignored.  Otherwise, it must contain a .count == 0, indicating
        a CPF container with no entries.

        """
        result			= b''
        if not data:
            return result # An empty CPF -- indicates no CPF segment present at all
        assert 'item' in data or ( 'count' in data and data.count == 0 ), \
            "Invalid CPF structure: no .item list, or .count != 0: %r" % ( data )
        segments		= data.item if 'item' in data else []
        result		       += UINT.produce( len( segments ))
        for item in segments:
            result	       += UINT.produce( item.type_id )
            if item.type_id in cls.ITEM_PARSERS:
                itmprs		= cls.ITEM_PARSERS[item.type_id] # eg 'unconnected_send', 'communications_service'
                item.input	= bytearray( itmprs.produce( item[itmprs.__name__] ))
            if 'input' in item:
                result	       += UINT.produce( len( item.input ))
                result	       += octets_encode( item.input )
            else:
                result	       += UINT.produce( 0 )
        return result


class send_data( dfa ):
    """Handle Connected (SendUnitData) or Unconnected (SendRRData) Send Data request/reply."""
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        ifce			= UDINT(			context='interface' )
        ifce[True]	= timo	= UINT(				context='timeout' )
        timo[True]		= CPF( terminal=True )

        super( send_data, self ).__init__( name=name, initial=ifce, **kwds )

    @staticmethod
    def produce( data ):
        result			= b''
        result		       += UDINT.produce( data.interface )
        result		       += UINT.produce(  data.timeout )
        result		       += CPF.produce( data.CPF )
        return result


class register( dfa ):
    """Handle RegisterSession request/reply (identical)"""
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        prto			= UINT(				context='protocol_version' )
        prto[True]		= UINT(				context='options',
                                                                terminal=True )

        super( register, self ).__init__( name=name, initial=prto, **kwds )

    @staticmethod
    def produce( data ):
        result			= b''
        result		       += UINT.produce(	data.protocol_version )
        result		       += UINT.produce(	data.options )
        return result


class unregister( octets_noop ):
    """Handle UnregisterSession request (no reply; session dropped)"""
    def terminate( self, exception, machine=None, path=None, data=None ):
        """Just create an empty value to indicate the command was received."""
        # Only operate if we have completed without exception.
        super( unregister, self ).terminate(
            exception=exception, machine=machine, path=path, data=data )
        if exception is not None:
            return
        ours			= self.context( path=path )
        data[ours]		= True


class CPF_service( dfa ):
    """Handle Service request/reply that are encoded as a CPF list.  We must deduce whether we are
    parsing a request or a reply.  The request will have a 0 length; the reply (which must contain a
    CPF with at least an item count) will have a non-zero length.

    Even if the request is empty, we want to produce 'CIP.<service_name>.CPF'.

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        svcs			= CPF( terminal=True )

        super( CPF_service, self ).__init__( name=name, initial=svcs, **kwds )

    @staticmethod
    def produce( data ):
        result			= b''
        if data and 'CPF' in data:
            result	       += CPF.produce( data.CPF )
        return result


class list_interfaces( CPF_service ):
    pass

class list_identity( CPF_service ):
    pass

class list_services( CPF_service ):
    pass

class legacy( CPF_service ):
    """Any "Legacy" EtherNet/IP CIP command codes that may contain CPF payloads."""
    pass


class CIP( dfa ):
    """The EtherNet/IP CIP Encapsulation transports various commands back and forth between a
    transmitter and a receiver.  There is no explicit designation of a request or a reply.  All have
    a common prefix; an EtherNet/IP header and encapsulated command (already parsed elsewhere).  We expect
    it to look something like this:

        enip.command			UINT		2
        enip.length			UINT		2
        enip.session			UDINT		4
        enip.status			UDINT		4
        enip.sender_context		octets[8]	8
        enip.options			UDINT		4
        enip.input 			octets[*]       .length

    We'll parse all our commands into the .CIP context (by default):

        enip.CIP...

    This parser is probably used to process that fixed-length encapsulated .input stream; however,
    we can't depend on this; we will select the appropriate sub-parser using '..command', and will
    limit our symbols to '..length'.

    The supported command values and their formats are:

    Legacy 0x0001               0x0001

        0000   f0 76 1c e0 d4 ec 08 5b 0e ee a5 c0 08 00 45 00  .v.....[......E.
        0010   00 6a 17 21 00 00 7e 06 d4 37 c0 a8 05 fd 0a 10  .j.!..~..7......
        0020   80 80 af 12 c5 64 18 b3 61 00 e9 ad b8 78 50 18  .....d..a....xP.
        0030   07 d0 97 49 00 00 01 00 2a 00 00 00 00 00 00 00  ...I....*.......
        0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00  ................
        0050   01 00 24 00 01 00 00 00 00 02 af 12 c0 a8 05 fd  ..$.............
        0060   00 00 00 00 00 00 00 00 31 39 32 2e 31 36 38 2e  ........192.168.
        0070   35 2e 32 35 33 00 00 00                          5.253...]

    ListIdentity		0x0063

    ListInterfaces		0x0064

    RegisterSession		0x0065
        .CIP.register.protocol_version	UINT
        .CIP.register.options		UINT

    UnregisterSession		0x0066
        .CIP.unregister

    ListServices		0x0004
        .CIP.list_services.CPF...	...

    SendRRData			0x006f
    SendUnitData		0x0070
        .CIP.send_data.inteface		UDINT
        .CIP.send_data.timeout		UINT
        .CIP.send_data.CPF...

    """
    COMMAND_PARSERS		= {
        # Unknown Legacy commands w/ CPF payloads
        (0x0001,):		legacy,		# many commands may use this parser, w/ 'CIP.legacy' payloads
	# Usually only seen via UDP/IP, but valid for TCP/IP
        (0x0004,):		list_services,
        (0x0063,):		list_identity,
        (0x0064,):		list_interfaces,
	# Valid for TCP/IP only
        (0x0065,):		register,
        (0x0066,):		unregister,
        (0x006f,0x0070):	send_data,	# 0x006f (SendRRData) is default if CIP.send_data seen
    }
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        slct			= octets_noop(	'sel_CIP' )
        for cmd,cls in self.COMMAND_PARSERS.items():
            slct[None]		= decide( cls.__name__,
                    state=cls( limit='...length', terminal=True ),
                    predicate=lambda path=None, data=None, cmd=cmd, **kwds: data[path+'..command'] in cmd )
        super( CIP, self ).__init__( name=name, initial=slct, **kwds )

    @classmethod
    def produce( cls, data ):
        """Expects to find a recognized .command value and/or and parsed .CIP.register,
        .CIP.unregister, .etc. in the provided data artifact as produced by our parser.  Produces
        the bytes string encoding the command.  There is little difference between a request and a
        response at this level, except that in a request the CIP.status is usually 0, while in a
        response it may indicate an error.

        This will recognize/match either:
        1) if .command == a recognized command COMMAND_PARSERS key
        2) if 'CIP.<something>' (where <somethign> is the )matches the 

        """
        for cmd,cmdcls in cls.COMMAND_PARSERS.items():
            if ( data.get( 'command' ) in cmd
                 or ( 'CIP.' + cmdcls.__name__  in data
                      and data.setdefault( 'command', cmd[0] ) in cmd )):
                return cmdcls.produce( data['CIP.' + cmdcls.__name__] )
        raise Exception( "Invalid CIP request/reply format: %r" % data )


class typed_data( dfa ):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within the
    data artifact, or an integer data type).  Data elements are parsed 'til exhaustion of input, so
    the caller should use limit= to define the limits of the data in the source symbol input stream;
    only complete data items must be parsed, so this must be exact, and match the specified data
    type.

    If no data is provided (or due to a limit=0), no data will be parsed, nor will .data be
    initialized to [].

    The known data types are:

    data type	supported	type value	  size

    BOOL 			= 0x00c1	# 1 byte (0x0_c1, _=[0-7] indicates relevant bit)
    SINT	yes		= 0x00c2	# 1 byte
    INT		yes		= 0x00c3	# 2 bytes
    DINT	yes		= 0x00c4	# 4 bytes
    REAL	yes		= 0x00ca	# 4 bytes
    LREAL	yes		= 0x00cb	# 8 bytes
    USINT	yes		= 0x00c6	# 1 byte
    UINT	yes		= 0x00c7	# 2 bytes
    WORD			= 0x00d2	# 2 byte (16-bit boolean array)
    UDINT	yes		= 0x00c8	# 4 bytes
    DWORD			= 0x00d3	# 4 byte (32-bit boolean array)
    LINT			= 0x00c5	# 8 byte
    SSTRING	yes		= 0x00da	# 1 byte length + <length> data
    STRING	yes		= 0x00d0	# 2 byte length + <length> data (rounded up to 2 bytes)
    STRUCT	yes		= 0x02a0	# 2 byte structure_tag + USINT data

    If a STRUCT is indicated by tag_type, then a structure_tag is required.  If not supplied as a
    numeric or string, it will be parsed into .structure_tag.
    """
    TYPES_SUPPORTED		= {
        BOOL.tag_type:  	BOOL,
        SINT.tag_type:		SINT,
        USINT.tag_type:		USINT,
        INT.tag_type:		INT,
        UINT.tag_type:		UINT,
        DINT.tag_type:		DINT,
        UDINT.tag_type:		UDINT,
        LINT.tag_type:		LINT,
        ULINT.tag_type:		ULINT,
        REAL.tag_type:		REAL,
        LREAL.tag_type:		LREAL,
        SSTRING.tag_type:	SSTRING,
        STRING.tag_type:	STRING,
        STRUCT.tag_type:	STRUCT,
    }

    def __init__( self, name=None, tag_type=None, structure_tag=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        assert tag_type and isinstance( tag_type, (int,type_str_base)), \
            "Must specify a numeric (or relative path to) the CIP data type; found: %r" % tag_type
        if structure_tag:
            assert structure_tag and isinstance( structure_tag, (int,type_str_base)), \
                "Must specify a numeric (or relative path to) the STRUCT handle; found: %r" % structure_tag

        slct			= octets_noop(	'sel_type' )
        
        i_8d			= octets_noop(	'end_8bit',
                                                terminal=True )
        i_8d[True]	= i_8p	= SINT()
        i_8p[None]		= move_if( 	'mov_8bit',	source='.SINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i_8d )

        u_8d			= octets_noop(	'end_8bitu',
                                                terminal=True )
        u_8d[True]	= u_8p	= USINT()
        u_8p[None]		= move_if( 	'mov_8bitu',	source='.USINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u_8d )

        u_1d			= octets_noop(	'end_1bitu',
                                                terminal=True )
        u_1d[True]	= u_1p	= BOOL()
        u_1p[None]		= move_if( 	'mov_1bitu',	source='.BOOL',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u_1d )

        i16d			= octets_noop(	'end16bit',
                                                terminal=True )
        i16d[True]	= i16p	= INT()
        i16p[None]		= move_if( 	'mov16bit',	source='.INT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i16d )

        u16d			= octets_noop(	'end16bitu',
                                                terminal=True )
        u16d[True]	= u16p	= UINT()
        u16p[None]		= move_if( 	'mov16bitu',	source='.UINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u16d )

        i32d			= octets_noop(	'end32bit',
                                                terminal=True )
        i32d[True]	= i32p	= DINT()
        i32p[None]		= move_if( 	'mov32bit',	source='.DINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i32d )

        u32d			= octets_noop(	'end32bitu',
                                                terminal=True )
        u32d[True]	= u32p	= UDINT()
        u32p[None]		= move_if( 	'mov32bitu',	source='.UDINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u32d )

        i64d			= octets_noop(	'end64bit',
                                                terminal=True )
        i64d[True]	= i64p	= LINT()
        i64p[None]		= move_if( 	'mov64bit',	source='.LINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i64d )

        u64d			= octets_noop(	'end64bitu',
                                                terminal=True )
        u64d[True]	= u64p	= ULINT()
        u64p[None]		= move_if( 	'mov64bitu',	source='.ULINT',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=u64d )

        fltd			= octets_noop(	'endfloat',
                                                terminal=True )
        fltd[True]	= fltp	= REAL()
        fltp[None]		= move_if( 	'movfloat',	source='.REAL', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=fltd )
        dltd			= octets_noop(	'enddouble',
                                                terminal=True )
        dltd[True]	= dltp	= LREAL()
        dltp[None]		= move_if( 	'movdouble',	source='.LREAL',
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=dltd )
        # Since a parsed "[S]STRING": { "string": "abc", "length": 3 } is multiple layers deep, and we
        # want to completely eliminate the target container in preparation for the next loop, we'll
        # need to move it up one layer, and then into the final target.
        sstd			= octets_noop(	'endsstring',
                                                terminal=True )
        sstd[True]	= sstp	= SSTRING()
        sstp[None]		= move_if( 	'movsstrings',	source='.SSTRING.string',
                                                destination='.SSTRING' )
        sstp[None]		= move_if(      'movsstring',   source='.SSTRING',
                                           destination='.data', initializer=lambda **kwds: [],
                                                state=sstd )

        sttd			= octets_noop(	'end_string',
                                                terminal=True )
        sttd[True]	= sttp	= STRING()
        sttp[None]		= move_if( 	'mov_strings',	source='.STRING.string',
                                                destination='.STRING' )
        sttp[None]		= move_if(      'mov_string',   source='.STRING',
                                           destination='.data', initializer=lambda **kwds: [],
                                                state=sttd )

        # STRUCT data is prefixed by a UINT structure_tag, then parsed raw into .data.  In theory,
        # there could be a .structure_tag followed by no data (eg. if you do a Read Tag Fragmented
        # with an offset to exactly the end of the structure.)  Move the parse { 'STRUCT': { 'data':
        # array( 'B'/'c', []), 'structure_tag': }} up onto the target name eg. 'typed_data' (tidy
        # empty dict as we go).
        # 
        # If the structure_tag has been supplied as either a string (data lookup, relative to path),
        # or a numeric value, we'll parse it with STRUCT (and move it into place, here).  Otherwise,
        # just the STRUCT.data payload will be parsed.
        strt			= STRUCT( structure_tag=structure_tag,
                                          terminal=True )
        if structure_tag is None:
            strt[None]		= move_if( 	'mov_struct',	source='.STRUCT.structure_tag',
                                                destination='.structure_tag' )
        strt[None]		= move_if( 	'mov_struct',	source='.STRUCT.data',
                                                destination='.STRUCT',
                                    initializer=lambda **kwds: dict( input=array.array( type_bytes_array_sumbol, [] )))
        strt[None]		= move_if( 	'mov_struct',	source='.STRUCT',
                                                destination='.data' )

        slct[None]		= decide(	'BOOL',	state=u_1d,
            predicate=lambda path=None, data=None, **kwds: \
                BOOL.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'SINT',	state=i_8d,
            predicate=lambda path=None, data=None, **kwds: \
                SINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'USINT',state=u_8d,
            predicate=lambda path=None, data=None, **kwds: \
                USINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'INT',	state=i16d,
            predicate=lambda path=None, data=None, **kwds: \
                INT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'UINT',	state=u16d,
            predicate=lambda path=None, data=None, **kwds: \
                UINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))

        slct[None]		= decide(	'DINT',	state=i32d,
            predicate=lambda path=None, data=None, **kwds: \
                DINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'UDINT',state=u32d,
            predicate=lambda path=None, data=None, **kwds: \
                UDINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'LINT',	state=i64d,
            predicate=lambda path=None, data=None, **kwds: \
                LINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'ULINT',state=u64d,
            predicate=lambda path=None, data=None, **kwds: \
                ULINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'REAL',	state=fltd,
            predicate=lambda path=None, data=None, **kwds: \
                REAL.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'LREAL', state=dltd,
            predicate=lambda path=None, data=None, **kwds: \
                LREAL.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'SSTRING', state=sstd,
            predicate=lambda path=None, data=None, **kwds: \
                SSTRING.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'STRING', state=sttd,
            predicate=lambda path=None, data=None, **kwds: \
                STRING.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))
        slct[None]		= decide(	'STRUCT', state=strt,
            predicate=lambda path=None, data=None, **kwds: \
                STRUCT.tag_type == ( data[path+tag_type] if isinstance( tag_type, type_str_base ) else tag_type ))

        super( typed_data, self ).__init__( name=name, initial=slct, **kwds )

    @classmethod
    def produce( cls, data, tag_type=None ):
        """Expects to find .type or .tag_type (if tag_type is None) and .data list, and produces the data
        encoded to bytes."""
        if tag_type is None:
            tag_type		= data.get( 'type' ) or data.get( 'tag_type' )
        assert tag_type in cls.TYPES_SUPPORTED, \
            "Unknown tag_type %r: %r" % ( tag_type, data )
        result			= b''
        producer		= cls.TYPES_SUPPORTED[tag_type].produce
        if tag_type == STRUCT.tag_type:
            # Raw .input data payload representing the UDT is expected to have been formed.  A UDT
            # is a monolithic data type that is opaque to us; raw data.data.input is expected.
            result	       += producer( data, structure_tag=True )
        else:
            # Other basic CIP data types; some type of data.data sequence expected
            payload		= data.get( 'data' )
            assert payload is not None and hasattr( payload, '__iter__' ), \
                "Unknown (or no) typed data found for tag_type %r: %r" % ( tag_type, data )
            result	       += b''.join( map( producer, data.get( 'data' )))
        return result

    @classmethod
    def datasize( cls, tag_type, size=1 ):
        """Compute the encoded data size for the specified tag_type and amount of data."""
        assert tag_type in cls.TYPES_SUPPORTED, \
            "Unknown tag_type %r" % ( tag_type )
        return cls.TYPES_SUPPORTED[tag_type].struct_calcsize * size


class status( dfa ):
    """Parses CIP status, and status_ext.size/.data:

        .status				USINT		1
	.status_ext.size		USINT		1
	.status_ext.data		UINT[*]		.size

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        # Parse the status, and status_ext.size
        stat			= USINT( 	'status',	context=None )
        stat[True]	= size	= USINT( 	'_ext.size',	extension='_ext.size' )

        # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .data list
        exts			= UINT(		'ext_status',	extension='.ext_status' )
        exts[None]		= move_if( 	'data',		source='.ext_status',
                                           destination='.data',	initializer=lambda **kwds: [] )
        exts[None]		= state( 	'done', terminal=True )

        # Parse each status_ext.data in a sub-dfa, repeating status_ext.size times
        each			= dfa(		'each',		extension='_ext',
                                                initial=exts,	repeat='_ext.size',
                                                terminal=True )
        # Only enter the state_ext.data dfa if status_ext.size is non-zero
        size[None]		= decide(	'_ext.size', 
                            predicate=lambda path=None, data=None, **kwds: data[path+'_ext.size'],
                                                state=each )
        # Otherwise, we're done!
        size[None]		= octets_noop( 'done', 
                                               terminal=True )
        super( status, self ).__init__( name=name, initial=stat, **kwds )

    @staticmethod
    def produce( data ):
        """Produces a status + extended status size/data.  Expects to find (all optional):

            .status
            .status_ext.size
            .status_ext.data

        If not found, default .status to 0, and assume 0 for everything else.  Extended status only
        allowed for non-zero .status """
        result			= b''
        status			= 0  if 'status' not in data else data.status
        result		       += USINT.produce( status )
        size			= 0  if not status or 'status_ext.size' not in data \
                                  else data.status_ext.size
        exts			= [] if not status or 'status_ext.data' not in data \
                                  else data.status_ext.data
        assert size == len( exts ), \
            "Inconsistent extended status size and data: %r" % data
        result		       += USINT.produce( size )
        result		       += b''.join( UINT.produce( v ) for v in exts )
        return result
