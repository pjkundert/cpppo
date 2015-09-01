#! /usr/bin/env python3

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
enip/parser.py	-- The EtherNet/IP CIP protocol parsers

"""

import array
import json
import logging
import struct
import sys

import cpppo

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
class octets_base( cpppo.dfa_base ):
    """Scan 'repeat' octets (default: 1), using an instance of the provided octets_state class as the
    sub-machine 'initial' state.  The sub-machine has no outgoing transitions, and will terminate
    after accepting and processing exactly one symbol.  Only after all 'repeat' loops will
    self.terminal be True."""
    def __init__( self, name=None, initial=None,
                  octets_name="byte",
                  octets_extension=None, # .input is state_input's default
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, initial=octets_state(
            name=octets_name, terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode, extension=octets_extension ), **kwds )
   

class octets( octets_base, cpppo.state ):
    """Scans 'repeat' octets into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


def octets_encode( value ):
    if isinstance( value, array.array ):
        return value.tostring() if sys.version_info[0] < 3 else value.tobytes()
    elif isinstance( value, bytearray ):
        return bytes( value )
    raise AssertionError( "Unrecognized octets type: %r" % value )


class octets_struct( octets_base, cpppo.state_struct ):
    """Scans octets sufficient to satisfy the specified struct 'format', and then parses it according
    to the supplied struct 'format' (default is class-level struct_format attribute)."""
    def __init__( self, name=None, format=None, **kwds ):
        if format is not None:
            assert isinstance( format, cpppo.type_str_base ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, format=format, 
            repeat=struct.calcsize( self.struct_format if format is None else format ),
                                               **kwds )


class octets_noop( octets_base, cpppo.state ):
    """Does nothing with an octet."""
    def __init__( self, name=None, octets_state=cpppo.state, **kwds ):
        super( octets_noop, self ).__init__(
            name=name, octets_name="noop", octets_state=octets_state, **kwds )


class octets_drop( octets_base, cpppo.state ):
    """Scans 'repeat' octets and drops them."""
    def __init__( self, name=None, octets_state=cpppo.state_drop, **kwds ):
        super( octets_drop, self ).__init__(
            name=name, octets_name="drop", octets_state=octets_state, **kwds )
        

class words_base( cpppo.dfa_base ):
    """Scan 'repeat' 2-byte words (default: 1), convenient when sizes are specified in words."""
    def __init__( self, name=None, initial=None,
                  words_state=cpppo.state_input,
                  words_alphabet=cpppo.type_bytes_iter,
                  words_encoder=None,
                  words_typecode=cpppo.type_bytes_array_symbol, **kwds ):
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
   

class words( words_base, cpppo.state ):
    """Scans 'repeat' words into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


# 
# The basic EtherNet/IP CIP protocol data types
# 
# USINT		-- Parse an 8-bit EtherNet/IP unsigned int 
# USINT.produce	--   and convert a value back to a 8-bit EtherNet/IP unsigned int
# INT		-- Parse a 16-bit EtherNet/IP   signed int 
# UINT		-- Parse a 16-bit EtherNet/IP unsigned int 
# DINT		-- Parse a 32-bit EtherNet/IP   signed int 
# UDINT		-- Parse a 32-bit EtherNet/IP unsigned int 
# 
#     You must provide either a name or a context; if you provide neither, then both default to the
# name of the class.  An instance of any of these types "is" a parser state machine, and has a
# produce method that will re-produce the bytes stream from a (previously parsed) structure.  All
# the simple data types are derived from TYPE, and simply drive from cpppo.state_struct to directly
# parse the data value into the provided context.
# 
#     More complex data types are derived from STRUCT, are derived from cpppo.dfa, and require a
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
    tag_type                    = 0x00c1
    struct_format               = 'B'
    struct_calcsize             = struct.calcsize( struct_format )

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

class UDINT( TYPE ):
    """An EtherNet/IP UDINT; 32-bit unsigned integer"""
    tag_type			= 0x00c8
    struct_format		= '<I'
    struct_calcsize		= struct.calcsize( struct_format )

class DINT( TYPE ):
    """An EtherNet/IP DINT; 32-bit signed integer"""
    tag_type			= 0x00c4
    struct_format		= '<i'
    struct_calcsize		= struct.calcsize( struct_format )

class REAL( TYPE ):
    """An EtherNet/IP INT; 32-bit float"""
    tag_type			= 0x00ca
    struct_format		= '<f'
    struct_calcsize		= struct.calcsize( struct_format )


class STRUCT( cpppo.dfa, cpppo.state ):
    pass

class SSTRING( STRUCT ):
    """Parses/produces a EtherNet/IP Short String:

        .SSTRING.length			USINT		1
        .SSTRING.string			octets[*]	.length

    The produce classmethod accepts this structure, or just a plain Python str, and will output the
    equivalent length+string."""
    tag_type			= None
    def __init__( self, name=None, **kwds):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        leng			= USINT(		context='length' )
        leng[None]		= cpppo.string_bytes(	'string',
                                                        context='string', limit='..length',
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
        
        if isinstance( value, cpppo.type_str_base ):
            value		= cpppo.dotdict( {'string': value } )

        encoded			= value.string.encode( 'iso-8859-1' )
        # If .length doesn't exist or is None, set the length to the actual string length
        actual			= len( encoded )
        desired			= value.setdefault( 'length', actual )
        if desired is None:
            value.length 	= actual
        assert value.length < 256, "SSTRING must be < 256 bytes in length; %r" % value

        result		       += USINT.produce( value.length )
        result		       += encoded[:value.length]
        if actual < value.length:
            result	       += b'\x00' * ( value.length - actual )
        return result

# 
# enip_header	-- Parse an EtherNet/IP header only 
# enip_machine	-- Parses an EtherNet/IP header and encapsulated data payload
# enip_encode	--   and convert parsed EtherNet/IP data back into a message
# 
class enip_header( cpppo.dfa ):
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
        init			= cpppo.state(  "empty",  terminal=True )
        init[True] = cmnd	= UINT(		"command",	context="command" )
        cmnd[True] = leng	= UINT(		"length",	context="length" )
        leng[True] = sess	= UDINT(	"sess_hdl",	context="session_handle" )
        sess[True] = stat	= UDINT(	"status",	context="status" )
        stat[True] = ctxt	= octets(	"sndr_ctx",	context="sender_context",
                                    repeat=8 )
        ctxt[True] 		= UDINT( 	"options",	context="options", terminal=True )

        super( enip_header, self ).__init__( name=name, initial=init, **kwds )


class enip_machine( cpppo.dfa ):
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
    
def enip_format( data, sort_keys=False ):
    """Format a decoded EtherNet/IP data bundle in a (more) human-readable form.  Note that sort_keys=True
    will not work as expected for keys which contain indices: the order of keys like:

        path[0].more
        path[10].more
        path[1].more

    will probably be unexpected.  There is no means by which to specify a custom sorting function.

    """
    return json.dumps( data, indent=4, sort_keys=sort_keys, default=lambda obj: repr( obj ))

# 
# EtherNet/IP CIP Parsing
# 
# See Vol2_1.14.pdf, Chapter 3-2.1 Unconnected Messages, for a simplified overview of parsing.  We
# parse the SendRRData, the CPF encapsulation, and the CPF Null Address and [Un]connected Data
# items, and finally the CIP Message Router Request from the second CPF item.
# 

class move_if( cpppo.decide ):
    """If the predicate is True (the default), then move (either append or assign) data[path+source]
    to data[path+destination], assigning init to it first if the target doesn't yet exist.  Then,
    proceed to the target state.  If no source is provided, only the initialization (if not None)
    occurs.  The destination defaults to the plain path context."""
    def __init__( self, name, source=None, destination=None, initializer=None, **kwds ):
        super( move_if, self ).__init__( name=name, **kwds )
        self.src		= source
        self.dst		= destination if destination else ''
        self.ini		= initializer
        
    def execute( self, truth, machine=None, source=None, path=None, data=None ):
        target			= super( move_if, self ).execute(
            truth, machine=machine, source=source, path=path, data=data )
        if truth:
            pathdst		= path + self.dst
            if self.ini is not None and pathdst not in data:
                ini		= ( self.ini
                                    if not hasattr( self.ini, '__call__' )
                                    else self.ini(
                                            machine=machine, source=source, path=path, data=data ))
                try:
                    data[pathdst]= ini
                finally:
                    log.debug( "%s -- init. data[%r] to %r in data: %s", self, pathdst, ini, data )
            if self.src is not None:
                pathsrc		= path + self.src
                assert pathsrc in data, \
                    "Could not find %r to move to %r in %r" % ( pathsrc, pathdst, data )
                if hasattr( data[pathdst], 'append' ):
                    log.debug( "%s -- append data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                    data[pathdst].append( data.pop( pathsrc ))
                else:
                    log.debug( "%s -- assign data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                    data[pathdst] = data.pop( pathsrc )

        return target


class EPATH( cpppo.dfa ):
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
        # is padded, so insert a state to drop the pad, and chain rest to that instead.
        size		= rest	= USINT(			context='size' )
        if self.PADSIZE:
            size[True]	= rest	= octets_drop( 	'pad', 		repeat=1 )

        # After capturing each segment__ (pseg), move it onto the path segment list, and loop
        pseg			= octets_noop(	'type',		terminal=True )
        # ...segment parsers...
        pmov			= move_if( 	'move',		initializer=lambda **kwds: [],
                                            source='..segment__', destination='..segment',
                                                state=pseg )

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
        syml[None]	= symv	= cpppo.string_bytes(
            					'symbolic',	context='symbolic', limit='.length',
                                                initial='.*',	decode='iso-8859-1' )

        # An odd-length ANSI Extended Symbolic name means an odd total.  Pad
        symo			= octets_drop(	'pad', 		repeat=1 )
        symo[None]		= pmov

        symv[None]		= cpppo.decide(	'odd',
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
            """Discard port values about 0x0F; return True (transition) if remaining port value is 0x0F
            (Optional Extended port)"""
            data[path].port    &= 0x0F
            if data[path].port == 0x0F:
                # Port is extended; discard and prepare to collect new port number
                data[path].port	= cpppo.dotdict()
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
        pnum[None]		= cpppo.decide( 'port_nfix',	predicate=port_fix,
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
        adrv			= cpppo.string_bytes(
            					'link_add',	context='link',	limit='.length',
                                                initial='.*',	decode='iso-8859-1' )

        # An odd-length link address means an odd total.  Pad
        adro			= octets_drop(	'link_pad', 		repeat=1 )
        adro[None]		= pmov

        adrv[None]		= cpppo.decide(	'link_odd',
                predicate=lambda path=None, data=None, **kwds: len( data[path+'.link'] ) % 2,
                                                state=adro )
        adrv[None]		= pmov

        # A big port#; re-scan a UINT into .port (won't work 'til port_fix is called)
        pabg			= UINT(		'port_abg',	context='port' )
        pabg[None]		= adrv

        # 
        padr[True]	= adrl	= USINT(	'link_len',	context='link.length' )
        adrl[None]		= cpppo.decide(	'port_afix', 	predicate=port_fix,
                                                state=pabg )
        adrl[None]	= adrv

        # Parse all segments in a sub-dfa limited by the parsed path.size (in words; double)
        rest[None]		= cpppo.dfa(    'each',		context='segment__',
                                                initial=pseg,	terminal=True,
            limit=lambda path=None, data=None, **kwds: data[path+'..size'] * 2 )

        super( EPATH, self ).__init__( name=name, initial=size, **kwds )

    @classmethod
    def produce( cls, data ):
        """Produce an encoded EtherNet/IP EPATH message from the supplied path data.  For example,
        here is an encoding a 8-bit instance ID 0x06, and ending with a 32-bit element ID
        0x04030201:
    
           byte:	0	1	2    ... N-6	N-5	N-4	N-3	N-2	N-1	N
                    <N/2>	0x24	0x06 ... 0x25	0x00	0x01	0x02	0x03	0x04
    
        Optionally pad the size (eg. for Route Paths).

        """
        
        result			= b''
        for seg in data.segment:
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
                
                # A Port/Link segment?
                if segnam == 'port':
                    assert 'link' in seg, \
                        "A path port segment requires a link #/address: %s" % ( seg )
                    port, pext	= (seg.port, 0) if seg.port < 0x0F else (0x0F, seg.port)
                    assert isinstance( seg.link, ( int, cpppo.type_str_base )), \
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
                    assert False, "Invalid value for numeric EPATH segment %r == %d: %d" % (
                        segnam, segval, data )
                break
            if not found:
                assert False, "Invalid EPATH segment %r found in %r" % ( segnam, data )
            assert len( result ) % 2 == 0, \
                "Failed to retain even EPATH word length after %r in %r" % ( segnam, data )
    
        return USINT.produce( len( result ) // 2 ) + ( b'\x00' if cls.PADSIZE else b'' ) + result


class route_path( EPATH ):
    """Unconnected message route path.  

        .route_path.size		USINT		1 (in words)
        (pad)				USINT		1 (pad)
        .route_path.segment 		...

    """
    PADSIZE			= True


class unconnected_send( cpppo.dfa ):
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

    Any other requests/replies carried in the 
    Get Attributes All Request (0x01) and Reply (0x81).

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        slct			= octets_noop(	'select' )

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

        mesg[None]		= cpppo.decide( 'pad',	state=pad0,
                            predicate=lambda path=None, data=None, **kwds: data[path+'.length'] % 2 )

        # But, if no pad, go parse the route path
        mesg[None]		= rout

        # So; 0x52 Unconnected Send parses an request with a Route Path, but anything else is just
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
            result	       += route_path.produce( data.route_path )
        else:
            # Not an Unconnected Send; just return the encapsulated request.input payload
            result	       += octets_encode( data.request.input )
        return result


class communications_service( cpppo.dfa ):
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

        capa[True]	= svnm	= cpppo.string_bytes( 'service_name',
                                        context='service_name', greedy=True,
                                        initial='[^\x00]*', decode='iso-8859-1' )
        svnm[b'\0'[0]]		= octets_drop( 'NUL', repeat=1, terminal=True )

        '''
        capa[b'\0'[0]]	= done	= octets_drop( 'NUL', repeat=1, terminal=True )
        capa[True]	= svnm	= octets(	context='service_name' )
        svnm[b'\0'[0]]	= done
        svnm[True]	= svnm
        '''

        super( communications_service, self ).__init__( name=name, initial=vers, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        result	       	       += UINT.produce( data.version )
        result	               += UINT.produce( data.capability )
        result		       += data.service_name.encode( 'iso-8859-1' )
        result		       += b'\0'
        return result


class CPF( cpppo.dfa ):

    """A SendRRData Common Packet Format specifies the number and type of the encapsulated CIP
    address items or data items that follow:

    	.CPF.count			UINT		2 	Number of items
        .CPF.item[0].type_id		UINT		2	Type ID of item encapsulated
        .CPF.item[0].length		UINT		2	Length of item encapsulated
        .CPF.item[0].<parser>...

    Parse the count, and then each CPF item into cpf.item_temp, and (after parsing) moves it to
    cpf.item[x].
    

    A dictionary of parsers for various CPF types must be provided.  Any CPF item with a length > 0
    will be parsed using the instance of the parser appropriate to its type: { 0x00b2: <class>, }

    Here is a subset of the types of CPF items to expect:

        0x0000: 	NULL Address (used w/Unconnected Messages)
        0x00b2: 	Unconnected Messages (eg. used within CIP command SendRRData)
        0x00a1:		Address for connection based requests
        0x00b1:		Connected Transport packet (eg. used within CIP command SendUnitData)
        0x0100:		ListServices response

    
    Presently we only handle NULL Address and Unconnected Messages, and ListServices.

    """
    ITEM_PARSERS		= {
            0x00b2:	unconnected_send,	# used in SendRRData request/response
            0x0100:	communications_service, # used in ListServices response
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
        ilen[None]		= cpppo.decide( 'empty',
                                predicate=lambda path=None, data=None, **kwds: not data[path].length,
                                                state=octets_noop( 'done', terminal=True ))

        # Prepare a parser for each recognized CPF item type.  It must establish one level of
        # context, because we need to pass it a limit='..length' denoting the length we just parsed.
        # Note that we must capture the value of 'typ' in the lambda definition as a keyword
        # parameter (which is evaluated at once), or it will take the final value of outer 'typ'
        for typ,cls in self.ITEM_PARSERS.items():
            ilen[None]		= cpppo.decide( cls.__name__, state=cls( terminal=True, limit='..length' ),
                        predicate=lambda path=None, data=None, typ=typ, **kwds: data[path].type_id == typ )

        # If we don't recognize the CPF item type, just parse remainder into .input (so we could re-generate)
        ilen[None]	= urec	= octets( 	'unrecognized',	context=None,
                                                terminal=True )
        urec[True]		= urec

        # Each item is collected into '.item__', 'til no more input available, and then moved into
        # place into '.item' (init to [])
        item			= cpppo.dfa( 	'each', 	context='item__',
                                                initial=ityp )
        item[None] 		= move_if( 	'move', 	source='.item__',
                                           destination='.item', initializer=lambda **kwds: [] )
        item[None]		= cpppo.state( 	'done', terminal=True )

        # Parse count, and then exactly .count CPF items (or just an empty dict, if nothing)
        emty			= octets_noop(	'empty',	terminal=True )
        emty.initial[None]	= move_if( 	'mark',		initializer={} )
        emty[True]	= loop	= UINT( 			context='count' )
        loop[None]		= cpppo.dfa( 	'all', 	
                                                initial=item,	repeat='.count',
                                                terminal=True )

        super( CPF, self ).__init__( name=name, initial=emty, **kwds )

    @classmethod
    def produce( cls, data ):
        """Regenerate a CPF message structure.   """
        result			= b''
        if not data:
            return result # An empty CPF -- indicates no CPF segment present at all
        result		       += UINT.produce( len( data.item ))
        for item in data.item:
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


class send_data( cpppo.dfa ):
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


class register( cpppo.dfa ):
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


class list_services( cpppo.dfa ):
    """Handle ListServices request/reply.  Services are encoded as a CPF list.  We must deduce whether
    we are parsing a request or a reply.  The request will have a 0 length; the reply (which must
    contain a CPF with at least an item count) will have a non-zero length.

    Even if the request is empty, we want to produce 'CIP.list_services.CPF'.
    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        svcs			= CPF( terminal=True )

        super( list_services, self ).__init__( name=name, initial=svcs, **kwds )

    @staticmethod
    def produce( data ):
        result			= b''
        if 'CPF' in data:
            result	       += CPF.produce( data.CPF )
        return result


class CIP( cpppo.dfa ):
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
        (0x006f,0x0070):	send_data,	# 0x006f (SendRRData) is default if CIP.send_data seen
        (0x0065,):		register,
        (0x0066,):		unregister,
        (0x0004,):		list_services,
    }
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        slct			= octets_noop(	'select' )
        for cmd,cls in self.COMMAND_PARSERS.items():
            slct[None]		= cpppo.decide( cls.__name__,
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

        """
        for cmd,cmdcls in cls.COMMAND_PARSERS.items():
            if ( data.get( 'command' ) in cmd
                 or ( 'CIP.' + cmdcls.__name__  in data
                      and data.setdefault( 'command', cmd[0] ) in cmd )):
                return cmdcls.produce( data['CIP.' + cmdcls.__name__] )
        raise Exception( "Invalid CIP request/reply format: %r" % data )

class typed_data( cpppo.dfa ):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within
    the data artifact, or an integer data type).  Data elements are parsed 'til exhaustion of input, so the caller should
    use limit= to define the limits of the data in the source symbol input stream; only complete
    data items must be parsed, so this must be exact, and match the specified data type.

    The known data types are:

    data type	supported	type value	  size

    BOOL 			= 0x00c1	# 1 byte (0x0_c1, _=[0-7] indicates relevant bit)
    SINT	yes		= 0x00c2	# 1 byte
    INT		yes		= 0x00c3	# 2 bytes
    DINT	yes		= 0x00c4	# 4 bytes
    REAL	yes		= 0x00ca	# 4 bytes
    USINT	yes		= 0x00c6	# 1 byte
    UINT	yes		= 0x00c7	# 2 bytes
    UDINT	yes		= 0x00c8	# 4 bytes
    DWORD			= 0x00d3	# 4 byte (32-bit boolean array)
    LINT			= 0x00c5	# 8 byte

    """
    TYPES_SUPPORTED		= {
        BOOL.tag_type:  BOOL,
        SINT.tag_type:	SINT,
        USINT.tag_type:	USINT,
        INT.tag_type:	INT,
        UINT.tag_type:	UINT,
        DINT.tag_type:	DINT,
        UDINT.tag_type:	UDINT,
        REAL.tag_type:	REAL,
    }

    def __init__( self, name=None, tag_type=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        assert tag_type, "Must specify a numeric (or relative path to) the CIP data type; found: %r" % tag_type

        slct			= octets_noop(	'select' )
        
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

        u_1d			= octets_noop(	'end_8bitu',
                                                terminal=True )
        u_1d[True]	= u_1p	= BOOL()
        u_1p[None]		= move_if( 	'mov_8bitu',	source='.BOOL',
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

        fltd			= octets_noop(	'endfloat',
                                                terminal=True )
        fltd[True]	= fltp	= REAL()
        fltp[None]		= move_if( 	'movfloat',	source='.REAL', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=fltd )

        slct[None]		= cpppo.decide(	'BOOL',	state=u_1p,
            predicate=lambda path=None, data=None, **kwds: \
                BOOL.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'SINT',	state=i_8p,
            predicate=lambda path=None, data=None, **kwds: \
                SINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'USINT',state=u_8p,
            predicate=lambda path=None, data=None, **kwds: \
                USINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'INT',	state=i16p,
            predicate=lambda path=None, data=None, **kwds: \
                INT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'UINT',	state=u16p,
            predicate=lambda path=None, data=None, **kwds: \
                UINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'DINT',	state=i32p,
            predicate=lambda path=None, data=None, **kwds: \
                DINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'UDINT',state=u32p,
            predicate=lambda path=None, data=None, **kwds: \
                UDINT.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        slct[None]		= cpppo.decide(	'REAL',	state=fltp,
            predicate=lambda path=None, data=None, **kwds: \
                REAL.tag_type == ( data[path+tag_type] if isinstance( tag_type, cpppo.type_str_base ) else tag_type ))
        
        super( typed_data, self ).__init__( name=name, initial=slct, **kwds )

    @classmethod
    def produce( cls, data, tag_type=None ):
        """Expects to find .type (if tag_type is None) and .data list, and produces the data encoded to bytes."""
        if tag_type is None:
            tag_type		= data.get( 'type' )
        assert hasattr( data, '__iter__' ) and 'data' in data and tag_type in cls.TYPES_SUPPORTED, \
            "Unknown (or no) typed data found for tag_type %r: %r" % ( tag_type, data )
        produce			= cls.TYPES_SUPPORTED[tag_type].produce
        return b''.join( produce( v ) for v in data.data )

    @classmethod
    def datasize( cls, tag_type, size=1 ):
        """Compute the encoded data size for the specified tag_type and amount of data."""
        assert tag_type in cls.TYPES_SUPPORTED, \
            "Unknown tag_type %r" % ( tag_type )
        return cls.TYPES_SUPPORTED[tag_type].struct_calcsize * size


class status( cpppo.dfa ):
    """Parses CIP status, and status_ext.size/.data:

        .status				USINT		1
	.status_ext.size		USINT		1
	.status_ext.data		UINT[*]		.size

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        # Parse the status, and status_ext.size
        stat			= BOOL( 	'status',	context=None )
        stat[True]	= size	= BOOL( 	'_ext.size',	extension='_ext.size' )

        # Parse the status, and status_ext.size
        stat			= USINT( 	'status',	context=None )
        stat[True]	= size	= USINT( 	'_ext.size',	extension='_ext.size' )

        # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .data list
        exts			= UINT(		'ext_status',	extension='.ext_status' )
        exts[None]		= move_if( 	'data',		source='.ext_status',
                                           destination='.data',	initializer=lambda **kwds: [] )
        exts[None]		= cpppo.state( 	'done', terminal=True )

        # Parse each status_ext.data in a sub-dfa, repeating status_ext.size times
        each			= cpppo.dfa(    'each',		extension='_ext',
                                                initial=exts,	repeat='_ext.size',
                                                terminal=True )
        # Only enter the state_ext.data dfa if status_ext.size is non-zero
        size[None]		= cpppo.decide(	'_ext.size', 
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
