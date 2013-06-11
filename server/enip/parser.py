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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "GNU General Public License, Version 3 (or later)"


"""
enip/parser.py	-- The EtherNet/IP CIP protocol parsers

"""

import array
import codecs
import errno
import json
import logging
import os
import struct
import sys
import threading
import time
import traceback
try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
from   cpppo import misc
import cpppo.server
from   cpppo.server import network 

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )

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
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        super( octets_base, self ).__init__( name=name, initial=octets_state(
            name=octets_name, terminal=True, alphabet=octets_alphabet, encoder=octets_encoder,
            typecode=octets_typecode ), **kwds )
   

class octets( octets_base, cpppo.state ):
    """Scans 'repeat' octets into <context>.input using a state_input sub-machine (by default), but
    doesn't itself perform any processing."""
    pass


def octets_encode( value ):
    return value.tostring() if sys.version_info.major < 3 else value.tobytes()


class octets_struct( octets_base, cpppo.state_struct ):
    """Scans octets sufficient to satisfy the specified struct 'format', and then parses it according to
    the supplied struct 'format'."""
    def __init__( self, name=None, format=None, **kwds ):
        assert isinstance( format, str ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, repeat=struct.calcsize( format ),
                                               format=format, **kwds )


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
class TYPE( octets_struct ):
    """An EtherNet/IP data type"""
    def __init__( self, name=None, **kwds ):
        name			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        super( TYPE, self ).__init__( name=name, format=self.struct_format, **kwds )

    @classmethod
    def produce( cls, value ):
        return struct.pack( cls.struct_format, value )

class USINT( TYPE ):
    """An EtherNet/IP USINT; 8-bit unsigned integer"""
    tag_type			= None
    struct_format		= 'B'

class SINT( TYPE ):
    """An EtherNet/IP SINT; 8-bit signed integer"""
    tag_type			= 0x00c2
    struct_format		= 'b'

class UINT( TYPE ):
    """An EtherNet/IP UINT; 16-bit unsigned integer"""
    tag_type			= None
    struct_format		= '<H'

class INT( TYPE ):
    """An EtherNet/IP INT; 16-bit signed integer"""
    tag_type			= 0x00c3
    struct_format		= '<h'

class UDINT( TYPE ):
    """An EtherNet/IP UINT; 16-bit unsigned integer"""
    tag_type			= None
    struct_format		= '<I'

class DINT( TYPE ):
    """An EtherNet/IP INT; 16-bit signed integer"""
    tag_type			= 0x00c4
    struct_format		= '<i'

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
        """Truncate or NUL-fill the provided .string to the given .length (if provided and not None).  Then,
        emit the (one byte) length+string.  Accepts either a {.length: ..., .string:... } dotdict,
        or a plain string.

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
    
        data.<context>.command		UINT         2
        data.<context>.length		UINT         2
        data.<context>.session_handle	UDINT        4
        data.<context>.status		UDINT        4
        data.<context>.sender_context	octets[8]    8
        data.<context>.options		UDINT        4
                                                    --
                                                    24

    Does *not* scan the command-specific data which (normally) follows the header.

    Each protocol element transitions to the next required element on any (non-None) symbol; we
    don't use None (no-input) transition, because we don't want to skip thru the state machine when
    no input is available."""
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'header' )
        name 			= name or kwds.get( 'context' )
        init			= cpppo.state(  "empty",  terminal=True )
        init[True] = cmnd	= UINT(		"command",	context="command" )
        cmnd[True] = leng	= UINT(		"length",	context="length" )
        leng[True] = sess	= UDINT(	"sess_hdl",	context="session_handle" )
        sess[True] = stts	= UDINT(	"status",	context="status" )
        stts[True] = ctxt	= octets(	"sndr_ctx",	context="sender_context",
                                    repeat=8 )
        ctxt[True] = opts	= UDINT( 	"options",	context="options", terminal=True )

        super( enip_header, self ).__init__( name=name, initial=init, **kwds )

class enip_machine( cpppo.dfa ):
    """Parses a complete EtherNet/IP message, including command-specific payload into
    '<context>.encapsulated_data.input'.  Context defaults to 'enip' (unless explicitly set to ''),
    and name default to context."""
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'enip' )
        name 			= name or kwds.get( 'context' )
        hedr			= enip_header()
        hedr[None] = encp	= octets(	"encp_dat",	context="encapsulated_data",
                                                repeat="..header.length", terminal=True )

        super( enip_machine, self ).__init__( name=name, initial=hedr, **kwds )

def enip_encode( data ):
    """Produce an encoded EtherNet/IP message from the supplied data; assumes any encapsulated data has
    been encoded to enip.encapsulated_data.input and is already available."""
    result			= b''.join( [
        UINT.produce(	data.enip.header.command ),
        UINT.produce(len(data.enip.encapsulated_data.input )),
        UDINT.produce( 	data.enip.header.session_handle ),
        UDINT.produce( 	data.enip.header.status ),
        octets_encode(	data.enip.header.sender_context.input ),
        UDINT.produce(	data.enip.header.options ),
        octets_encode(	data.enip.encapsulated_data.input ),
    ])
    return result
    
def enip_format( data ):
    """Format a decoded EtherNet/IP data bundle in a human-readable form."""
    return json.dumps( data, indent=4, sort_keys=True, default=lambda obj: repr( obj ))

# 
# EtherNet/IP CIP Parsing
# 
# See Vol2_1.14.pdf, Chapter 3-2.1 Unconnected Messages, for a simplified overview of parsing.  We
# parse the SendRRData, the CPF encapsulation, and the CFP Null Address and [Un]connected Data
# items, and finally the CIP Message Router Request from the second CFP item.
# 

class move_if( cpppo.decide ):
    """If the predicate is True (the default), then move (either append or assign) data[path+source] to
    data[path+destination], assigning init to it first if the target doesn't yet exist.  Then,
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
                log.debug( "%s -- init. data[%r] to %r", self, pathdst, ini )
                data[pathdst]	= ini
            if self.src is not None:
                pathsrc		= path + self.src
                assert pathsrc in data, \
                    "Could not find %r to move to %r in %r" % ( pathsrc, pathdst, data )
                if hasattr( data[pathdst], 'append' ):
                    log.debug( "%s -- append data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                    data[pathdst].append( data.pop( pathsrc ))
                else:
                    log.debug( "%s -- assign data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                    data[pathdst]	= data.pop( pathsrc )

        return target


class EPATH( cpppo.dfa ):
    """Parses an Extended Path of .size (in words), path_data and path segment list

        .EPATH.size
        .EPATH.segment [
            { 'class':      # },
            { 'instance':   # },
            { 'attribute':  # },
            { 'element':    # },
            { 'symbolic':   '...' },
         ]
         .EPATH.segment__... temp 
    """

    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        psiz			= USINT( context='size' )

        # After capturing each segment__ (pseg), move it onto the path segment list, and loop
        pseg			= octets_noop(	'type',		terminal=True )
        # ...segment parsers...
        pmov			= move_if( 	'move',		initializer=lambda **kwds: [],
                                            source='..segment__', destination='..segment',
                                                state=pseg )

        # Wire each different segment type parser between pseg and pmov
        pseg[b'\x28'[0]]= e_8t	= octets_drop(	'type',		repeat=1 )
        e_8t[True]	= e_8v	= USINT( 	'elem_8bit',	context='element')
        e_8v[None]		= pmov

        pseg[b'\x29'[0]]= e16t	= octets_drop(	'type',		repeat=2 )
        e16t[True]	= e16v	= UINT(		'elem16bit',	context='element')
        e16v[None]		= pmov

        pseg[b'\x2a'[0]]= e32t	= octets_drop(	'type',		repeat=2 )
        e32t[True]	= e32v	= UDINT(	'elem32bit',	context='element')
        e32v[None]		= pmov


        pseg[b'\x20'[0]]= c_8t	= octets_drop(	'type',		repeat=1 )
        c_8t[True]	= c_8v	= USINT(	'clas_8bit',	context='class')
        c_8v[None]		= pmov

        pseg[b'\x21'[0]]= c16t	= octets_drop(	'type',		repeat=2 )
        c16t[True]	= c16v	= UINT(		'clas16bit',	context='class')
        c16v[None]		= pmov


        pseg[b'\x24'[0]]= i_8t	= octets_drop(	'type',		repeat=1 )
        i_8t[True]	= i_8v	= USINT(	'inst_8bit',	context='instance')
        i_8v[None]		= pmov

        pseg[b'\x25'[0]]= i16t	= octets_drop(	'type',		repeat=2 )
        i16t[True]	= i16v	= UINT(		'inst16bit',	context='instance')
        i16v[None]		= pmov


        pseg[b'\x30'[0]]= a_8t	= octets_drop(	'type',		repeat=1 )
        a_8t[True]	= a_8v	= USINT(	'attr_8bit',	context='attribute')
        a_8v[None]		= pmov

        pseg[b'\x31'[0]]= a16t	= octets_drop(	'type',		repeat=2 )
        a16t[True]	= a16v	= UINT(		'attr16bit',	context='attribute')
        a16v[None]		= pmov


        pseg[b'\x91'[0]]= symt	= octets_drop(	'type',		repeat=1 )
        symt[True]	= syml	= USINT(	'sym_len',	context='length' )
        syml[None]	= symv	= cpppo.string_bytes(
            					'symbolic',	context='symbolic', limit='..length',
                                                initial='.*',	decode='iso-8859-1' )

        # An odd-length ANSI Extended Symbolic name means an odd total.  Pad
        symo			= octets_drop(	'pad', 		repeat=1 )
        symo[None]		= pmov

        symv[None]		= cpppo.decide(	'odd',
                predicate=lambda path=None, data=None, **kwds: data[path+'.length'] % 2,
                                                state=symo )
        symv[None]		= pmov


        # Parse all segments in a sub-dfa limited by the parsed path.size (in words; double)
        psiz[None]	= pall	= cpppo.dfa(    'each',		context='segment__',
                                                initial=pseg,	terminal=True,
            limit=lambda path=None, data=None, **kwds: data[path+'..size'] * 2 )

        super( EPATH, self ).__init__( name=name, initial=psiz, **kwds )

    @staticmethod
    def produce( data ):
        """Produce an encoded EtherNet/IP EPATH message from the supplied path data.  For example, here is
        an encoding a 8-bit instance ID 0x06, and ending with a 32-bit element ID 0x04030201:
    
           byte:	0	1	2	... 	N-6	N-5	N-4	N-3	N-2	N-1	N
                    <N/2>	0x24	0x06	... 	0x25	0x00	0x01	0x02	0x03	0x04
    
        """
        
        result			= b''
        for seg in data.segment:
            found			= False
            for segnam, segtyp in {
                    'symbolic':	0x91,
                    'class':	0x20,
                    'instance':	0x24,
                    'attribute':	0x30,
                    'element':	0x28, }.items():
                if segnam not in seg:
                    continue
                found		= True
                segval		= seg[segnam]
                # An ANSI Extended Symbolic segment?
                if segnam == 'symbolic':
                    result     += USINT.produce( segtyp )
                    seglen	= len( segval )
                    result     += USINT.produce( seglen )
                    result     += segval.encode( 'iso-8859-1' )
                    if seglen % 2:
                        result += USINT.produce( 0 )
                    break
               
                # A numeric path segment.
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
                    assert False, "Invalid value for numeric EPATH segment %r == %d: %d" (
                        segnam, segval, data )
                break
            if not found:
                assert False, "Invalid EPATH segment %r found in %r" % ( segnam, data )
            assert len( result ) % 2 == 0, \
                "Failed to retain even EPATH word length after %r in %r" % ( segnam, data )
    
        return USINT.produce( len( result ) // 2 ) + result


class route_path( cpppo.dfa ):
    """Unconnected message route path.  Not interpreted, just parsed as octets into .input array.
    Consumes all available input symbols.

        .route_path.input 		octets[*]

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        rout			= octets( terminal=True )      	# Just soak up remaining data for now
        rout[True]		= rout

        super( route_path, self ).__init__( name=name, initial=rout, **kwds )


class unconnected_send( cpppo.dfa ):
    """See CIP Specification, Vol. 1, Chapter 3, 3-5.26.  A Message Router object must process
    Unconnected Send requests, which carry a message and a routing path, allowing delivery of the
    message to a port.  When the route_path contains only a port, then the message is delivered the
    attached processor; otherwise, it needs to be forwarded; we do not handle these cases yet.

        .unconnected_send.service	USINT
        .unconnected_send.path		EPATH		?	object handling parsing (message router)
        .unconnected_send.priority	USINT
        .unconnected_send.timeout_ticks	USINT
        .unconnected_send.length	UINT
        .unconnected_send.<parser>      ...	     .length
                                        USINT		1 	optional pad, if length is odd)
        .unconnected_send.route_path	EPATH (padded; one byte between EPATH size and EPATH payload)

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        cmnd			= USINT(	context='service' )
        cmnd[True]	= path	= EPATH(	context='request_path',	
                                                terminal=True )
        # Some commands (eg Get Attribute All) have no other content, and terminate here.

        path[True]	= prio	= USINT(	context='priority' )
        prio[True]	= timo	= USINT(	context='timeout_ticks' )
        timo[True]	= leng	= UINT(		context='length' )

        # If length is odd, drop the pad byte, and then parse the route_path
        # TODO: Find object w/path, and use its parser!  cpppo.decide derived lookup?
        mesg			= logix( limit='..length' )
        pad0			= octets_drop( 'pad', 	repeat=1 )
        pad0[None]		= mesg
        leng[None]		= cpppo.decide( 'pad',	state=pad0,
                            predicate=lambda path=None, data=None, **kwds: data[path+'.length'] % 2 )
        leng[None]		= mesg

        # route segments, like path but for hops/links/keys...
        mesg[None]		= route_path( terminal=True )

        super( unconnected_send, self ).__init__( name=name, initial=cmnd, **kwds )


class CPF( cpppo.dfa ):

    """A SendRRData Common Packet Format specifies the number and type of the encapsulated CIP address
    items or data items that follow:

    	.CPF.count			UINT		2 	Number of items
        .CPF.item[0].type_id		UINT		2	Type ID of item encapsulated		
        .CPF.item[0].length		UINT		2	Length of item encapsulated		
        .CPF.item[0].<parser>...

    Parse the count, and then each CPF item into cpf.item_temp, and (after parsing) moves it to
    cpf.item[x].
    

    A dictionary of parsers for various CPF types must be provided.  Any CPF item with a length > 0 will
    be parsed using the instance of the parser appropriate to its type:
        {
            0x00b2:	<class>,
        }

    Here is a subset of the types of CPF items to expect:

        0x0000: 	NULL Address (used w/Unconnected Messages)
        0x00b2: 	Unconnected Messages (eg. used within CIP command SendRRData)
        0x00a1:		Address for connection based requests
        0x00b1:		Connected Transport packet (eg. used within CIP command SendUnitData)
        0x0100:		ListServices response

    

    """
    def __init__( self, name=None, **kwds ):
        """Parse CPF list items 'til .count reached, which should be simultaneous with symbol exhaustion, if
        caller specified a symbol limit.

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

        send_parsers		= {
            0x00b2: unconnected_send,
        } 

        for typ,cls in ( send_parsers or {} ).items():
            ilen[None]		= cpppo.decide( cls.__name__, state=cls( terminal=True, limit='..length' ),
                        predicate=lambda path=None, data=None, **kwds: data[path].type_id == typ )

        # If we don't recognize the CPF item type, just parse remainder into .unrecognized.input
        ilen[None]	= urec	= octets( context='unrecognized', repeat='..length',
                                          terminal=True )
        urec[True]		= urec

        # Each item is collected into '.item__', 'til no more input available, and then moved into
        # place into '.item' (init to [])
        item			= cpppo.dfa( 	'each', 	context='item__',
                                                initial=ityp )
        item[None] 		= move_if( 	'move', 	source='.item__',
                                           destination='.item', initializer=lambda **kwds: [] )
        item[None]		= cpppo.state( 	'done', terminal=True )

        # Parse count, and then exactly .count CPF items.
        loop			= UINT( 			context='count' )
        loop[None]		= cpppo.dfa( 	'all', 	
                                                initial=item,	repeat='.count',
                                                terminal=True )

        super( CPF, self ).__init__( name=name, initial=loop, **kwds )


class send_data( cpppo.dfa ):
    """Handle Connected (SendUnitData) or Unconnected (SendRRData) Send Data request/reply."""
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        ifce			= UDINT(			context='interface' )
        ifce[True]	= timo	= UINT(				context='timeout' )
        timo[True]		= CPF( terminal=True )

        super( send_data, self ).__init__( name=name, initial=ifce, **kwds )


class register( cpppo.dfa ):
    """Handle RegisterSession request/reply (identical)"""
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        
        prto			= UINT(				context='protocol_version' )
        prto[True]		= UINT(				context='options',
                                                                terminal=True )

        super( register, self ).__init__( name=name, initial=prto, **kwds )


class unregister( octets_noop ):
    """Handle UnregisterSession request (no reply; session dropped)"""
    def terminate( self, exception, machine=None, path=None, data=None ):
        """Just create an empty value to indicate the command was received."""
        # Only operate if we have completed without exception.
        super( state_struct, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        if exception is not None:
            return
        ours			= self.context( path=path )
        data[ours]		= True


class list_services( cpppo.dfa ):
    """Handle ListServices request.  Services are encoded as a CPF list."""
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        svcs			= CPF( terminal=True )

        super( list_services, self ).__init__( name=name, initial=svcs, **kwds )




class CIP( cpppo.dfa ):
    """The EtherNet/IP CIP Encapsulation transports various commands back and forth between a
    transmitter and a receiver.  There is no explicit designation of a request or a reply.  All have
    a common prefix;

        .CIP.command			UINT		2
        .CIP.length			UINT		2
        .CIP.session			UDINT		4
        .CIP.status			UDINT		4
        .CIP.sender_context		octets[8]	8
        .CIP.options			UDINT		4

    The supported command values and their formats are:

    ListIdentity		0x0063

    ListInterfaces		0x0064

    RegisterSession		0x0065
        .CIP.register.protocol_version
        .CIP.register.options

    UnregisterSession		0x0066
        .CIP.unregister

    ListServices		0x0004
        .CIP.listservices.CPF...

    SendRRData			0x006f
    SendUnitData		0x0070
        .CIP.send.inteface		UDINT
        .CIP.send.timeout		UINT
        .CIP.send.CPF...

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        cmnd			= UINT(		context='command' )
        cmnd[True]	= leng	= UINT(		context='length' )
        leng[True]	= sess	= UDINT(	context='session' )	
        sess[True]	= stts	= UDINT(	context='status' )	
        stts[True]	= cntx	= octets(	context='sender_context', repeat=8 )
        cntx[True]	= opts	= UDINT( 	context='options' )

        opts[None]		= cpppo.decide( 'SendData',
            predicate=lambda path=None, data=None, **kwds: data[path].command in ( 0x006f, 0x0070 ),
                                                state=send_data(
                                                    limit='..length',		terminal=True ))
        opts[None]		= cpppo.decide( 'Register', 
            predicate=lambda path=None, data=None, **kwds: data[path].command == 0x0065,
                                               state=register(
                                                   limit='..length', 		terminal=True ))
        opts[None]		= cpppo.decide( 'Unregister',
            predicate=lambda path=None, data=None, **kwds: data[path].command == 0x0066,
                                                state=unregister(
                                                    limit='..length',		terminal=True ))
        opts[None]		= cpppo.decide( 'ListServices',
            predicate=lambda path=None, data=None, **kwds: data[path].command == 0x0004,
                                                state=list_services(
                                                    limit='..length',		terminal=True))
        # If unrecognized, default to just collect the data
        opts[None]		= octets( 	context='unrecognized',
                                                    limit='..length',		terminal=True )

        super( CIP, self ).__init__( name=name, initial=cmnd, **kwds )


class typed_data( cpppo.dfa ):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within the
    data artifact).  Data elements are parsed 'til exhaustion of input, so the caller should use
    limit= to define the limits of the data in the source symbol input stream; only complete data
    items must be parsed, so this must be exact, and match the specified data type.

    The known data types are:

    data type			type value	  size

    BOOL 			= 0x00c1	# 1 byte (0x0_c1, _=[0-7] indicates relevant bit)
    SINT			= 0x00c2	# 1 byte
    INT				= 0x00c3	# 2 bytes
    DINT			= 0x00c4	# 4 bytes
    REAL			= 0x00ca	# 4 bytes
    DWORD			= 0x00d3	# 4 byte (32-bit boolean array)
    LINT			= 0x00c5	# 8 byte
    """
    def __init__( self, name=None, datatype=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        assert datatype, "Must specify a relative path to the CIP data type; found: %r" % datatype

        slct			= octets_noop(	'select' )
        
        i_8d			= octets_noop(	'end_8bit',
                                                terminal=True )
        i_8d[True]	= i_8p	= SINT()
        i_8p[None]		= move_if( 	'mov_8bit',	source='.SINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i_8d )

        i16d			= octets_noop(	'end16bit',
                                                terminal=True )
        i16d[True]	= i16p	= INT()
        i16p[None]		= move_if( 	'mov16bit',	source='.INT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i16d )

        i32d			= octets_noop(	'end32bit',
                                                terminal=True )
        i32d[True]	= i32p	= DINT()
        i32p[None]		= move_if( 	'mov32bit',	source='.DINT', 
                                           destination='.data',	initializer=lambda **kwds: [],
                                                state=i32d )

        slct[None]		= cpppo.decide(	'SINT',	state=i_8p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == SINT.tag_type )
        slct[None]		= cpppo.decide(	'INT',	state=i16p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == INT.tag_type )
        slct[None]		= cpppo.decide(	'DINT',	state=i32p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == DINT.tag_type )
        
        super( typed_data, self ).__init__( name=name, initial=slct, **kwds )

    @staticmethod
    def produce( data ):
        """Expects to find .type and .data.list, and produces the data encoded to bytes."""
        assert 'type' in data and data.type in ( SINT.tag_type, INT.tag_type, DINT.tag_type ), \
            "Unknown (or no) .type found: %r" % data
        if data.type ==   SINT.tag_type:
            return b''.join(  SINT.produce( v ) for v in data.data )
        elif data.type ==  INT.tag_type:
            return b''.join(   INT.produce( v ) for v in data.data )
        elif data.type == DINT.tag_type:
            return b''.join(  DINT.produce( v ) for v in data.data )


class logix( cpppo.dfa ):
    """Parses a Logix vendor-specific CIP request.

    If a Logix5000 Controller is being addressed (See Logix5000 Data Access manual, pp 16, Services
    Supported by Logix5000 Controllers), the ucmm.request_data. may contain:
    
	.service			USINT		1

    Read Tag					0x4c
    Read Tag Fragmented				0x52	(unrelated to Unconnected Send, above...)
    Write Tag					0x4d
    Write Tag Fragmented			0x53
    Read Modify Write Tag			0x4e	(not implemented)
					      | 0x80	(indicates response)
 
	.path				EPATH		...

    The portions of these requests/replies that are generic to all are placed in the root of the
    data path; any data that has differing meaning for each command is placed in a named context.

    The request-specific data for the supported services are:

    Read Tag Service				0x4c
	.read_tag.elements		UINT		2
    Read Tag Service (reply)			0xcc
	.status				USINT		1
					USINT		1 (ext_status_size ignored; must be 0x00)
	.read_tag.type			UINT		2
	.read_tag.data.list		[0x...]		1/2/4 (depending on type)
    
    Read Tag Fragmented Service			0x52
	.read_frag.elements		UINT		2
	.read_frag.offset		UDINT		4 (in bytes)
    Read Tag Fragmented Service (reply)		0xd2
	.status				USINT		1
					USINT		1 (ext_status_size ignored; must be 0x00)
	.read_frag.type			UINT		2
	.read_frag.data			[0x..., 0x...]	* x 1/2/4 (depending on type)

    Write Tag Service				0x4d
	.write_tag.type			UINT		2
	.write_tag.data.list		[0x...]		1/2/4 (depending on type)
    Write Tag Service (reply)			0xdd
	.status				USINT		1
					USINT		1 (ext_status_size ignored; must be 0x00)
        .write_tag 					(created, but left empty)

    Write Tag Fragmented Service		0x53
	.write_frag.type		UINT		2
	.write_frag.elements		UINT		2
	.write_frag.offset		UDINT		4 (in bytes)
	.write_frag.data		[0x..., 0x...]	* x 1/2/4 (depending on type)
    Write Tag Fragmented Service (reply)	0xd3
	.status				USINT		1
					USINT		1 (ext_status_size ignored; must be 0x00)
        .write_frag					(created, but left empty)

    This must be run with a length-constrained 'source' iterable (eg. a fixed-length array harvested
    by a previous parser, eg. ucon_send.request_data).	Since there are no indicators within this
    level of the protocol the indicate the size of the request, the Write Tag [Fragmented] Service
    requests (and Read Tag [Fragmented] replies) do not carry indicators of the size of their data.
    It could be deduced from the type for Write Tag requests (Read Tag replies), but cannot be
    deduced for the Fragmented versions.

    """
    GA_ALL_REQ			= 0x01
    GA_ALL_RPY			= GA_ALL_REQ | 0x80
    RD_TAG_REQ			= 0x4c
    RD_TAG_RPY			= RD_TAG_REQ | 0x80
    RD_FRG_REQ			= 0x52
    RD_FRG_RPY			= RD_FRG_REQ | 0x80
    WR_TAG_REQ			= 0x4d
    WR_TAG_RPY			= WR_TAG_REQ | 0x80
    WR_FRG_REQ			= 0x53
    WR_FRG_RPY			= WR_FRG_REQ | 0x80
    transit			= {}
    service			= {}
    for x,xn in (( GA_ALL_REQ, "Get Attribute All" ),
                 ( GA_ALL_RPY, "Get Attribute All Reply" ),
                 ( RD_TAG_REQ, "Read Tag Request" ),
                 ( RD_TAG_RPY, "Read Tag Request Reply" ),
                 ( RD_FRG_REQ, "Read Tag Fragmented" ),
                 ( RD_FRG_RPY, "Read Tag Fragmented Reply" ),
                 ( WR_TAG_REQ, "Write Tag Request" ),
                 ( WR_TAG_RPY, "Write Tag Request Reply" ),
                 ( WR_FRG_REQ, "Write Tag Fragmented" ),
                 ( WR_FRG_RPY, "Write Tag Fragmented Reply" )):
        service[x]		= xn
        service[xn]		= x
        transit[x]		= chr( x ) if sys.version_info.major < 3 else x

    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )

        slct			= octets_noop(	'select' )	# parse path size and path

        # Read Tag Service
        slct[self.transit[self.RD_TAG_REQ]] \
			= rtsv	= USINT(	 	  	context='service' )
        rtsv[True]	= rtpt	= EPATH(			context='path' )
        rtpt[True]	= rtel	= UINT(		'elements', 	context='read_tag',   extension='.elements',
                                                terminal=True )
        # Read Tag Service (reply).  Remainder of symbols are typed data.
        slct[self.transit[self.RD_TAG_RPY]] \
			= Rtsv	= USINT(		 	context='service' )
        Rtsv[True]	= Rtrs	= octets_drop(	'reserved',	repeat=1 )
        Rtrs[True]	= Rtst	= USINT( 			context='status' )
        Rtst[b'\x00'[0]]= Rtss	= octets_drop(	'status_size',	repeat=1 )
        Rtss[True]	= Rtdt	= UINT( 	'type',   	context='read_tag',  extension='.type' )
        Rtdt[True]		= typed_data( 	'data',   	context='read_tag',
                                                datatype='.type',
                                                terminal=True )

        # Read Tag Fragmented Service
        slct[self.transit[self.RD_FRG_REQ]] \
			= rfsv	= USINT(			context='service' )
        rfsv[True]	= rfpt	= EPATH(			context='path' )
        rfpt[True]	= rfel	= UINT(		'elements',	context='read_frag',  extension='.elements' )
        rfel[True]		= UDINT( 	'offset',   	context='read_frag',  extension='.offset',
                                                terminal=True )
        # Read Tag Fragmented Service (reply).  Remainder of symbols are typed data.
        slct[self.transit[self.RD_FRG_RPY]] \
			= Rfsv	= USINT(			context='service' )
        Rfsv[True]	= Rfrs	= octets_drop(	'reserved',	repeat=1 )
        Rfrs[True]	= Rfst	= USINT( 			context='status' )
        Rfst[b'\x00'[0]]= Rfss	= octets_drop( 'status_size',	repeat=1 )
        Rfss[True]	= Rfdt	= UINT( 	'type',   	context='read_frag',  extension='.type' )
        Rfdt[True]		= typed_data( 	'data',   	context='read_frag',
                                                datatype='.type',
                                                terminal=True )

        # Write Tag Service
        slct[self.transit[self.WR_TAG_REQ]] \
			= wtsv	= USINT(		  	context='service' )
        wtsv[True]	= wtpt	= EPATH(			context='path' )
        wtpt[True]	= wtty	= UINT(		'type',   	context='type' )
        wtty[True]		= typed_data( 	'write_tag',	context='write_tag' ,
                                                datatype='.type',
                                                terminal=True )
        # Write Tag Service (reply)
        slct[self.transit[self.WR_TAG_RPY]] \
			= Wtsv	= USINT(		  	context='service' )
        Wtsv[True]	= Wtrs	= octets_drop(	'reserved',	repeat=1 )
        Wtrs[True]	= Wtst	= USINT( 			context='status' )
        Wtst[b'\x00'[0]]= Wtss	= octets_drop(	'status_size',	repeat=1 )
        Wtss[None]		= move_if( 	'write_tag',	destination='.write_tag',
                                                initializer=True, # was: lambda **kwds: cpppo.dotdict(),
                                                state=octets_noop( terminal=True ))

        # Write Tag Fragmented Service
        slct[self.transit[self.WR_FRG_REQ]] \
			= wfsv	= USINT(		  	context='service' )
        wfsv[True]	= wfpt	= EPATH(			context='path' )
        wfpt[True]	= wfty	= UINT(		'type',     	context='write_frag', extension='.type' )
        wfty[True]	= wfel	= UINT(		'elements', 	context='write_frag', extension='.elements' )
        wfel[True]	= wfof	= UDINT( 	'offset',   	context='write_frag', extension='.offset' )
        wfof[True]		= typed_data( 	'data',  	context='write_frag',
                                                datatype='.type',
                                                terminal=True )
        # Write Tag Fragmented Service (reply)
        slct[self.transit[self.WR_FRG_RPY]] \
			= Wfsv	= USINT(			context='service' )
        Wfsv[True]	= Wfrs	= octets_drop(	'reserved',	repeat=1 )
        Wfrs[True]	= Wfst	= USINT( 			context='status' )
        Wfst[b'\x00'[0]]= Wfss	= octets_drop(	'status_size',	repeat=1 )
        Wfss[None]		= move_if( 	'write_frag',	destination='.write_frag',
                                                initializer=True, # was: lambda **kwds: cpppo.dotdict(),
                                                state=octets_noop( terminal=True ))

        # Get Attribute All
        slct[self.transit[self.GA_ALL_REQ]] \
			= gasv	= USINT(		 	context='service' )
        gasv[True]	= gapt	= EPATH(			context='path')
        gapt[None]		= move_if( 	'get_attr_all',	destination='.get_attributes_all',
                                                initializer=True, # was: lambda **kwds: cpppo.dotdict(),
                                                state=octets_noop( terminal=True ))


        # By default, just collect the payload into .unrecognized.input
        slct[None]		= octets(			context='unrecognized',
                                                terminal=True )

        super( logix, self ).__init__( name=name, initial=slct, **kwds )

    @staticmethod
    def produce( data ):
        """Expects to find .type and .data.list, and produces the data encoded to bytes.  Defaults to 
         produce the Request, if no .service specified, and just .read/write_tag/frag found.  
         
         A Reply status of 0x06 to the read_frag command indicates that more data is available"""
        result			= b''
        if 'get_attributes_all' in data and data.setdefault( 'service', logix.GA_ALL_REQ ) == logix.GA_ALL_REQ:
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
        elif 'read_tag' in data and data.setdefault( 'service', logix.RD_TAG_REQ ) == logix.RD_TAG_REQ:
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.read_tag.elements )
        elif 'read_frag' in data and data.setdefault( 'service', logix.RD_FRG_REQ ) == logix.RD_FRG_REQ:
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.read_frag.elements )
            result	       += UDINT.produce(	data.read_frag.offset )
        elif 'write_tag' in data and data.setdefault( 'service', logix.WR_TAG_REQ ) == logix.WR_TAG_REQ:
            # We can deduce the number of elements from len( data )
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(		data.write_tag.type )
            result	       += UINT.produce(		data.write_tag.setdefault( 
                'elements', len( data.write_tag.data )))
            result	       += typed_data.produce(	data.write_tag )
        elif 'write_frag' in data and data.setdefault( 'service', logix.WR_FRG_REQ ) == logix.WR_FRG_REQ:
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
        elif (    'write_tag'  in data and data.service == logix.WR_TAG_RPY
               or 'write_frag' in data and data.service == logix.WR_FRG_RPY ):
            result	       += USINT.produce(	data.service )
            result	       += USINT.produce(	0x00 )
            result	       += USINT.produce(	data.setdefault( 'status', 0x00 ))
            result	       += USINT.produce( 	0x00 )	# ext_status_size
        elif 'read_tag' in data and data.service == logix.RD_TAG_RPY:
            result	       += USINT.produce(	data.service )
            result	       += USINT.produce(	0x00 )
            result	       += USINT.produce(	data.setdefault( 'status', 0x00 ))
            result	       += USINT.produce( 	0x00 )	# ext_status_size
            result	       += typed_data.produce(	data.read_tag )
        elif 'read_frag' in data and data.service == logix.RD_FRG_RPY:
            result	       += USINT.produce(	data.service )
            result	       += USINT.produce(	0x00 )
            result	       += USINT.produce(	data.setdefault( 'status', 0x00 ))
            result	       += USINT.produce( 	0x00 )	# ext_status_size
            result	       += UINT.produce(		data.read_frag.type )
            result	       += typed_data.produce(	data.read_frag )
        else:
            assert False, "Invalid logix CIP request/reply format: %r" % data
        return result
