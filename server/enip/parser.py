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
class octets_base( cpppo.dfa_base ):
    """Scan 'repeat' octets (default: 1), using an instance of the provided octets_state class as the
    sub-machine 'initial' state.  The sub-machine has no outgoing transitions, and will terminate
    after accepting and processing exactly one symbol.  Only after all 'repeat' loops will
    self.terminal be True."""
    def __init__( self, name, initial=None,
                  octets_name="byte",
                  octets_state=cpppo.state_input,
                  octets_alphabet=cpppo.type_bytes_iter,
                  octets_encoder=None,
                  octets_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
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
    def __init__( self, name, format=None, **kwds ):
        assert isinstance( format, str ), "Expected a struct 'format', found: %r" % format
        super( octets_struct, self ).__init__( name=name, repeat=struct.calcsize( format ),
                                               format=format, **kwds )


class octets_noop( octets_base, cpppo.state ):
    """Does nothing with an octet."""
    def __init__( self, name,
                  octets_state=cpppo.state, **kwds ):
        super( octets_noop, self ).__init__( name=name, octets_name="noop",
                                             octets_state=octets_state, **kwds )


class octets_drop( octets_base, cpppo.state ):
    """Scans 'repeat' octets and drops them."""
    def __init__( self, name,
                  octets_state=cpppo.state_drop, **kwds ):
        super( octets_drop, self ).__init__( name=name, octets_name="drop",
                                             octets_state=octets_state, **kwds )
        

class words_base( cpppo.dfa_base ):
    """Scan 'repeat' 2-byte words (default: 1), convenient when sizes are specified in words."""
    def __init__( self, name, initial=None,
                  words_state=cpppo.state_input,
                  words_alphabet=cpppo.type_bytes_iter,
                  words_encoder=None,
                  words_typecode=cpppo.type_bytes_array_symbol, **kwds ):
        assert initial is None, "Cannot specify a sub-machine for %s.%s" % (
            __package__, self.__class__.__name__ )
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
# usint		-- Parse an 8-bit EtherNet/IP unsigned int 
# usint_encode	--   and convert a value back to a 8-bit EtherNet/IP unsigned int
# uint		-- Parse a 16-bit EtherNet/IP unsigned int 
# uint_encode	--   and convert a value back to a 16-bit EtherNet/IP unsigned int
# udint		-- Parse a 32-bit EtherNet/IP unsigned int 
# udint_encode	--   and convert a value back to a 32-bit EtherNet/IP unsigned int
# 
class usint( octets_struct ):
    """An EtherNet/IP UINT; 8-bit unsigned integer"""
    def __init__( self, name, **kwds ):
        super( usint, self ).__init__( name=name, format='B', **kwds )

def usint_encode( value ):
    return struct.pack( 'B', value )

class uint( octets_struct ):
    """An EtherNet/IP UINT; 16-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( uint, self ).__init__( name=name, format='<H', **kwds )

def uint_encode( value ):
    return struct.pack( '<H', value )

class udint( octets_struct ):
    """An EtherNet/IP UDINT; 32-bit little-endian unsigned integer"""
    def __init__( self, name, **kwds ):
        super( udint, self ).__init__( name=name, format='<I', **kwds )

def udint_encode( value ):
    return struct.pack( '<I', value )
        

# 
# enip_header	-- Parse an EtherNet/IP header only 
# enip_machine	-- Parses an EtherNet/IP header and encapsulated data payload
# enip_encode	--   and convert parsed EtherNet/IP data back into a message
# 
class enip_header( cpppo.dfa ):
    """Scans either a complete EtherNet/IP encapsulation header, or nothing (EOF), into the context
    (default 'header'):
    
        data.<context>.command		uint         2
        data.<context>.length		uint         2
        data.<context>.session_handle	udint        4
        data.<context>.status		udint        4
        data.<context>.sender_context	octets[8]    8
        data.<context>.options		udint        4
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
        init[True] = cmnd	= uint(		"command",	context="command" )
        cmnd[True] = leng	= uint(		"length",	context="length" )
        leng[True] = sess	= udint(	"sess_hdl",	context="session_handle" )
        sess[True] = stts	= udint(	"status",	context="status" )
        stts[True] = ctxt	= octets(	"sndr_ctx",	context="sender_context",
                                    repeat=8 )
        ctxt[True] = opts	= udint( 	"options",	context="options", terminal=True )

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
        uint_encode(	data.enip.header.command ),
        uint_encode(len(data.enip.encapsulated_data.input )),
        udint_encode( 	data.enip.header.session_handle ),
        udint_encode( 	data.enip.header.status ),
        octets_encode(	data.enip.header.sender_context.input ),
        udint_encode(	data.enip.header.options ),
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
# parse the SendRRData, the CPF encapsulation, and the CFP Null Address and Unconnected Data itmes, 
# and finally the CIP Message Router Request from the second CFP item.
# 
class move_if( cpppo.decide ):
    """If the predicate is True (the default), then move (either append or assign) data[path+source] to
    data[path+destination], assigning init to it first if the target doesn't yet exist.  Then,
    proceed to the target state."""
    def __init__( self, name, source=None, destination=None, initializer=None, **kwds ):
        super( move_if, self ).__init__( name=name, **kwds )
        self.src		= source if source else ''
        self.dst		= destination if destination else ''
        self.ini		= initializer
        
    def execute( self, truth, machine=None, source=None, path=None, data=None ):
        target			= super( move_if, self ).execute(
            truth, machine=machine, source=source, path=path, data=data )
        if truth:
            pathsrc		= path + self.src
            pathdst		= path + self.dst
            assert pathsrc in data, \
                "Could not find %r to move to %r in %r" % ( pathsrc, pathdst, data )
            if self.ini and pathdst not in data:
                ini		= ( self.ini
                                    if not hasattr( self.ini, '__call__' )
                                    else self.ini(
                                            machine=machine, source=source, path=path, data=data ))
                log.debug( "%s -- init. data[%r] to %r", self, pathdst, ini )
                data[pathdst]	= ini

            if hasattr( data[pathdst], 'append' ):
                log.debug( "%s -- append data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                data[pathdst].append( data.pop( pathsrc ))
            else:
                log.debug( "%s -- assign data[%r] == %r to data[%r]", self, pathsrc, data[pathsrc], pathdst )
                data[pathdst]	= data.pop( pathsrc )

        return target


class extpath( cpppo.dfa ):
    """Parses an extended request path_size (words), path_data and path segment list

        .path.size
        .path.list [
            { 'class':      # },
            { 'instance':   # },
            { 'attribute':  # },
            { 'element':    # },
            { 'symbolic':   '...' },
         ]
    """

    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'path' )
        name 			= name or kwds.get( 'context' )
        
        psiz			= usint(	'size',		context='size' )

        # After capturing each segment (pseg), move it onto the path list, and loop
        pseg			= octets_noop(	'seg',		terminal=True )
        # ...segment parsers...
        pmov			= move_if( 	'move',		initializer=lambda **kwds: [],
                                            source='..segment', destination='..list',
                                                state=pseg )

        # Wire each different segment type parser between pseg and pmov
        pseg[b'\x28'[0]]= e_8t	= octets_drop(	'type',		repeat=1 )
        e_8t[True]	= e_8v	= usint( 	'elem_8bit',	context='element')
        e_8v[None]		= pmov

        pseg[b'\x29'[0]]= e16t	= octets_drop(	'type',		repeat=2 )
        e16t[True]	= e16v	= uint(		'elem16bit',	context='element')
        e16v[None]		= pmov

        pseg[b'\x2a'[0]]= e32t	= octets_drop(	'type',		repeat=2 )
        e32t[True]	= e32v	= udint(	'elem32bit',	context='element')
        e32v[None]		= pmov


        pseg[b'\x20'[0]]= c_8t	= octets_drop(	'type',		repeat=1 )
        c_8t[True]	= c_8v	= usint(	'clas_8bit',	context='class')
        c_8v[None]		= pmov

        pseg[b'\x21'[0]]= c16t	= octets_drop(	'type',		repeat=2 )
        c16t[True]	= c16v	= uint(		'clas16bit',	context='class')
        c16v[None]		= pmov


        pseg[b'\x24'[0]]= i_8t	= octets_drop(	'type',		repeat=1 )
        i_8t[True]	= i_8v	= usint(	'inst_8bit',	context='instance')
        i_8v[None]		= pmov

        pseg[b'\x25'[0]]= i16t	= octets_drop(	'type',		repeat=2 )
        i16t[True]	= i16v	= uint(		'inst16bit',	context='instance')
        i16v[None]		= pmov


        pseg[b'\x30'[0]]= a_8t	= octets_drop(	'type',		repeat=1 )
        a_8t[True]	= a_8v	= usint(	'attr_8bit',	context='attribute')
        a_8v[None]		= pmov

        pseg[b'\x31'[0]]= a16t	= octets_drop(	'type',		repeat=2 )
        a16t[True]	= a16v	= uint(		'attr16bit',	context='attribute')
        a16v[None]		= pmov


        pseg[b'\x91'[0]]= symt	= octets_drop(	'type',		repeat=1 )
        symt[True]	= syml	= usint(	'sym_len',	context='length' )
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
        psiz[None]	= pall	= cpppo.dfa(    'all',		context='segment',
                                                initial=pseg,	terminal=True,
            limit=lambda path=None, data=None, **kwds: data[path+'..size'] * 2 )

        super( extpath, self ).__init__( name=name, initial=psiz, **kwds )


def extpath_encode( data ):
    """Produce an encoded EtherNet/IP EPATH message from the supplied path data.  For example, here is
    an encoding a 8-bit instance ID 0x06, and ending with a 32-bit element ID 0x04030201:

       byte:	0	1	2	... 	N-6	N-5	N-4	N-3	N-2	N-1	N
                <N/2>	0x24	0x06	... 	0x25	0x00	0x01	0x02	0x03	0x04

    """
    
    result			= b''
    for seg in data['list']:
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
                result	       += usint_encode( segtyp )
                seglen		= len( segval )
                result	       += usint_encode( seglen )
                result	       += segval.encode( 'iso-8859-1' )
                if seglen % 2:
                    result      += usint_encode( 0 )
                break
           
            # A numeric path segment.
            if segval <= 0xff:
                result          += usint_encode( segtyp )
                result          += usint_encode( segval )
            elif segval <= 0xffff:
                result          += usint_encode( segtyp + 1 )
                result          += usint_encode( 0 )
                result          += uint_encode( segval )
            elif segval <= 0xffffffff and segnam == 'element':
                result          += usint_encode( segtyp + 2 )
                result          += usint_encode( 0 )
                result          += udint_encode( segval )
            else:
                assert False, "Invalid value for numeric EPATH segment %r == %d: %d" (
                    segnam, segval, data )
            break
        if not found:
            assert False, "Invalid EPATH segment %r found in %r" % ( segnam, data )
        assert len( result ) % 2 == 0, \
            "Failed to retain even EPATH word length after %r in %r" % ( segnam, data )

    return usint_encode( len( result ) // 2 ) + result


class cpfdata( cpppo.dfa ):
    """A SendRRData Common Packet Format specifies the number and type of the encapsulated CIP address
    items or data items that follow:

    	.cpf.item_count			uint		2 	Number of items
        .cpf.item[0].type_id		uint		2	Type of item encapsulated		
        .cpf.item[0].length		uint		2	Type of item encapsulated		
        .cpf.item[0].data		octets[length]

    Parse each CPF item into cpf.item_temp, and (after parsing) moves it to cpf.item[x].

    """
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'cpf' )
        name 			= name or kwds.get( 'context' )

        ityp			= uint( 	"type_id", 	context="type_id" )
        ityp[True] = ilen	= uint( 	"length", 	context="length" )
        ilen[None] = idat	= octets( 	"data", 	context="data",
                                                repeat="..length", 
                                                terminal=True )

        # Each item is collected into '..item_temp', and then moved into place into the provided
        # context, probably 'item' (init to [])
        item			= cpppo.dfa( 	"item_temp", 	extension="..item_temp",
                                                initial=ityp )
        item[None] 		= move_if( 	"move", 	source='..item_temp',
                                                initializer=lambda: [],
                                                state=cpppo.state( "moved", terminal=True ))


        # Collect 'number' items, each into item_temp, then move to 'item[x]'
        numb			= uint(		"item_count",	context="item_count" )
        numb[None] 		= cpppo.dfa(    "item", 	context="item", 
                                                initial=item,
                                                repeat='..item_count',
                                                terminal=True )

        super( cpfdata, self ).__init__( name=name, initial=numb, **kwds )


class sendrrdata( cpppo.dfa ):
    """The EtherNet/IP command SendRRData (0x006f) encapsulates an interface and timeout, followed by a
    list of items specified in Common Packet Format.

        .sendrrdata.interface
        .sendrrdata.timeout
        .sendrrdata.cpf...
        
    """
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'sendrrdata' )
        name 			= name or kwds.get( 'context' )
        
        ifce			= udint( 	"interface",	context="interface_handle" )
        ifce[True] = timo	= uint( 	"timeout",	context="timeout", 
                                                terminal=True )
        timo[True] = cpfd	= cpfdata( terminal=True )

        super( sendrrdata, self ).__init__( name=name, initial=ifce, **kwds )

    
class ucmm( cpppo.dfa ):
    """Parses an encapsulated UCMM Unconnected Send (0x52) request, typically found in a SendRRData CPF
    item's data.  No other UCMM services are supported.  Assuming a valid EtherNet/IP header has
    been parsed containing a SendRRData (0x006f) command, containing CPF items, in turn containing
    an item with a type_id of UCMM Unconnected Send (0x52).


    Assumes:

        .service				usint		1 (0x52 for Unconnected Send)

    Produces:

        .path_size				usint		1 (in words, not bytes)
        .path_data				octets[size*2]  *
        .path       			        [
            { 'class':      # },...
         ]
        .ucon_send.priority			usint		1
        .ucon_send.timeout_ticks		usint		1
        .ucon_send.request_size			uint		2
        .ucon_send.request_data			octets[...]	size

    The user should then proceed to parse the embedded request_data, in the context of whatever
    (sometimes vendor-specific, eg. Rockwell Logix5000 ) Object Class/Instance has been addressed.

    """

    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'ucmm' )
        name 			= name or kwds.get( 'context' )
        
        srvc			= usint(	"service",	context="request_service" )
        

        srvc[True] = rpsz	= usint(	"path_siz",	context="request_path_size",
                                                terminal=True ) 
        
        '''
        def initial_list(machine, source, path, data ):
            return []

        # Loop parsing request_path elements 'til we reach the specified request path size.  We'll
        # use a predicate that captures the current value of source.sent, and computes the maximal
        # value of source.sent while we can still parse segments.
        next_seg		= state(  "path_seg" )
        mvsg			= move_if( 	'move_seg', 	context='request_path'
                                                source=req_p_seg, initial=initial_list,
                                                state=pseg )

        def calc_path_end( machine,source,path,data ):
            data[path].request_path__end = source.sends + data[path].request_path_size * 2
            return True

        rpsz[True] 		= decide( 	"path_end", 	state=pseg, predicate=calc_path_end )


        req_p_seg		= 'request_path_segment'
        pseg['\x28'] = el_8_pre	= usint(	'seg_type',	context=req_p_seg, extension=".type" )
        el_8_pre[True] = el_8	= usint( 	'8-bit elem', 	context=req_p_seg, extension='element' )

        rpth[True] = pseg	= usint( 	"")
        '''

        super( ucmm, self ).__init__( name=name, initial=srvc, **kwds )

class typed_data( cpppo.dfa ):
    """Parses CIP typed data, of the form specified by the datatype (must be a relative path within the
    data artifact).  Data elements are parsed 'til exhaustion of input, so the caller should use
    limit= to define the limits of the data in the source symbol input stream; only complete data
    items must be parsed, so this must be exact, and match the specified data type.

    The known data types are:

    	data type	type value	size
    	BOOL 		0x0_c1		1 byte (_=[0-7] indicates relevant bit)
	SINT		0x00c2		1 byte
	INT		0x00c3		2 byte
	DINT		0x00c4		4 byte
	REAL		0x00ca		4 byte
	DWORD		0x00d3		4 byte (32-bit boolean array)
	LINT		0x00c5		8 byte

    """    
    def __init__( self, name=None, datatype=None, **kwds ):
        kwds.setdefault( 'context', 'data' )
        name 			= name or kwds.get( 'context' )
        assert datatype, "Must specify a relative path to the CIP data type; found: %r" % datatype

        slct			= octets_noop(	'select' )
        
        i_8p			= usint( 	'int_8bit',	extension='.integer' )
        i_8d			= octets_noop(	'end_8bit', 	terminal=True )
        i_8d[True]		= i_8p
        i_8p[None]		= move_if( 	'mov_8bit',	source='.integer', 
                                           destination='.list',	initializer=lambda **kwds: [],
                                                state=i_8d )

        i16p			= uint(		'int16bit',	extension='.integer' )
        i16d			= octets_noop(	'end16bit', 	terminal=True )
        i16d[True]		= i16p
        i16p[None]		= move_if( 	'mov16bit',	source='.integer', 
                                           destination='.list',	initializer=lambda **kwds: [],
                                                state=i16d )

        i32p			= udint( 	'int32bit',	extension='.integer' )
        i32d			= octets_noop(	'end32bit', 	terminal=True )
        i32d[True]		= i32p
        i32p[None]		= move_if( 	'mov32bit',	source='.integer', 
                                           destination='.list',	initializer=lambda **kwds: [],
                                                state=i32d )

        slct[None]		= cpppo.decide(	'SINT',	state=i_8p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == 0x00c2 )
        slct[None]		= cpppo.decide(	'INT',	state=i16p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == 0x00c3 )
        slct[None]		= cpppo.decide(	'DINT',	state=i32p,
            predicate=lambda path=None, data=None, **kwds: data[path+datatype] == 0x00c4 )
        
        super( typed_data, self ).__init__( name=name, initial=slct, **kwds )


class logix( cpppo.dfa ):
    """Parses a Logix vendor-specific CIP request.

    If a Logix5000 Controller is being addressed (See Logix5000 Data Access manual, pp 16, Services
    Supported by Logix5000 Controllers), the ucmm.request_data. may contain:
    
	.service			usint		1

    Read Tag Service				0x4c
    Read Tag Fragmented Service			0x52	(unrelated to Unconnected Send, above...)
    Write Tag Service				0x4d
    Write Tag Fragmented Service		0x53
    Read Modify Write Tag Service		0x4e	(not implemented)
					      | 0x80	(indicates response)
 
	.path				extpath		...

	The request-specific data for the supported services are:

    Read Tag Service				0x4c
	.read_tag.elements		uint		2
    Read Tag Service (reply)			0xcc
	.read_tag.type			uint		2
	.read_tag.data.list		[0x...]		1/2/4 (depending on type)
    
    Read Tag Fragmented Service			0x52
	.read_frag.elements		uint		2
	.read_frag.offset		udint		4 (in bytes)
    Read Tag Fragmented Service (reply)		0xd2
	.read_frag.status		usint		1
	.read_frag.status_size		usint		1 (0x00)
	.read_frag.type			uint		2
	.read_frag.data.list		[0x..., 0x...]	* x 1/2/4 (depending on type)

    Write Tag Service				0x4d
	.write_tag.type			uint		2
	.write_tag.data.list		[0x...]		1/2/4 (depending on type)
    Write Tag Service (reply)			0xdd
	.write_tag.status		usint		1
	.write_tag.status_size		usint		1 (0x00)

    Write Tag Fragmented Service		0x53
	.write_frag.type		uint		2
	.write_frag.elements		uint		2
	.write_frag.offset		udint		4 (in bytes)
	.write_frag.data.list		[0x..., 0x...]	* x 1/2/4 (depending on type)
    Write Tag Fragmented Service (reply)	0xd3
	.write_tag.status		usint		1
	.write_tag.status_size		usint		1 (0x00)

    This must be run with a length-constrained 'source' iterable (eg. a fixed-length array harvested
    by a previous parser, eg. ucon_send.request_data).	Since there are no indicators within this
    level of the protocol the indicate the size of the request, the Write Tag [Fragmented] Service
    requests (and Read Tag [Fragmented] replies) do not carry indicators of the size of their data.
    It could be deduced from the type for Write Tag requests (Read Tag replies), but cannot be
    deduced for the Fragmented versions.

    """
    def __init__( self, name=None, **kwds ):
        kwds.setdefault( 'context', 'cip' )
        name 			= name or kwds.get( 'context' )

        slct			= octets_noop(	'select' )	# parse path size and path

        # Read Tag Service
        slct[b'\x4c'[0]]= rtsv	= usint(	'service',  	context='service' )
        rtsv[True]	= rtpt	= extpath()
        rtpt[True]	= rtel	= uint(		'elements', 	context='read_tag',   extension='.element',
                                                terminal=True )
        # Read Tag Service (reply)
        slct[b'\xcc'[0]]= Rtsv	= usint(	'service',  	context='service' )
        Rtsv[True]	= Rtrs	= octets_drop(	'reserved',	repeat=1 )
        Rtrs[True]	= Rtst	= usint( 	'status', 	context='read_tag',  extension='.status' )
        Rtst[b'\x00'[0]]= Rtss	= usint( 	'status_size', 	context='read_tag',  extension='.status_size' )
        Rtss[True]	= Rtdt	= uint( 	'type',   	context='read_tag',  extension='.type' )
        Rtdt[True]		= typed_data( 	'data',   	context='read_tag',  extension='.data',
                                                datatype='..type',
                                                terminal=True )

        # Read Tag Fragmented Service
        slct[b'\x52'[0]]= rfsv	= usint(	'service',	context='service' )
        rfsv[True]	= rfpt	= extpath()
        rfpt[True]	= rfel	= uint(		'elements',	context='read_frag',  extension='.elements' )
        rfel[True]		= udint( 	'offset',   	context='read_frag',  extension='.offset',
                                                terminal=True )
        # Read Tag Fragmented Service (reply)
        slct[b'\xd2'[0]]= Rfsv	= usint(	'service',  	context='service' )
        Rfsv[True]	= Rfrs	= octets_drop(	'reserved',	repeat=1 )
        Rfrs[True]	= Rfst	= usint( 	'status', 	context='read_frag',  extension='.status' )
        Rfst[b'\x00'[0]]= Rfss	= usint( 	'status_size', 	context='read_frag',  extension='.status_size' )
        Rfss[True]	= Rfdt	= uint( 	'type',   	context='read_frag',  extension='.type' )
        Rfdt[True]		= typed_data( 	'data',   	context='read_frag',  extension='.data',
                                                datatype='..type',
                                                terminal=True )

        # Write Tag Service
        slct[b'\x4d'[0]]= wtsv	= usint(	'service',  	context='service' )
        wtsv[True]	= wtpt	= extpath()
        wtpt[True]	= wtty	= uint(		'type',   	context='write_tag',  extension='.type' )
        wtty[True]		= typed_data( 	'data',   	context='write_tag',  extension='.data',
                                                datatype='..type',
                                                terminal=True )
        # Write Tag Service (reply)
        slct[b'\xdd'[0]]= Wtsv	= usint(	'service',  	context='service' )
        Wtsv[True]	= Wtrs	= octets_drop(	'reserved',	repeat=1 )
        Wtrs[True]	= Wtst	= usint( 	'status', 	context='read_frag',  extension='.status' )
        Wtst[b'\x00'[0]]	= usint( 	'status_size', 	context='read_frag',  extension='.status_size',
                                                terminal=True )

        # Write Tag Fragmented Service
        slct[b'\x53'[0]]= wfsv	= usint(	'service',  	context='service' )
        wfsv[True]	= wfpt	= extpath()
        wfpt[True]	= wfty	= uint(		'type',     	context='write_frag', extension='.type')
        wfty[True]	= wfel	= uint(		'elements', 	context='write_frag', extension='.elements')
        wfel[True]	= wfof	= udint( 	'offset',   	context='write_frag', extension='.offset' )
        wfof[True]		= typed_data( 	'data',   	context='write_frag', extension='.data',
                                                datatype='..type',
                                                terminal=True )
        # Write Tag Fragmented Service (reply)
        slct[b'\xd3'[0]]= Wtsv	= usint(	'service',  	context='service' )
        Wtsv[True]	= Wtrs	= octets_drop(	'reserved',	repeat=1 )
        Wtrs[True]	= Wtst	= usint( 	'status', 	context='write_frag',  extension='.status' )
        Wtst[b'\x00'[0]]	= usint( 	'status_size', 	context='write_frag',  extension='.status_size',
                                                terminal=True )

        super( logix, self ).__init__( name=name, initial=slct, **kwds )


