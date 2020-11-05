
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2020, Hard Consulting Corporation.
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
__email__                       = "perry@dominionrnd.com"
__copyright__                   = "Copyright (c) 2020 Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


"""
enip.udt	-- Implements User-Defined Types

"""

import contextlib
import logging
import sys
import traceback

from ... import misc
from ...dotdict import dotdict
from ...automata import peekable, type_str_base
from . import parser

log				= logging.getLogger( "enip.udt" )


class tag_struct( object ):
    """Parses/produces binary data according to a UDT structure in the supplied data_type dict.  The
    UDT structure definition is compatible with those produced by pycomm3.

    This parse function is not incremental; it parses the full bytes rec and returns the resultant
    decoded dict, or raises an Exception.

    """
    def __init__( self ):
        """Prepare to parse.  We'll identify the target sub-tag data type in each case w/ a
        data.tag_type.

        """
        self.typed_data_machine	= parser.typed_data( tag_type=".tag_type" )

    def parse( self, rec, data_type ):
        """Pull out each of the Tag struct's attribute and their value(s) as a record"""
        record			= dotdict()

        for internal_tag_name in data_type["attributes"]:
            internal_tag	= data_type["internal_tags"][internal_tag_name]
            offset		= internal_tag["offset"]
            type_name		= internal_tag["data_type"]

            if isinstance( type_name, dict ):
                # A sub-struct; recursion!
                assert internal_tag["tag_type"] == "struct"
                item		= self.parse( rec[offset:], type_name )
                # Special tag structs named "STRING" are handled...  These are not CIP STRING (UINT
                # size) or SHORT_STRING (USINT size).  The LEN subvalue (a DINT, oddly) encodes the
                # length, and the DATA subvalue (an SINT array) contains the string data.  So, pull
                # these out, and convert it to a standard CIP STRING for parsing.
                if type_name["name"] == "STRING":
                    item	= ''.join( chr( c ) for c in item.DATA[:item.LEN] )
            elif isinstance( type_name, type_str_base ):
                # Simple atomic data type name (eg "DINT"; use parser.DINT() as parser, and parse
                # data.  May be a single item, or an array.
                assert internal_tag["tag_type"] == "atomic"
                assert "STRING" not in type_name

                raw		= rec[offset:]
                if type_name == "BOOL" and "bit" in internal_tag:
                    # BOOL tags may have a bit mask; apply it before parsing
                    assert "array" not in internal_tag
                    rawarr	= bytearray( raw )
                    rawarr[0]  &= 1 << internal_tag["bit"]
                    raw		= bytes( rawarr )
                try:
                    parser_cls	= getattr( parser, type_name ) 	# eg. "DINT"
                    count	= internal_tag.get( "array" )	# None/0 --> scalar
                    size	= ( count or 1 ) * parser_cls.struct_calcsize
                    source	= peekable( raw[:size] )
                    data	= dotdict( dict( typed_data = dict( tag_type = parser_cls.tag_type )))
                    with self.typed_data_machine as machine:
                        with contextlib.closing( machine.run( source=source, data=data )) as engine:
                            for m,s in engine:
                                pass
                    if log.isEnabledFor( logging.DETAIL ):
                        log.detail( "{internal_tag_name:32} ==> {type_name:10}: {data.typed_data.data!r:24} == {dump}".format(
                            internal_tag_name=internal_tag_name, type_name=type_name, data=data,
                            dump=misc.hexdump( raw[:size], length=8 )))
                    item	= data.typed_data.data
                    if not count: # None/0 --> scalar
                        item	= item[0]
                except Exception as exc:
                    log.info( ''.join( traceback.format_exception( *sys.exc_info() )))
                    item	= exc
            else:
                raise RuntimeError( "Unrecognized type_name: {type_name!r}".format( type_name=type_name ))
            record[internal_tag_name] = item
        return record

    def produce( self, record, data_type, structure_size=None ):
        """Produce the encoded bytes representing the supplied Tag struct record"""
        if structure_size is None:
            structure_size	= data_type["template"]["structure_size"]
        # Begin w/ an empty 0x00 bytearray of the correct structure_siz
        rec			= bytearray( int( structure_size ))
        for internal_tag_name in data_type["attributes"]:
          try:
            internal_tag	= data_type["internal_tags"][internal_tag_name]
            offset		= internal_tag["offset"]
            type_name		= internal_tag["data_type"]
            if internal_tag_name not in record:
                continue # Leave any non-existant elements as 0/empty/null

            if isinstance( type_name, dict ):
                # A sub-struct; recursion.  A "STRING" struct w/ a DINT .LEN and SINT[] .DATA.  Encode
                # string as ISO-8859-1, decode its LEN and DATA.
                if type_name["name"] == "STRING" and set( type_name["attributes"] ) == {"LEN", "DATA"}:
                    stringdata	= bytearray(str( record[internal_tag_name] ).encode( 'iso-8859-1' ))
                    data	= dotdict(
                        LEN	= len( stringdata ),
                        DATA	= list( map( int, stringdata )),
                    )
                else:
                    data	= record[internal_tag_name]
                item		= self.produce( data, type_name )
            else:
                try:
                    parser_cls	= getattr( parser, type_name ) 	# eg. "DINT"
                    count	= internal_tag.get( "array" )	# None/0 --> scalar
                    size	= ( count or 1 ) * parser_cls.struct_calcsize
                except:
                    log.info( ''.join( traceback.format_exception( *sys.exc_info() )))
                    raise
                elements	= record[internal_tag_name]
                if not count:
                    elements	= [ elements ]
                data		= dotdict( dict(
                    data	= elements,
                    tag_type	= parser_cls.tag_type,
                ))
                item		= parser.typed_data.produce( data )
                if type_name == "BOOL" and "bit" in internal_tag:
                    # We shouldn't assume a BOOL True encodes to b'\xff'...
                    truthy	= item != b'\x00'
                    item	= bytearray( [ 1 << internal_tag["bit"] if truthy else 0 ] )

            beg			= offset
            end			= offset + len( item )
            oring		= type_name == "BOOL" and "bit" in internal_tag
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "{internal_tag_name:32} <== {type_name!r:10}: [{beg:3}:{end:3}] {assign} {dump}".format(
                    internal_tag_name=internal_tag_name, type_name=type_name,
                    beg=beg, end=end, assign='|=' if oring else ' =',
                    dump=misc.hexdump( item, length=8 )))
            if oring:
                assert end == beg+len(item)
                rec[beg:end]	= bytearray( a|b for a,b in zip( rec[beg:end], item ))
            else:
                rec[beg:end]	= item
          except Exception as exc:
            log.warning( "Failed to produce {type_name} {internal_tag_name!r} at offset {offset}: {exc!r}".format(
                internal_tag_name=internal_tag_name, exc=exc, offset=offset, type_name=type_name ))
        return bytes( rec )


class STRUCT_typed( parser.STRUCT ):
    """A STRUCT with a known data_type (ie. produced by pycomm3, or compatible).  Knows how to parse
    raw data into structures of the specified type, and how to produce a stream of data from
    structures of the target data_type.  The raw STRUCT data is parsed into .data.input, and is then
    post-processed by tag_struct to extract the UDT sub-tags.

    Parses/produces a single record of the STRUCT_typed.data_type at a time.

    Only UDTs with a STRUCT data_types prefixed by a .structure_tag are handled by this code.  For
    example, reading/writing a sub-tag of a STRUCT that is a simple CIP type eg. DINT or array of
    DINT do *not* prefix their Read/Write Tag [Fragmented] data with a STRUCT tag.  THus, the values
    supplied with these requests/replies do *not* use the STRUCT data type.  It is expected that the
    CIP device handling these requests will A) recognize that they are symbolically addressing a
    sub-tag of a STRUCT, and B) access and decode the target UDT, and then access the requested
    sub-tag within the decoded data (and finally encode and write the full, updated UDT value).

    """
    def __init__( self, name=None, data_type=None, structure_tag=None, **kwds ):
        self.data_type		= data_type
        self.tag_encoder	= tag_struct()
        if structure_tag is None:
            structure_tag	= self.structure_tag
        assert structure_tag == self.structure_tag
        if name is None:
            name		= self.structure_name
        super( STRUCT_typed, self ).__init__( name=name, structure_tag=structure_tag, **kwds )
        rec_cnt			= self.dimensions[0]
        rec_siz			= self.struct_calcsize
        log.info( "{name} is a {size}-byte ({rec_cnt} x {rec_siz} bytes/UDT) of {self.structure_name}".format(
            self=self, name=name, size=rec_cnt*rec_siz, rec_cnt=rec_cnt, rec_siz=rec_siz ))

    def terminate( self, exception, machine, path, data ):
        """Decode the raw STRUCT data.input into the specified UDT.

        For an UDT that defines an array of UDTs, ["data_type"] contains the type of each element.

        """
        ours			= self.context( path=path )
        subt			= data[ours] if ours else data
        assert subt and ( 'data.input' in subt ), \
            "Couldn't locate raw .data.input in data[{ours}]: {data!r}".format( ours=ours, data=data )
        super( STRUCT_typed, self ).terminate( exception=exception, machine=machine, path=path, data=data )
        record			= self.tag_encoder.parse( subt.data.input, self.structure_array_type )
        if log.isEnabledFor( logging.INFO ):
            log.info( "Parsed {record!r} from {subt!r}".format( record=record, subt=subt ))
        subt.update( record )

    @property
    def structure_array_type( self ):
        return self.data_type["data_type"]
    @property
    def structure_tag( self ):
        return self.structure_array_type["template"]["structure_handle"]
    @property
    def structure_name( self ):
        return self.structure_array_type["name"]
    @property
    def dimensions( self ):
        return self.data_type["dimensions"]
    
    @property
    def struct_calcsize( self ):
        return self.data_type["data_type"]["template"]["structure_size"]
    
    def produce( self, value, **kwds ):
        """Encode the supplied UDT value into a raw data.input payload."""
        value.data.input	= self.tag_encoder.produce( value, self.structure_array_type )
        return super( STRUCT_typed, self ).produce( value, **kwds )

