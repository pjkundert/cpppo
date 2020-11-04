
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
enip.device	-- support for implementing an EtherNet/IP device Objects and Attributes

"""
__all__				= ['dialect', 'lookup_reset', 'lookup', 'resolve', 'resolve_element',
                                   'redirect_tag', 'resolve_tag',
                                   'parse_int', 'parse_path', 'parse_path_elements', 'parse_path_component',
                                   'port_link', 'parse_route_path', 'parse_connection_path',
                                   'RequestUnrecognized', 'Object', 'Attribute',
                                   'Connection_Manager', 'Message_Router', 'Identity', 'TCPIP']

import ast
import contextlib
import itertools
import json
import logging
import random
import struct
import sys
import threading
import traceback

try:
    import reprlib
except ImportError:
    import repr as reprlib

import configparser # Python2 requires 'pip install configparser'

from ...dotdict import dotdict
from ...automata import ( type_str_base,
                          peekable, rememberable,
                          decide,
                          dfa, dfa_post, state )
from ... import misc
from . import defaults
from .parser import ( UDINT, DINT, DWORD, INT, UINT, WORD, USINT,
                      EPATH, EPATH_padded, SSTRING, STRING, IFACEADDRS,
                      typed_data,
                      octets, octets_encode, octets_noop, octets_drop, move_if,
                      enip_format, status )

# Default "dialect" of EtherNet/IP CIP protocol.  If no Message Router object is available (eg. we
# are a "Client", not a "Controller"), then we need to know the dialect of EtherNet/IP CIP to use.
# For that, we need a parser defined.  All client/connector instances use the same globally-defined
# cpppo.server.enip.client.dialect parser.  The default dialect is "Logix" (eg. Read/Write Tag
# [Fragmented], etc.)
dialect				= None		# Default: typically logix.Logix

log				= logging.getLogger( "enip.dev" )

# 
# directory	-- All available device Objects and Attributes (including the "class" instance 0)
# lookup	-- Find a class/instance/attribute
# 
#     Object/Instance/Attribute lookup.  The Object is stored at (invalid)
# attribute_id 0.   For example:
# 
#         directory.6.0		Class 6, Instance 0: (metaclass) directory of Object/Attributes
#         directory.6.1		Class 6, Instance 1: (instance)  directory of Object/Attributes
#         directory.6.1.0	Class 6, Instance 1: device.Object (python instance)
#         directory.6.1.1	Class 6, Instance 1, Attribute 1 device.Attribute (python instance)
# 
directory			= dotdict()

def __directory_path( class_id, instance_id=0, attribute_id=None ):
    """It is not possible to in produce a path with an attribute_id=0; this is
    not a valid Attribute ID.  The '0' entry is reserved for the Object, which is
    only accessible with attribute_id=None."""
    assert attribute_id != 0, \
        "Class %5d/0x%04x, Instance %3d; Invalid Attribute ID 0"
    return str( class_id ) \
        + '.' + str( instance_id ) \
        + '.' + ( str( attribute_id if attribute_id else 0 ))

def lookup( class_id, instance_id=0, attribute_id=None ):
    """Lookup by path ("#.#.#" string type), or numeric class/instance/attribute ID"""
    exception			= None
    try:
        key			= class_id
        if not isinstance( class_id, type_str_base ):
            assert type( class_id ) is int
            key			= __directory_path(
                class_id=class_id, instance_id=instance_id, attribute_id=attribute_id )
        res			= directory.get( key, None )
    except Exception as exc:
        exception		= exc
        res			= None
    finally:
        log.detail( "Class %5d/0x%04X, Instance %3d, Attribute %5r ==> %s",
                    class_id, class_id, instance_id, attribute_id, 
                    res if not exception else ( "Failed: %s" % exception ))
    return res

# 
# symbol	-- All known symbolic address
# redirect_tag	-- Direct a tag to a class, instance and attribute
# resolve*	-- Resolve the class, instance [and attribute] from a path or tag.
# 
# A path is something of the form:
# 
#     {
#         'size':6,
#         'segment':[
#             {'symbolic':'SCADA'}, 
#             {'element':123}]
#     }
# 
# Multiple symbolic and element entries are allowed.  This is used for addressing structures:
# 
#     boo[3].foo
# 
# or for indexing multi-dimensional arrays:
# 
#     table[3][4]
# 
# or returning arbitrary sets of elements from an array:
# 
#     array[3,56,179]
# 
# The initial segments of the path must address a class and instance.
# 
#TODO: A Tag must be able to (optionally) specify an element
symbol				= {}
symbol_keys			= ('class', 'instance', 'attribute')


def lookup_reset():
    """Clear any known CIP Objects, and any Tags referencing to their Attributes.  Note that each CIP
    Object-derived class will retain its .max_instance variable, so future instances will get new
    (higher) Instance IDs, unless you provide an instance_id=... to the constructor.

    WARNING: This is really mostly for testing multiple CIP Object configurations in a single Python
    interpreter run, and is not recommended for production usage.  It suffers from removing
    references to Object and Attribute instances that are necessary for internal consistency in the
    CIP heirarchy, so if the directory is reset, avoid interogating any Object or Attribute from the
    prior configuration.  See MaxInstance.value, for example.
    """
    global directory
    global symbol
    directory			= dotdict()
    symbol			= {}


def redirect_tag( tag, address ):
    """Establish (or change) a tag, redirecting it to the specified class/instance/attribute address.
    Make sure we stay with only str type tags (mostly for Python2, in case somehow we get a Unicode
    tag).  Multi-segment symbolic tags are expected to be looked up as: symbol["<symbol1>.<symbol2>"]

    All Tag lookups are case-insensitive, so are stored lower-case.
    """
    assert isinstance( address, dict )
    assert all( k in symbol_keys for k in address )
    assert all( k in address     for k in symbol_keys )
    symbol[str( tag ).lower()]	= address
    return tuple( address[k] for k in symbol_keys )


def resolve_tag( tag ):
    """Return the (class_id, instance_id, attribute_id) tuple corresponding to tag, or None if not specified"""
    address			= symbol.get( str( tag ).lower(), None )
    if address:
        return tuple( address[k] for k in symbol_keys )
    return None


def resolve( path, attribute=False ):
    """Given a path, returns the fully resolved (class,instance[,attribute]) tuple required to lookup an
    Object/Attribute.  Won't allow over-writing existing elements (eg. 'class') with symbolic data
    results; build up Tags from multiple symbolic paths, eg. "Symbol.Subsymbol".  We only recognize
    {'symbolic':<str>}, ... and {'class':<int>}, {'instance':<int>}, {'attribute':<int>} paths.

    Other valid paths segments (eg. {'port':...}, {'connection':...}) are not presently usable in
    our Controller communication simulation.

    Call with attribute=True to force resolving to the Attribute level; otherwise, always returns
    None for the attribute.

    """

    result			= { 'class': None, 'instance': None, 'attribute': None }
    tag				= '' # developing symbolic tag "Symbol.Subsymbol"

    for term in path['segment']:
        if ( result['class'] is not None and result['instance'] is not None
             and ( not attribute or result['attribute'] is not None )):
            break # All desired terms specified; done! (ie. ignore 'element')
        working			= dict( term )
        while working:
            # Each term is something like {'class':5}, {'instance':1}, or (from symbol table):
            # {'class':5,'instance':1}.  Pull each key (eg. 'class') from working into result,
            # but only if not already defined.
            for key in result:
                if key in working:
                    # If we hit non-symbolic segments, any tag resolution had better be complete
                    assert result[key] is None, \
                        "Failed to override %r==%r with %r from path segment %r in path %r" % (
                            key, result[key], working[key], term, path['segment'] )
                    result[key]	= working.pop( key ) # single 'class'/'instance'/'attribute' seg.
            if working:
                assert 'symbolic' in working, \
                    ( "Unrecognized symbolic name %r found in path %r" % ( tag, path['segment'] )
                      if tag
                      else "Invalid term %r found in path %r" % ( working, path['segment'] ))
                tag	       += ( '.' if tag else '' ) + str( working['symbolic'] )
                working		= None
                if tag.lower() in symbol:
                    working	= dict( symbol[tag.lower()] )
                    tag		= ''

    # Any tag not recognized will remain after all resolution complete
    assert not tag, \
        "Unrecognized symbolic name %r found in path %r" % ( tag, path['segment'] )

    assert ( result['class'] is not None and result['instance'] is not None
             and ( not attribute or result['attribute'] is not None )), \
        "Failed to resolve required Class (%r), Instance (%r) %s Attribute(%r) from path: %r" % (
            result['class'], result['instance'], "and the" if attribute else "but not",
            result['attribute'], path['segment'] )
    result			= result['class'], result['instance'], result['attribute'] if attribute else None
    log.detail( "Class %5d/0x%04x, Instance %3d, Attribute %5r <== %r",
                result[0], result[0], result[1], result[2], path['segment'] )

    return result


def resolve_element( path ):
    """Resolve an element index tuple from the path; defaults to (0, ) (the 0th element of a
    single-dimensional array).

    """
    element		= []
    for term in path['segment']:
        if 'element' in term:
            element.append( term['element'] )
            break
    return tuple( element ) if element else (0, )

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

# 
# Parsing of a symbolic tag like: 'Tag.Sub_Tag[<index>].Yet_More[<index>-<index>]', or a numeric tag
# like: '@<class>/<instance>/<attribute>/<element>' or "@<class>/{"connection":123}/<attribute>".
# 
# parse_path -- Returns a list containing EPATH segments.
# parse_path_elements -- Returns '.'-separated EPATH segments, w/ element, count if any (otherwise None)
# parse_path_component -- Parses a single 'str' EPATH component
# 
def parse_path( path, elm=None ):
    """Convert a "."-separated sequence of "Tag" or "@<class>/<instance>/<attribute>" to a list of
    EtherNet/IP EPATH segments (if a string is supplied). Numeric form allows
    <class>[/<instance>[/<attribute>[/<element>]]] by default, or any segment type at all by
    providing it in JSON form, eg. .../{"connection":100}.

    Resultant path will be a list of the form [{'symbolic': "Tag"}, {'element': 3}], or [{'class':
    511}, {'instance': 1}, {'attribute': 2}].

    If strings are supplied for path or element, any numeric data (eg. class, instance, attribute or
    element numbers) default to integer (eg. 26), but may be escaped with the normal base indicators
    (eg. 0x1A, 0o49, 0b100110).  Leading zeros do NOT imply octal.

    Also supported is the manual assembly of the path segments: @{"class":0x04}/5/{"connection":100}

    A trailing element count may be included in the path, but this interface provides no mechanism
    to return an element count.  A default <element> 'elm' keyword (if non-None) may be supplied.

    """
    return parse_path_elements( path, elm=elm )[0]


def parse_path_elements( path, elm=None, cnt=None ):
    """Returns (<path>,<element>,<count>).  If an element is specified (eg. Tag[#]), then it will be
    added to the path (or replace any existing element segment at the end of the path) and returned,
    otherwise None will be returned.  If a count is specified (eg. Tag[#-#] or ...*#), then it will be
    returned; otherwise a None will be returned.

    Any "."-separated EPATH component (except the last) including an element index must specify
    exactly None/one element, eg: "Tag.SubTag[5].AnotherTag[3-4]".

    A default <element> 'elm' and/or <count> 'cnt' (if non-None) may be specified.

    """
    if isinstance( path, list ) and len( path ) == 1 and isinstance( path[0], type_str_base ):
        # Unpack single-element list containing a string
        path			= path[0]
    elif not isinstance( path, type_str_base ):
        # Already better be a list-like CIP path...
        assert isinstance( path, list ) and all( isinstance( p, dict ) for p in path ), \
            "parse_path unrecognized: %r" % ( path, )
        return path,None,None

    segments			= []
    p				= path.split( '.' )
    while len( p ) > 1:
        s,e,c			= parse_path_component( p.pop( 0 ))
        assert c in (None,1), "Only final path segment may specify multiple elements: %r" % ( path )
        segments	       += s
    s,elm,cnt			= parse_path_component( p[0], elm=elm, cnt=cnt )
    return segments+s,elm,cnt


def parse_path_component( path, elm=None, cnt=None ):
    """Parses a single str "@class/instance/attribute" or "Tag" segment, optionally followed by a
    "[<begin>-<end>]" and/or "*<count>".  Returns <path>,<element>,<count>.  Priority for computing
    element count is the "[<begin>-<end>]" range, any specified "*<count>", and finally the supplied
    'cnt' (default: None).

    """
    if '*' in path:
        path,cnt		= path.split( '*', 1 )
        cnt			= parse_int( cnt )

    if '[' in path:
        path,elm		= path.split( '[', 1 )
        elm,rem			= elm.split( ']' )
        assert not rem, "Garbage after [...]: %r" % ( rem )
        lst			= None
        if '-' in elm:
            elm,lst		= elm.split( '-' )
            lst			= int( lst )
        elm			= int( elm )
        if lst is not None:
            cnt			= lst + 1 - elm
            assert cnt > 0, "Invalid element range %d-%d" % ( elm, lst )

    segments			= []
    if path.startswith( '@' ):
        # Numeric and/or JSON. @<class>/<instance>/<attribute>/<element> (up to 4 segments)
        try:
            defaults		= ('class','instance','attribute','element')
            for i,seg in enumerate( path[1:].split( '/' )):
                if seg.startswith( '{' ):
                    trm		= json.loads( seg )
                else:
                    assert i < len( defaults ), "No default segment type beyond %r" % ( defaults )
                    trm		= {defaults[i]: parse_int( seg )}
                segments.append( trm )
        except Exception as exc:
            raise Exception( "Invalid @%s; 1-4 (default decimal) terms, eg. 26, 0x1A, {\"connection\":100}, 0o46, 0b100110: %s" % (
                '/'.join( '<%s>' % d for d in defaults ), exc ))
    else:
        # Symbolic Tag
        segments.append( { "symbolic": path } )

    if elm is not None:
        if not segments or 'element' not in segments[-1]:
            segments.append( {} )
        segments[-1]['element']	= elm

    return segments,elm,cnt


def port_link( pl ):
    """Convert "1/1" or "2/1.2.3.4" (or validate provided dict) to: {"port": 1, "link": 1} or {"port":
    2, "link": "1.2.3.4"}.  Link may be integer or IPv4 dotted-quad address.  Raises an Exception if
    not valid port/link types.  This result could be one element of a route_path list.

    """
    if isinstance( pl, type_str_base ):
        pl			= map( str.strip, str( pl ).split( '/', 1 ))
    if not isinstance( pl, dict ):
        # If its not already a dict, it better be an iterable satisfying exactly [<port>, <link>]
        try:
            port,link		= pl
        except:
            raise AssertionError( "port/link: must have exactly 2 components, not: %r" % ( pl ))
        pl			= { "port": port, "link": link }
    assert isinstance( pl, dict ) and 'port' in pl and 'link' in pl, \
        """port/link: must be dict containing { "port": <int>, "link": <int>/"<ip>" }"""

    try:
        pl["port"]		= int( pl["port"] )
    except:
        raise AssertionError( "port/link: port must be an integer" )
    assert pl["port"] > 0, \
        "port/link: port number must be > 0"

    try:
        pl["link"]		= int( pl["link"] )
    except: # Not an int; must be an IPv{4,6} address; canonicalize
        try:
            pl["link"]		= str( misc.ip( pl["link"] ))
        except Exception as exc:
            raise AssertionError( "port/link: %r: %s" % ( pl["Link"], exc ))
    return pl


def parse_route_path( route_path, trailer_parser=None ):
    """A route path is None/0/False, or list of port/link[/port/link] segments.  Allows a single
    port/link element to be specified bare, and will en-list it, eg: "--route_path=1/2".
    
    Must either result in a Falsey, or a valid sequence of port/link[/port/link...], followed by
    whatever sequence trailer_parser produces (if supplied).

    """
    if isinstance( route_path, type_str_base ):
        try:
            route_path		= json.loads( route_path )
            if route_path and isinstance( route_path, dict ):
                # a dict; validate as eg. [{"port":<int>,"link":<int>/"<ip>"}]
                route_path	= [route_path]
            assert isinstance( route_path, list ), \
                "route_path invalid; must resolve to list, not: %r" % ( route_path, )
        except Exception as exc:
            # Handle multiple route_path strings like: "1/0/2/1.2.3.4", by splitting on even '/'.
            # Ceases splitting when port_link fails to recognize a component; the remainder is
            # re-joined and appended for processing in final stage, below.
            assert route_path[:1] not in '[{"', \
                "route_path JSON invalid: %r; %s" % ( route_path, exc, ) # JSON was intended, but was invalid
            rps			= []
            pls			= iter( route_path.split( '/' ))
            pl			= list( itertools.islice( pls, 2 ))
            while pl:
                try:
                    rps.append( port_link( pl ))
                except Exception as exc:
                    # Done processing; this wasn't a valid port_link element
                    break
                pl		= list( itertools.islice( pls, 2 ))
            # Done all port_link segments; put any remaining back on the end
            trailer		= '/'.join( pl + list( pls ))
            if trailer:
                rps.append( trailer )
            log.info( "Converted route_path %r to %r", route_path, rps )
            route_path		= rps
        else:
            # Was JSON; better be one of the known types
            assert isinstance( route_path, (type(None),bool,int,list)), \
                "route_path: must be null/0/false/true or a (sequence of) port/link, not: %r" % ( route_path )
    if route_path:
        # not a JSON 0/false/null (0/False/None); must be a sequence of str/dict port_link elements,
        # followed optionally by something acceptable to trailer_parser (producing a sequence)
        rps			= []
        pls			= iter( route_path )
        pl			= next( pls, None )
        while pl:
            try:
                rps.append( port_link( pl ))
            except Exception as exc:
                break
            pl			= next( pls, None )
        trs			= ( [] if pl is None else [ pl ] ) + list( pls )
        if trs:
            # All trailer elements are CIP paths
            assert trailer_parser, "route_path unhandled: %r" % ( trs, )
            try:
                pth		= trailer_parser( trs )
                rps.extend( pth )
            except Exception as exc:
                raise AssertionError( "route_path invalid: %s" % ( exc ))
        log.info( "Converted route_path %r to %r", route_path, rps )
        route_path		= rps
    return route_path


def parse_connection_path( path ):
    """A Connection Path (eg. for Forward Open) consists of a route path, eg. 2/192.168.0.24/1/0
    (eg. port 2, link 192.168.0.24, then port 1 (backplane), link 0.  Following may optionally be
    another '/' + CIP path, eg. "/@2/1" (Connection Manaager), "/@1/1/7" (CIP Identity ProductName
    SSTRING), or "/TagName[0].SubName").  The only restriction is that a 'symbolic' CIP path may not
    contain a '/' character.

    The trailing CIP path is identified typically by the presense of a non-[0-9.:] element (ie. not
    a port/link component); once the parse_route_path and port_link ceases to be able to parse
    '/'-separated components, then parse_path must successfully consume the remainder.

    The only ambiguity is between IPv6 addresses eg. '2001:db8::1' and Tag names; therefore, we do
    not support Tag names with ':' symbols in them; if necessary, supply these as JSON-encoded
    connection paths.

    """
    return parse_route_path( path, trailer_parser=parse_path )


# 
# EtherNet/IP CIP Object Attribute
# 
class Attribute( object ):
    """A simple Attribute just has a default scalar value of 0.  We'll instantiate an instance of the
    supplied enip.TYPE/STRUCT class as the Attribute's .parser property.  This can be used to parse
    incoming data, and produce the current value in bytes form.

    The value defaults to a scalar 0, but may be configured as an array by setting default to a list
    of values of the desired array size.

    If an error code is supplied, requests on the Attribute should fail with that code.

    To interface to other types of data (eg. remote data), supply as 'default' an object that
    supplies the following interface:

        o.__len__()			-- DOESN'T EXIST if scalar; returns number of elements if vector (a str is considered scalar)
        o.__repr__()			-- Some representation of the object; a few of its elements, an address
        o.__getitem__(b[:e[:s]])	-- Raise TypeError if scalar; return an item/slice if a vector
        o.__setitem(k,v)		-- Raise TypeError if scalar, store the value(s) v at index/slice k if vector
        o.__int__(), __float__()	-- Scalars should directly implement conversion methods; vectors should return
            				   objects (on [int]) or iterables of objects (on [slice]) convertible to
    					   int/float.  These will be accessed by functions such as struct.pack()

    Note that it is impossible to capture assignment to a scalar value; all remote data must be
    vectors, even if they only have a single element.  However, for Attributes whose underlying
    'default' value is a simple scalar type, we'll support simple value assignment (it will replace
    the underlying 'default' value with a new instance of the same type).

    Therefore, for scalar types, it is important to ensure that the original default=... value supplied is
    of the correct type; eg. 'float' for REAL, 'int', for SINT/INT/DINT types, etc.

    """
    MASK_GA_SNG			= 1 << 0
    MASK_GA_ALL			= 1 << 1

    def __init__( self, name, type_cls, default=0, error=0x00, mask=0 ):
        self.name		= name
        self.default	       	= default
        self.scalar		= isinstance( default, type_str_base ) or not hasattr( default, '__len__' )
        self.parser		= type_cls()
        self.error		= error		# If an error code is desired on access
        self.mask		= mask		# May be hidden from Get Attribute(s) All/Single

    @property
    def value( self ):
        return self.default
    @value.setter
    def value( self, v ):
        assert self.scalar, "Scalar assignment to %s not supported" % type( self.default )
        self.default		= type(self.default)( v )

    def __str__( self ):
        return "%-24s %10s%s == %s" % (
            self.name, self.parser.__class__.__name__,
            ( ("[%4d]" % len( self )) if not self.scalar else ( " x%-4d" % len( self )) ), reprlib.repr( self.value ))
    __repr__ 			= __str__

    def __len__( self ):
        """Scalars are limited to 1 indexable element, while arrays (implemented as lists) are limited to
        their length. """
        return 1 if self.scalar else len( self.value )

    # Indexing.  This allows us to get/set individual values in the Attribute's underlying data
    # repository.  Simple, linear slices are supported.
    def _validate_key( self, key ):
        """Support simple, linear beg:end slices within Attribute len with no truncation (accepts
        slices like [:], with a slice.stop of None); even on scalars, allows [0:1].  Returns type of
        index, which must be slice or int.  We do not validate that the length of the assignment
        equals the length of the slice!  The caller must ensure this is the same, or truncation /
        extension of the underlying datastore would occur.

        """
        if isinstance( key, slice ):
            start,stop,stride	= key.indices( len( self ))
            if stride == 1 and start < stop and stop <= len( self ) and key.stop in (stop,None):
                return slice
            raise KeyError( "%r indices %r too complex, empty, or beyond Attribute length %d" % (
                key, (start,stop,stride), len( self )))
        if not isinstance( key, int ) or key >= len( self ):
            raise KeyError( "Attempt to access item at key %r beyond Attribute length %d" % ( key, len( self )))
        return int

    def __getitem__( self, key ):
        if self._validate_key( key ) is slice:
            # Returning slice of elements; always returns an iterable
            return [ self.value ] if self.scalar else self.value[key]
        # Returning single indexed element; always returns a scalar
        return self.value if self.scalar else self.value[key]

    def __setitem__( self, key, value ):
        """Allow setting a scalar or indexable array item.  We will not confirm length of supplied value for
        slices, to allow iterators/generators to be supplied."""
        if log.isEnabledFor( logging.INFO ):
            log.info( "Setting %s %s %s[%r] to %r", "scalar" if self.scalar else "vector", type( self.value ),
                      ( repr if log.isEnabledFor( logging.DEBUG ) else misc.reprlib.repr )( self.value ),
                      key, value )
        if self._validate_key( key ) is slice:
            # Setting a slice of elements; always supplied an iterable; must confirm size
            if self.scalar:
                self.value	= next( iter( value ))
            else:
                self.value[key]	= value
            return
        # Setting a single indexed element; always supplied a scalar
        if self.scalar:
            self.value		= value
        else:
            self.value[key] 	= value

    def produce( self, start=0, stop=None ):
        """Output the binary rendering of the current value, using enip type_cls instance configured,
        to produce the value in binary form ('produce' is normally a classmethod on the type_cls).
        Both scalar and vector Attributes respond to appropriate slice indexes.

        """
        if stop is None:
            stop		= len( self )
        return b''.join( self.parser.produce( v ) for v in self[start:stop] )


class MaxInstance( Attribute ):
    def __init__( self, name, type_cls, class_id=None, **kwds ):
        assert class_id is not None
        self.class_id		= class_id
        super( MaxInstance, self ).__init__( name=name, type_cls=type_cls, **kwds )

    @property
    def value( self ):
        """Look up any instance of the specified class_id; it has a max_instance property, which
        is the maximum instance number allocated thus far. """
        return lookup( self.class_id, 0 ).max_instance

    def __setitem__( self, key, value ):
        raise AssertionError("Cannot set value")


class NumInstances( MaxInstance ):
    def __init__( self, name, type_cls, **kwds ):
        super( NumInstances, self ).__init__( name=name, type_cls=type_cls, **kwds )

    @property
    def value( self ):
        """Count how many instances are presently in existence; use the parent class MaxInstances.value."""
        return sum( lookup( class_id=self.class_id, instance_id=i_id ) is not None
                    for i_id in range( 1, super( NumInstances, self ).value + 1 ))

    def __setitem__( self, key, value ):
        raise AssertionError("Cannot set value")

# 
# EtherNet/IP CIP Object
# 
# Some of the standard objects (Vol 1-3.13, Table 5-1-1):
# 
#     Class Code	Object
#     ----------	------
#     0x01		Identity
#     0x02		Message Router
#     0x03		DeviceNet
#     0x04		Assembly
#     0x05 		Connection
#     0x06		Connection Manager
#     0x07		Register
# 
# Figure 1-4.1 CIP Device Object Model
#                                                       +-------------+
#   Unconnected        -------------------------------->| Unconnected |
#   Explicit Messages  <--------------------------------| Message     |
#                                                       | Manager     |           
#                                                       +-------------+
#                                                            |^            
#                                                            ||           
#                                                            ||          +-------------+
#                                                            ||          | Link        |
#                                                            ||          | Specific    |
#                                                            ||          | Objects     |
#                                                            ||          +-------------+
#                                                            v|              ^v
#                                                       +-------------+      ||               
#   Connection         -->       Explcit                | Message     |      ||
#   Based              <--       Messaging      <--     | Router      |>-----+|                 
#   Explicit                     Connection     -->     |             |<------+                 
#   Message                      Objects                +-------------+                 
#                                                            |^                          
#                                                            ||                          
#                                                            ||                                                    
#                                                            ||                                                    
#                                                            v|                                                    
#                                                       +-------------+                               
#   I/O                -->       I/O       ..+          | Application |                               
#   Messages           <--       Connection  v  <..     | Objects     |                               
#                                Objects   ..+  -->     |             |                               
#                                                       +-------------+                               
#                                                                                      
#                                                                                      
#                                                                                      
class RequestUnrecognized( AssertionError ):
    """If a Request/Reply cannot be parsed"""

class Object( object ):
    """An EtherNet/IP device.Object is capable of parsing and processing a number of requests.  It has
    a class_id and an instance_id; an instance_id of 0 indicates the "class" instance of the
    device.Object, which has different (class level) Attributes (and may respond to different
    commands) than the other instance_id's.  An instance_id will be dynamically allocated, if one
    isn't specified.

    Each Object has a single class-level parser, which is used to register all of its available
    service request parsers.  The next available symbol designates the type of service request,
    eg. 0x01 ==> Get Attributes All.  These parsers enumerate the requests that are *possible* on
    the Object.  Later, when the Object is requested to actually process the request, a decision can
    be made about whether the request is *allowed*.

    The parser knows how to parse any requests it must handle, and any replies it can generate, and
    puts the results into the provided data artifact.

    Assuming Obj is an instance of Object, and the source iterator produces the incoming symbols:

        0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
        0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */

    then we could run the parser:

        data = dotdict()
        with Obj.parse as machine:
            for m,w in machine.run( source=source, data=data ):
                pass
    
    and it would parse a recognized command (or reply, but that would be unexpected), and produce
    the following entries (in data, under the current context):

            'service': 			0x52,
            'path.segment': 		[{'symbolic': 'SCADA', 'length': 5}],
            'read_frag.elements':	20,
            'read_frag.offset':		2,

    Then, we could process the request:

        proceed = Obj.request( data )

    and this would process a request, converting it into a reply (any data elements unchanged by the
    reply remain):

            'service': 			0xd2,			# changed: |= 0x80
            'status':			0x00,			# default if not specified
            'path.segment': 		[{'symbolic': 'SCADA', 'length': 5}], # unchanged
            'read_frag.elements':	20,			# unchanged
            'read_frag.offset':		2,			# unchanged
            'read_frag.type':		0x00c3,			# produced for reply
            'read_frag.data':	[				# produced for response
                0x104c, 0x0008,
                0x0003, 0x0002, 0x0002, 0x0002,
                0x000e, 0x0000, 0x0000, 0x42e6,
                0x0007, 0x40c8, 0x40c8, 0x0000,
                0x00e4, 0x0000, 0x0064, 0x02b2,
                0x80c8
            ]
            'input':			bytearray( [	# encoded response payload
                                                        0xd2, 0x00, #/* ....,... */
                    0x00, 0x00, 0xc3, 0x00, 0x4c, 0x10, 0x08, 0x00, #/* ....L... */
                    0x03, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, #/* ........ */
                    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe6, 0x42, #/* .......B */
                    0x07, 0x00, 0xc8, 0x40, 0xc8, 0x40, 0x00, 0x00, #/* ...@.@.. */
                    0xe4, 0x00, 0x00, 0x00, 0x64, 0x00, 0xb2, 0x02, #/* ....d... */
                    0xc8, 0x80                                      #/* .@ */
                ]

    The response payload is also produced as a bytes array in data.input, encoded and ready for
    transmission, or encapsulation by the next higher level of request processor (eg. a
    Message_Router, encapsulating the response into an EtherNet/IP response).

    If desired, invoke Object.config_loader.read method on a sequence of configuration file names
    (see Python3 configparser for format), before first Object is created.

    """
    max_instance		= 0

    # A derived class may specify its own parser and lock (and service, transit, used for logging)
    # This would be necessary if the same service numbers are used for different services.
    service			= {} # Service number/name mappings
    transit			= {} # Symbol to transition to service parser on

    # The parser doesn't add a layer of context; run it with a path= keyword to add a layer
    lock			= threading.Lock()
    parser			= dfa_post( service, initial=state( 'Obj svc' ),
                                                  terminal=True )
    # No config, by default (use default values).  Allows ${<section>:<key>} interpolation, and
    # comments anywhere via the # symbol (this implies no # allowed in any value, due to the lack of
    # support for escape symbol).
    # 
    # If config files are desired, somewhere early in program initialization, add:
    # 
    #     Object.config_loader.read( ["<config-file>", ...] )
    # 
    config_loader		= configparser.ConfigParser(
        comment_prefixes=('#',), inline_comment_prefixes=('#',),
        allow_no_value=True, empty_lines_in_values=False,
        interpolation=configparser.ExtendedInterpolation() )

    @classmethod
    def config_section( cls, section ):
        if section and section in cls.config_loader:
            log.detail( "[{section}]".format( section=section ))
            return cls.config_loader[section]
        log.detail( "[{section}]".format( section='DEFAULT' ))
        return cls.config_loader['DEFAULT']

    @classmethod
    def config_override( cls, val, key, default=None, config=None, section=None ):
        """Use the provided val (or get key's value from config, toggling '_'/' ' so either
        "Some Thing" or "some_thing" are acceptable config file keys), converting to type of
        default.

        The configparser doesn't support accessing dicts in 'k.r...' form, so we'll split on '.'
        and attempt to convert the discovered config[k] to a dotdict, and index it by 'r...'.

        """
        if config is None:
            config		= cls.config_section( section ) # if neither, uses 'DEFAULT'

        if val is None:
            for kr in ( key, key.replace( '_', ' ' ), key.replace( '_', ' ' )):
                for k,r in ( [kr, ''], ) + ( ( kr.split( '.', 1 ), ) if '.' in kr else () ):
                    if r: # a key.key...;
                        try:
                            val	= dotdict( config.get( k )).get( r )
                            log.info( "  {k:>10}{r:<10} == {val!r} (config dict)".format( k=k, r=r, val=val ))
                        except Exception as exc:
                            log.info( "  {k:>10}{r:<10}: {exc!r}".format( k=k, r=r, exc=exc ))
                    else:
                        val	= config.get( k, None )
                if val is not None:
                    log.info( "  {k:<20} == {val!r} (config)".format( k=k, val=val ))
                    break
        try:
            if val is None:
                val		= default
                if val: log.info( "  {key:<20} == {val!r:<20} (default)".format( key=key, val=val ))
            elif isinstance( default, bool) and \
                 isinstance( val,     type_str_base):
                # Python bools supplied as strings or from config files are a special case, eg. 0 or
                # "False" ==> False, 1 or "True' ==> True
                val		= type( default )( ast.literal_eval( val.capitalize() ))
            elif isinstance( default, (list, dict )) and \
                 isinstance( val,     type_str_base):
                # Other complex types eg. "[ ... ]" must be obtained by ast.literal_eval.
                val		= type( default )( ast.literal_eval( val ))
            elif isinstance( default, (bool, int, float, type_str_base)) and \
                 isinstance( val,     (bool, int, float, type_str_base)):
                # Otherwise, any basic-typed val supplied or loaded from config file will be converted to
                # type of any basic-typed default supplied.  This allows conversion of values
                # supplied as valid literals, or from string to numeric types.
                try:
                    val		= type( default )( val )			# eg.   123,  abc
                except ValueError:
                    if isinstance( val, type_str_base ):
                        val	= type( default )( ast.literal_eval( val ))	# eg. 0x123, "abc"
                    else:
                        raise
            # else leave val as str/None
            log.detail( "  {key:<20} == {val!r}".format( key=key, val=val ))
        except Exception as exc:
            msg			= "Converting {key} from {val!r} failed (default type {typ.__name__}): {exc}".format(
                key=key, val=val, typ=type( default ), exc=exc )
            log.warning( "  %s", msg )
            raise Exception( msg )
        return val

    @classmethod
    def register_service_parser( cls, number, name, short, machine ):
        """Registers a parser with the Object.  May be invoked during import; no logging.  Allows a single
        "default" parser w/ number == True to be defined. So, use our parser's .encode() method to
        process the number, to convert True/None to state.ALL/NON

        """
        enc			= cls.parser.encode( number )
        assert enc not in cls.service, \
            "Duplicate service #%s: %r number registered for Object %s" % ( number, name, cls.__name__ )
        assert name not in cls.service, \
            "Duplicate service #%s: %r name   registered for Object %s" % ( number, name, cls.__name__ )

        cls.service[enc]	= name
        cls.service[name]	= enc
        cls.transit[enc]	= ( chr( enc )
                                    if sys.version_info[0] < 3 and enc >= 0
                                    else enc )
        cls.parser.initial[cls.transit[enc]] \
				= dfa( name=short, initial=machine, terminal=True )

    GA_ALL_NAM			= "Get Attributes All"
    GA_ALL_CTX			= "get_attributes_all"
    GA_ALL_REQ			= 0x01
    GA_ALL_RPY			= GA_ALL_REQ | 0x80

    GA_LST_NAM			= "Get Attribute List"
    GA_LST_CTX			= "get_attribute_list"
    GA_LST_REQ			= 0x03
    GA_LST_RPY			= GA_LST_REQ | 0x80

    GA_SNG_NAM			= "Get Attribute Single"
    GA_SNG_CTX			= "get_attribute_single"
    GA_SNG_REQ			= 0x0E
    GA_SNG_RPY			= GA_SNG_REQ | 0x80

    SA_SNG_NAM			= "Set Attribute Single"
    SA_SNG_CTX			= "set_attribute_single"
    SA_SNG_REQ			= 0x10
    SA_SNG_RPY			= SA_SNG_REQ | 0x80

    SV_COD_NAM			= "Service Code"
    SV_COD_CTX			= "service_code"

    @property
    def config( self ):
        if self._config is None:
            self._config	= self.config_section( self.name )
        return self._config

    @misc.logresult( log=log, log_level=logging.DETAIL )
    def config_str( self, *args, **kwds ):
        return self.config.get( *args, **kwds )

    @misc.logresult( log=log, log_level=logging.DETAIL )
    def config_int( self, *args, **kwds ):
        return self.config.getint( *args, **kwds )

    @misc.logresult( log=log, log_level=logging.DETAIL )
    def config_float( self, *args, **kwds ):
        return self.config.getfloat( *args, **kwds )

    @misc.logresult( log=log, log_level=logging.DETAIL )
    def config_bool( self, *args, **kwds ):
        return self.config.getboolean( *args, **kwds )

    @misc.logresult( log=log, log_level=logging.DETAIL )
    def config_json( self, *args, **kwds ):
        return json.loads( self.config_str( *args, **kwds ))

    def __init__( self, name=None, instance_id=None ):
        """Create the instance (default to the next available instance_id).  An instance_id of 0 holds the
        "class" attributes/commands.  Any configured values for the Object are available in
        self.config via its get/getint/getfloat/getboolean( <name>, <default> ) methods.

            [Object Name]
            a key = some value

        """
        self._config		= None
        self.name		= name or self.__class__.__name__
        # Allocate and/or keep track of maximum instance ID assigned thus far.
        if instance_id is None:
            instance_id		= self.__class__.max_instance + 1
        if instance_id > self.__class__.max_instance:
            self.__class__.max_instance = instance_id
        self.instance_id	= instance_id

        ( log.detail if self.instance_id else log.info )(
            "%24s, Class ID 0x%04x, Instance ID %3d created",
            self, self.class_id, self.instance_id )

        instance		= lookup( self.class_id, instance_id )
        assert instance is None, \
            "CIP Object class %x, instance %x already exists\n%s" % (
                self.class_id, self.instance_id, ''.join( traceback.format_stack() ))

        # 
        # directory.1.2.None 	== self
        # self.attribute 	== directory.1.2 (a dotdict), for direct access of our attributes
        # 
        self.attribute		= directory.setdefault( str( self.class_id )+'.'+str( instance_id ),
                                                        dotdict() )
        self.attribute['0']	= self

        # Check that the class-level instance (0) has been created; if not, we'll create one using
        # the default parameters.  If this isn't appropriate, then the user should create it using
        # the appropriate parameters.
        if lookup( self.class_id, 0 ) is None:
            self.__class__( name='meta-'+self.name, instance_id=0 )

        if self.instance_id == 0:
            # Set up the default Class-level values.
            self.attribute['1']= Attribute( 	'Revision', 		INT,
                    default=self.config_int(	'Revision', 0 ))
            self.attribute['2']= MaxInstance(	'Max Instance',		INT,
                                                class_id=self.class_id )
            self.attribute['3']= NumInstances(	'Num Instances',	INT,
                                                class_id=self.class_id )
            # A UINT array; 1st UINT is size (default 0)
            self.attribute['4']= Attribute( 	'Optional Attributes',	INT,
                    default=self.config_int(	'Optional Attributes', 0 ))

    def __str__( self ):
        return self.name

    def __repr__( self ):
        return "(0x%02x,%3d) %s" % ( self.class_id, self.instance_id, self )

    def request( self, data, addr=None ):
        """Handle a request, converting it into a response.  Must be a dotdict data artifact such as is
        produced by the Object's parser.  For example, a request data containing either of the
        following:

            {
                'service':		0x01,
                'get_attributes_all':	True,
            }

        should run the Get Attribute All service, and return True if the channel should continue.
        In addition, we produce the bytes used by any higher level encapsulation.

        We can produce a generic CIP Service Code request, with an optional data payload -- but we
        cannot (of course) execute such a request (we don't know what it is supposed to do).  A
        derived class could be supplied that knows the semantics of such a service code, and could
        properly parse and execute it.  But, for the purposes of sending a generic CIP Service Code
        and its payload (eg. by cpppo.server.enip.client), this implementation is sufficient.

        """
        result			= b''
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Request: %s", self, enip_format( data ))
        try:
            # Validate the request.  As we process, ensure that .status is set to reflect the
            # failure mode, should an exception be raised.  Return True iff the communications
            # channel should continue.
            data.status		= 0x08		# Service not supported, if not recognized or fail to access
            data.pop( 'status_ext', None )

            if ( data.get( 'service' ) == self.GA_SNG_REQ
                 or self.GA_SNG_CTX in data and data.setdefault( 'service', self.GA_SNG_REQ ) == self.GA_SNG_REQ ):
                pass
            elif ( data.get( 'service' ) == self.GA_LST_REQ
                 or self.GA_LST_CTX in data and data.setdefault( 'service', self.GA_LST_REQ ) == self.GA_LST_REQ ):
                pass
            elif ( data.get( 'service' ) == self.GA_ALL_REQ
                 or self.GA_ALL_CTX in data and data.setdefault( 'service', self.GA_ALL_REQ ) == self.GA_ALL_REQ ):
                pass
            elif ( data.get( 'service' ) == self.SA_SNG_REQ
                 or self.SA_SNG_CTX in data and data.setdefault( 'service', self.SA_SNG_REQ ) == self.SA_SNG_REQ ):
                pass
            else:
                raise RequestUnrecognized( "Unrecognized Service Request" )

            # A recognized Set/Get Attribute[s] {Single/List/All} request; process the request data
            # artifact, converting it into a reply.  All of these requests produce/consume a
            # sequence of unsigned bytes.
            data.service       |= 0x80
            result		= b''
            if data.service == self.GA_ALL_RPY:
                # Get Attributes All.  Collect up the bytes representing the attributes.  Replace
                # the place-holder .get_attribute_all=True with a real dotdict.  Returns only the
                # sequentially available attributes.
                a_id		= 1
                while str(a_id) in self.attribute:
                    if not ( self.attribute[str(a_id)].mask & Attribute.MASK_GA_ALL ):
                        result += self.attribute[str(a_id)].produce()
                    a_id       += 1
                assert len( result ), "No Attributes available for Get Attributes All request"
                data.get_attributes_all = dotdict()
                data.get_attributes_all.data = [
                    b if type( b ) is int else ord( b ) for b in result ]
            elif data.service == self.GA_LST_RPY:
                # Get Attribute List.  Collect up the bytes representing the attributes.  Converts a
                # placehold .get_attribute_list = [<attribute>,...] list of attribute numbers with
                # real dotdict containing a sequence of .data.
                for a_id in data.get_attribute_list:
                    result     += UINT.produce( a_id )
                    if str(a_id) not in self.attribute:
                        result += UINT.produce( 0x16 ) # status: Object does not exist
                    else:
                        result += UINT.produce( 0x00 ) # status: OK
                        result += self.attribute[str(a_id)].produce()
                data.get_attribute_list = dotdict()
                data.get_attribute_list.data= [
                    b if type( b ) is int else ord( b ) for b in result ]
            elif data.service in ( self.GA_SNG_RPY, self.SA_SNG_RPY ):
                # Get/Set Attribute Single.  Collect up the bytes representing the attribute.
                nam		= self.GA_SNG_NAM if data.service == self.GA_SNG_RPY else self.SA_SNG_NAM
                assert 'attribute' in data.path['segment'][-1], \
                    "%s path must identify Attribute" % ( nam )
                a_id		= data.path['segment'][-1]['attribute']
                assert str(a_id) in self.attribute, \
                    "%s specified non-existent Attribute" % ( nam )
                assert not ( self.attribute[str(a_id)].mask & Attribute.MASK_GA_SNG ),\
                    "Attribute not available for %s request" % ( nam )
                if data.service == self.GA_SNG_RPY:
                    # Get Attribute Single.  Render bytes as unsigned ints.
                    result     += self.attribute[str(a_id)].produce()
                    data.get_attribute_single = dotdict()
                    data.get_attribute_single.data = [
                        b if type( b ) is int else ord( b ) for b in result ]
                else:
                    # Set Attribute Single.  Convert unsigned ints to bytes, parse appropriate
                    # elements using the Attribute's .parser, and assign.  Must produce exactly the
                    # correct number of elements to fully populate the Attribute.
                    att		= self.attribute[str(a_id)]
                    siz		= att.parser.struct_calcsize
                    assert 'set_attribute_single.data' in data and len( data.set_attribute_single.data ) == siz * len( att ), \
                        "Expected %d bytes in .set_attribute_single.data to satisfy %d x %d-byte %s values" % (
                            siz * len( att ), len( att ), siz, att.parser.__class__.__name__ )
                    fmt		= att.parser.struct_format
                    buf		= bytearray( data.set_attribute_single.data )
                    val		= [ struct.unpack( fmt, buf[i:i+siz] )[0]
                                    for i in range( 0, len(buf), siz ) ]
                    att[:]	= val
            else:
                raise RequestUnrecognized( "Unrecognized Service Reply" )
            data.status		= 0x00
            data.pop( 'status_ext', None )
        except Exception as exc:
            log.normal( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s\nStack %s", self,
                         data.service if 'service' in data else 0,
                         ( self.service[data.service]
                           if 'service' in data and data.service in self.service
                           else "(Unknown)" ), exc, enip_format( data ),
                         ''.join( traceback.format_exception( *sys.exc_info() )),
                         ''.join( traceback.format_stack()))

            assert data.status != 0x00, \
                "Implementation error: must specify .status error code before raising Exception"
            pass

        # Always produce a response payload; if a failure occurred, will contain an error status.
        # If this fails, we'll raise an exception for higher level encapsulation to handle.
        log.detail( "%s Response: %s: %s", self,
                    ( self.service[data.service]
                      if 'service' in data and data.service in self.service
                      else "(Unknonw)" ), enip_format( data ))
        data.input		= bytearray( self.produce( data ))
        return True # We shouldn't be able to terminate a connection at this level

    @classmethod
    def produce( cls, data ):
        """
        From pp60-61 of
        https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf:

        Of particular note is the fact that the Get_Attribute_List response does *not* return any
        size data with each attribute returned -- so it is *absolutely required* that the caller
        know, a-priori, the exact types of each and every attribute requested!  It is also
        impossible to parse a response to such this request -- unless the parser also knows the
        layout and types of the target class/instance!

        | Message Field     | Bytes          | Description                                         |
        |-------------------+----------------+-----------------------------------------------------|
        | Request Service   | 03             | Get_Attribute_List (Request)                        |
        | Request Path Size | 02             | Request path is 2 words (4 bytes)                   |
        | Request Path      | 20 AC 24 01    | Logical Segment class 0x02, instance 1              |
        | ----------------- | -------------- | --------------------------------------------------- |
        | Request Data      | 05 00          | Number of attribute IDs that follow (5)              |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 01 00          |                                                     |
        |                   | 02 00          |                                                     |
        |                   | 03 00          |                                                     |
        |                   | 04 00          |                                                     |
        |                   | 0A 00          |                                                     |
        |                   | -------------- | --------------------------------------------------- |
        |                   |                |                                                     |
        | Request Service   | 83             | Get_Attribute_List (Reply)                          |
        | Reserved          | 00             |                                                     |
        | General Status    | 00             | Success                                             |
        | Extended Sts Size | 00             | No extended status                                  |
        | ----------------- | -------------- | --------------------------------------------------- |
        | Reply Data        | 05 00          | Number of attribute responses that follow           |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 01 00          | Attribute number (1)                                |
        |                   | 00 00          | Status (success)                                    |
        |                   | 05 00          | Attribute value (INT)                               |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 02 00          | Attribute number (2)                                |
        |                   | 00 00          | Status (success)                                    |
        |                   | 01 00          | Attribute value (INT)                               |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 03 00          | Attribute number (3)                                |
        |                   | 00 00          | Status (success)                                    |
        |                   | 03 B2 80 C5    | Attribute value (DINT)                              |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 04 00          | Attribute number (4)                                |
        |                   | 00 00          | Status (success)                                    |
        |                   | 03 B2 80 C5    | Attribute value (DINT)                              |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 0A 00          | Attribute number (10)                               |
        |                   | 00 00          | Status (success)                                    |
        |                   | F8 DE 47 B8    | Attribute value (DINT)                              |
        |                   | -------------- | --------------------------------------------------- |

        """
        result			= b''
        if cls.GA_ALL_CTX in data and data.setdefault( 'service', cls.GA_ALL_REQ ) == cls.GA_ALL_REQ:
            # Get Attributes All
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
        elif cls.GA_SNG_CTX in data and data.setdefault( 'service', cls.GA_SNG_REQ ) == cls.GA_SNG_REQ:
            # Get Attribute Single
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
        elif cls.GA_LST_CTX in data and data.setdefault( 'service', cls.GA_LST_REQ ) == cls.GA_LST_REQ:
            # Get Attribute List
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += UINT.produce(    len( data.get_attribute_list ))
            for a_id in data.get_attribute_list:
                result	       += UINT.produce( a_id )
        elif cls.SA_SNG_CTX in data and data.setdefault( 'service', cls.SA_SNG_REQ ) == cls.SA_SNG_REQ:
            # Set Attribute Single
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            result	       += typed_data.produce(	data.set_attribute_single,
                                                        tag_type=USINT.tag_type )
        elif data.get( 'service' ) == cls.GA_ALL_RPY:
            # Get Attributes All/List/Single Reply.
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
            if data.status == 0x00:
                result	       += typed_data.produce( 	data.get_attributes_all,
                                                        tag_type=USINT.tag_type )
        elif data.get( 'service' ) == cls.GA_LST_RPY:
            # Get Attribute List Reply
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
            if data.status == 0x00:
                result	       += typed_data.produce(	data.get_attribute_list,
                                                        tag_type=USINT.tag_type )
        elif data.get( 'service' ) == cls.GA_SNG_RPY:
            # Get Attribute Single Reply
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
            if data.status == 0x00:
                result	       += typed_data.produce(	data.get_attribute_single,
                                                        tag_type=USINT.tag_type )
        elif data.get( 'service' ) == cls.SA_SNG_RPY:
            # Set Attribute Single Reply
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
        elif cls.SV_COD_CTX in data and data.get( 'service' ):
            # Generic CIP Service Code + EPATH, with possible (typed) data payload supplied.
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
            if isinstance( data.service_code, dict ) and 'data' in data.service_code:
                result	       += typed_data.produce(	data.service_code,
                                                        tag_type=USINT.tag_type )
        elif data.get( 'service', 0 ) & 0x80: # Could be absent
            # Generic CIP Service Code Reply.  May or may not carry a data payload.
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
            if data.status == 0x00 and 'service_code' in data \
               and isinstance( data.service_code, dict ) and 'data' in data.service_code:
                result	       += typed_data.produce(	data.service_code,
                                                        tag_type=USINT.tag_type )
        else:
            raise RequestUnrecognized( "%s doesn't recognize request/reply format: %r" % ( cls.__name__, data ))
        return result

# Register the standard Object parsers
def __service_code_reply():
    """Because True/1 hash to the same dict entry, we can't allow a wildcard transition in a state w/ a
    0x01 transition... So, we'll support being invoked from the None (no input default) transition."""
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    srvc[None]			= octets_noop(	'nodata',
                                                terminal=True )
    rsvd[True]		= stts	= status()
    # If any remaining payload, parse it into data.service_code.data as USINTs
    stts[True]			= typed_data( 			context=Object.SV_COD_CTX,
                                                tag_type=USINT.tag_type,
                                                terminal=True )
    stts[None]			= octets_noop(	'nodata',
                                                terminal=True )
    return srvc

Object.register_service_parser( number=True, name=Object.SV_COD_NAM,
                                short=Object.SV_COD_CTX, machine=__service_code_reply() )

def __get_attributes_all():
    srvc			= USINT(		 	context='service' )
    srvc[True]		= path	= EPATH(			context='path')
    path[None]		= mark	= octets_noop(			context=Object.GA_ALL_CTX,
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )
    return srvc

Object.register_service_parser( number=Object.GA_ALL_REQ, name=Object.GA_ALL_NAM,
                                short=Object.GA_ALL_CTX, machine=__get_attributes_all() )

def __get_attributes_all_reply():
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[True]			= typed_data( 			context=Object.GA_ALL_CTX,
                                                tag_type=USINT.tag_type,
                                                terminal=True )
    stts[None]			= octets_noop(	'nodata',
                                                terminal=True )
    return srvc

Object.register_service_parser( number=Object.GA_ALL_RPY, name=Object.GA_ALL_NAM + " Reply",
                                short=Object.GA_ALL_CTX, machine=__get_attributes_all_reply() )

def __get_attribute_list():
    srvc			= USINT(		 	context='service' )
    srvc[True]		= path	= EPATH(			context='path')
    path[None]		= numr	= UINT(		'number',	context=Object.GA_LST_CTX, extension='.number' )


    # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .attribute list
    att_			= UINT(		'attr',		context=Object.GA_LST_CTX, extension='.UINT' )
    att_[None]			= move_if( 	'attr',		source='.'+Object.GA_LST_CTX+'.UINT',
                                        destination=Object.GA_LST_CTX+'.attributes', initializer=lambda **kwds: [] )
    att_[None]			= state(	'attr',
                                                terminal=True )

    # Parse the number of attributes expected. TODO: handle 0 attributes?
    numr[True]		= atts	= dfa(		'attributes',
                                                 initial=att_,	repeat='.'+Object.GA_LST_CTX+'.number' )
    atts[None]		= done	= octets_noop(	'done',
                                                terminal=True )
    # Finally, move the scanned list of attributes[:] to .get_attribute_list[:]
    done.initial[None]		= move_if(	'move',	source='.'+Object.GA_LST_CTX+'.attributes',
                                                   destination=Object.GA_LST_CTX,
                                                initializer=lambda **kwds: [] )
    return srvc

Object.register_service_parser( number=Object.GA_LST_REQ, name=Object.GA_LST_NAM,
                                short=Object.GA_LST_CTX, machine=__get_attribute_list() )

def __get_attribute_list_reply():
    """Impossible to parse; the reply doesn't identify the origin path -- which must be known, in
    order to identify the attributes' types, which are required to be known in order to iterate
    through the response items...  Just parse it as raw data.  So, we'll return the reply as an
    opaque .data array."""
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[True]			= typed_data( 			context=Object.GA_LST_CTX,
                                                tag_type=UINT.tag_type,
                                                terminal=True )
    stts[None]			= octets_noop(	'nodata',
                                                terminal=True )
    return srvc

Object.register_service_parser( number=Object.GA_LST_RPY, name=Object.GA_LST_NAM + " Reply",
                                short=Object.GA_LST_CTX, machine=__get_attribute_list_reply() )

def __get_attribute_single():
    srvc			= USINT(		 	context='service' )
    srvc[True]		= path	= EPATH(			context='path')
    path[None]		= mark	= octets_noop(			context=Object.GA_SNG_CTX,
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )
    return srvc

Object.register_service_parser( number=Object.GA_SNG_REQ, name=Object.GA_SNG_NAM,
                                short=Object.GA_SNG_CTX, machine=__get_attribute_single() )
def __get_attribute_single_reply():
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[True]			= typed_data( 			context=Object.GA_SNG_CTX,
                                                tag_type=USINT.tag_type,
                                                terminal=True )
    stts[None]			= octets_noop(	'nodata',
                                                terminal=True )
    return srvc

Object.register_service_parser( number=Object.GA_SNG_RPY, name=Object.GA_SNG_NAM + " Reply",
                                short=Object.GA_SNG_CTX, machine=__get_attribute_single_reply() )

def __set_attribute_single():
    srvc			= USINT(		 	context='service' )
    srvc[True]		= path	= EPATH(			context='path')
    path[True]			= typed_data( 			context=Object.SA_SNG_CTX,
                                                tag_type=USINT.tag_type,
                                                terminal=True )
    return srvc

Object.register_service_parser( number=Object.SA_SNG_REQ, name=Object.SA_SNG_NAM,
                                short=Object.SA_SNG_CTX, machine=__set_attribute_single() )

def __set_attribute_single_reply():
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= mark	= octets_noop(			context=Object.SA_SNG_CTX,
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )
    return srvc

Object.register_service_parser( number=Object.SA_SNG_RPY, name=Object.SA_SNG_NAM + " Reply",
                                short=Object.SA_SNG_CTX, machine=__set_attribute_single_reply() )


class Identity( Object ):
    class_id			= 0x01

    def __init__( self, name=None, **kwds ):
        super( Identity, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes (these example defaults are from a Rockwell Logix PLC)
            self.attribute['1']	= Attribute( 'Vendor Number', 		INT,
	        default=self.config_int(     'Vendor Number',			0x0001 ))
            self.attribute['2']	= Attribute( 'Device Type', 		INT,
	        default=self.config_int(     'Device Type',			0x000e ))
            self.attribute['3']	= Attribute( 'Product Code Number',	INT,
	        default=self.config_int(     'Product Code Number',		0x0036 ))
            self.attribute['4']	= Attribute( 'Product Revision', 	INT,
	        default=self.config_int(     'Product Revision',		0x0b14 ))
            self.attribute['5']	= Attribute( 'Status Word', 		WORD,
	        default=self.config_int(     'Status Word',			0x3160 ))
            self.attribute['6']	= Attribute( 'Serial Number', 		UDINT,
	        default=self.config_int(     'Serial Number',			0x006c061a ))
            self.attribute['7']	= Attribute( 'Product Name', 		SSTRING,
                default=self.config_str(     'Product Name',			'1756-L61/B LOGIX5561' ))
            self.attribute['8']	= Attribute( 'State',			USINT,
	        default=self.config_int(     'State',				0xff ))
            self.attribute['9']	= Attribute( 'Configuration Consistency Value', UINT,
	        default=self.config_int(     'Configuration Consistency Value', 0 ))
            self.attribute['10']= Attribute( 'Heartbeat Interval',	USINT,
                default=self.config_int(     'Heartbeat Interval', 		0 ))


class Logical_Segments( Object ):
    """See:
    https://literature.rockwellautomation.com/idc/groups/literature/documents/pm/1756-pm020_-en-p.pdf
    for an exapmple of how to read attributes from this class via Get_Attribute_List.  It is
    recommended here: http://www.plctalk.net/qanda/showthread.php?t=85521 and on pp59 of 1756-pm020 to:

        For client applications, use the Get_Attribute_List service to periodically retrieve
        attributes 1, 2, 3, 4 and 10 of class 0xAC in the controller. If the value of these
        attributes changes between reads, the client application must refresh the:
        - List of symbols
        - Association between symbols and templates
        - Template information.

    No further information on the meaning of the attributes of class 0xAC is available anywhere that
    I have been able to find.  Here are some values for some of these attributes from a C*Logix PLC:
    """
    class_id			= 0xAC

    def __init__( self, name=None, **kwds ):
        super( Logical_Segments, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes (these example defaults are from a Rockwell Logix PLC)
            self.attribute['1']	= Attribute( 'Attribute 1', 		INT,
	        default=self.config_int(     'Attribute 1',			0x0005 ))
            self.attribute['2']	= Attribute( 'Attribute 2', 		INT,
	        default=self.config_int(     'Attribute 2',			0x0002 ))
            self.attribute['3']	= Attribute( 'Attribute 3',		UDINT,
	        default=self.config_int(     'Attribute 3',			0xC580B203 ))
            self.attribute['4']	= Attribute( 'Attribute 4',	 	UDINT,
	        default=self.config_int(     'Attribute 4',			0xC580B203 ))
            self.attribute['10']= Attribute( 'Attribute 10', 		UDINT,
	        default=self.config_int(     'Attribute 10',			0xB847DEF8))


class TCPIP( Object ):
    """Contains the TCP/IP network details of a CIP device.  See Volume 2: EtherNet/IP Adaptation of
    CIP, Chapter 5-4, TCP/IP Interface Object.

    According to Volume 2: EtherNet/IP Adaptation of CIP, Table 5-4.13, the Get_Attributes_All
    formatting of the Domain Name and Host Name are CIP STRINGs consist of 2-byte (UINT) length, followed
    by the string, followed by a 1-byte PAD if the string is of odd length.

    As per Volume 2: 5-4.3, the Instance Attributes 1-6 are Required:

    | Attribute | Type  | Name / bits               | Description                                 |
    |-----------+-------+---------------------------+---------------------------------------------|
    |         1 | DWORD | Interface Status          | Interface Configuration Status              |
    |           |       | 0-3: I'face Config Status | 0 == Not configured                         |
    |           |       |                           | 1 == BOOTP/DHCP/non-volatile storage        |
    |           |       |                           | 2 == IP address from hardware configuration |
    |           |       | 4: M'cast Pending         | (not if Attribute 2, bit 5 False)           |
    |           |       | 5: I'face Config Pending  |                                             |
    |           |       | 6: AcdStatus              |                                             |
    |           |       | 7: AcdFault               |                                             |
    |           |       | 8-31:                     | Reserved                                    |
    |         2 | DWORD | Configuration Capability  |                                             |
    |           |       | 0: BOOTP Client           | Capable of config. w/BOOTP                  |
    |           |       | 1: DNS Client             | Can resolve hostname w/DNS                  |
    |           |       | 2: DHCP Client            | Can obtain network config w/DHCP            |
    |           |       | 3: DHCP-DNS Update        | Shall be 0                                  |
    |           |       | 4: Config. Settable       | Interface Config. Attr. is settable         |
    |           |       | 5: Hardware Configurable  | IP can be configured from h/w               |
    |           |       | 6: I'face Chg. Reset      | Restart required on IP config change        |
    |           |       | 7: AcdCapable             | Indicates ACD capable                       |
    |           |       | 8-31:                     | Reserved                                    |
    |         3 | DWORD | Configuration Control     |                                             |
    |           |       | 0-3: Configuration method | 0 == Use statically-assigned IP config      |
    |           |       |                           | 1 == Obtain config. via BOOTP               |
    |           |       |                           | 2 == Obtain config. via DHCP                |
    |           |       |                           | 3-15 Reserved for future use.               |
    |           |       | 4: DNS Enable             | Resolve hostnames via DHCP                  |
    |           |       | 5-31                      | Reserved                                    |

    Default to values implying minimal capability, hardware configuration
    """
    class_id			= 0xF5

    STS_UN_CONFIGURED		= 0
    STS_EX_CONFIGURED		= 1 # External (eg. BOOTP/DHCP, non-volatile stored config)
    STS_HW_CONFIGURED		= 2 # Hardware

    CAP_BOOTP_CLIENT		= 1 << 0
    CAP_DNS_CLIENT		= 1 << 1
    CAP_DHCP_CLIENT		= 1 << 2
    CAP_CONFIG_SETTABLE		= 1 << 4
    CAP_HW_CONFIGURABLE		= 1 << 5
    CAP_IF_CHG_RST_REQ		= 1 << 6
    CAP_ADC_CAPABLE		= 1 << 7

    CON_STATIC			= 0
    CON_BOOTP			= 1
    CON_DHCP			= 2
    CON_DNS_ENABLE		= 1 << 4

    def __init__( self, name=None, **kwds ):
        super( TCPIP, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            self.attribute['0'] = Attribute( 'Revision', 		UINT,
                    default=self.config_int( 'Revision', 			3 ))
        else:
            # Instance Attributes
            self.attribute['1']	= Attribute( 'Interface Status',	DWORD,
                default=self.config_int(     'Interface Status',		self.STS_HW_CONFIGURED ))
            self.attribute['2']	= Attribute( 'Configuration Capability',DWORD,
                default=self.config_int(     'Configuration Capability',	self.CAP_CONFIG_SETTABLE | self.CAP_HW_CONFIGURABLE ))
            self.attribute['3']	= Attribute( 'Configuration Control',	DWORD,
                default=self.config_int(     'Configuration Control',		self.CON_STATIC ))
            self.attribute['4']	= Attribute( 'Path to Physical Link ',	EPATH_padded,
                default=[self.config_json(   'Path to Physical Link',		'[]' )] )
            self.attribute['5']	= Attribute( 'Interface Configuration',	IFACEADDRS,
                default=[self.config_json(   'Interface Configuration',		'{}' )] )
            self.attribute['6']	= Attribute( 'Host Name', 		STRING,
                default=self.config_str(     'Host Name',			'' ))


class Message_Router( Object ):
    """Processes incoming requests.  Normally a derived class would expand the normal set of Services
    with any specific to the actual device.

    """
    class_id			= 0x02

    MULTIPLE_NAM		= "Multiple Service Packet"
    MULTIPLE_CTX		= "multiple"
    MULTIPLE_REQ		= 0x0A
    MULTIPLE_RPY		= MULTIPLE_REQ | 0x80

    ROUTE_FALSE			= 0	# Return False if invalid route
    ROUTE_RAISE			= 1	# Raise an Exception if invalid route

    def route( self, data, fail=ROUTE_FALSE ):
        """If the request has a .path and is not for this object, return the target, else None.  On
        invalid route (no such object found), either raise Exception or return False.  Thus, we're
        returning a non-truthy value iff not routing to another object, OR if the route was invalid.

        """
        target			= None
        if 'path' not in data:
            return target
        try:
            path,ids		= None,None
            path		= data.path
            ids			= resolve( path )
            if ( ids[0] == self.class_id and ids[1] == self.instance_id ):
                return None
            target		= lookup( *ids )
        except Exception:
            # The resolution/lookup fails (eg. bad symbolic Tag); Either ignore it (return False)
            # and continue processing, so we can return a proper .status error code from the actual
            # request processing code, or raise an Exception.
            log.warning( "%s Failed attempting to resolve path %r: class,inst,addr: %r, target: %r",
                         self, path, ids, target )
            if ( fail == self.ROUTE_FALSE ):
                return False
            raise
        return target

    def request( self, data, addr=None ):
        """Any exception should result in a reply being generated with a non-zero status.  Fails with
        Exception on invalid route.

        NOTE

        If the .path designates another object, should we route the Multiple Service Packet request
        to the object, or should we process it here and route the encapsulated requests to that
        object?  Perhaps the latter...  This request was routed to this Message_Router by the path
        in the Unconnected Send.  Then, another path is provided in the Multiple Service Packet,
        identifying the target Message_Router for all the encapsulated requests.  Finally, each
        request specifies a path for the object known to that Message Router -- however, it may not
        necessarily know how to process the Multiple Service Packet request -- only the payload
        requests(s).  So, we will *not* route the Multiple Service Packet to the target; only the
        individual requests in the payload.

        """
        if self.MULTIPLE_CTX in data and data.setdefault( 'service', self.MULTIPLE_REQ ) == self.MULTIPLE_REQ:
            # Multiple Service Packet Request; '.multiple' required
            pass
        else:
            # Not recognized; more generic command?
            return super( Message_Router, self ).request( data, addr=addr )

        # It is a Multiple Service Packet request; turn it into a reply.  Any exception processing
        # one of the sub-requests will fail this request; normally, the sub-request should just
        # return a non-zero Response Status in its payload...  If we cannot successfully iterate the
        # request payload, return a generic Service not supported.
        data.service	       |= 0x80
        try:
            data.status		= 0x16			# Object does not exist, if path invalid
            target		= None
            if 'path' in data:
                target		= self.route( data, fail=self.ROUTE_RAISE )
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Routing to %s: %s", self, target or "(self)", enip_format( data ))
            if target is None:
                target		= self

            if data.service == self.MULTIPLE_RPY:
                data.pop( 'status_ext', None )
                # If no data.path, default to self; If path, None if target is self.  Otherwise, an
                # invalid path with raise Exception.

                data.status	= 8			# Service not supported, if anything blows up
                if log.isEnabledFor( logging.DETAIL ):
                    log.detail( "%s Parsed  on %s: %s", self, target, enip_format( data ))

                # We have a fully parsed Multiple Service Packet request, including sub-requests
                # Now, convert each sub-request into a response.
                for r in data.multiple.request:
                    if log.isEnabledFor( logging.DETAIL ):
                        log.detail( "%s Process on %s: %s", self, target, enip_format( r ))
                    target.request( r, addr=addr )
                data.status	= 0x00
            else:
                raise AssertionError( "Unknown service code %s" % data.service )

        except Exception as exc:
            # On Exception, if we haven't specified a more detailed error code, return General
            # Error.  Remember: 0x06 (Insufficent Packet Space) is a NORMAL response to a successful
            # Read Tag Fragmented that returns a subset of the requested data.
            log.normal( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s", self,
                         data.service if 'service' in data else 0,
                         ( self.service[data.service]
                           if 'service' in data and data.service in self.service
                           else "(Unknown)"), exc, enip_format( data ),
                         ( '' if log.getEffectiveLevel() >= logging.NORMAL # is at/below NORMAL
                           else ''.join( traceback.format_exception( *sys.exc_info() ))))
            assert data.status, \
                "Implementation error: must specify non-zero .status before raising Exception!"

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
        """Produces an encoded Multiple Service Packet request or reply.  Defaults to produce the
        request, if no .service specified, and just .multiple_request.  Expects multiple_request to
        be an array of Message_Router requests, each one individually able to produce() a serialized
        result, using this same cls.produce() method.

            "unconnected_send.service": 0x0A,					# default, if '.multiple' seen
            "unconnected_send.multiple.path": { 'class': 0x02, 'instance': 1}	# default, if no path provided
            "unconnected_send.multiple.request[0].path": { 'symbolic': "SCADA_40100", 'element': 123 }
            "unconnected_send.multiple.request[0].read_tag.elements": 1		# vector access, single element
            "unconnected_send.multiple.request[1].path": { 'symbolic': "part" }
            "unconnected_send.multiple.request[1].read_tag.elements": 1		# scalar access

        Iterate over the available multiple.request entries, and produce each of their encoded
        messages in turn.  Add each new encoded message's length to the developing list of requests
        offsets.  Finally, prepend a 0 to the list of offsets (the offset of the latest request),
        and prepend it to the request data.  Finally, add 2 + 2 * #requests to all offsets.

        Encode the beginning of message up to the number of requests and request offsets, and
        prepend to requests data.  The Multiple Service Packet request/reply message formats are:

        | Message Field     | Bytes          | Description                                         |
        |-------------------+----------------+-----------------------------------------------------|
        | Request Service   | 0A             | Multiple Service Packet (Request)                   |
        | Request Path Size | 02             | Request path is 2 words (4 bytes)                   |
        | Request Path      | 20 02 24 01    | Logical Segment class 0x02, instance 1              |
        | ----------------- | -------------- | --------------------------------------------------- |
        | Request Data      | 02 00          | Number of Services contained in req.                |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 06 00          | Offsets for each Service from start of Request Data |
        |                   | 12 00          |                                                     |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 4C             | First Request: Read Tag Service                     |
        |                   | 04 91 05 70 61 | EPATH, 4 words, symbolic "parts"                    |
        |                   | 72 74 73 00    |                                                     |
        |                   | 01 00          | Read 1 element                                      |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 4C             | Second Request: Read Tag Service                    |
        |                   | 07 91 0B 43 6F | EPATH, 7 words, symbolic "ControlWord"              |
        |                   | 6E 74 72 6F 6C |                                                     |
        |                   | 57 6F 72 64 00 |                                                     |
        |                   | 01 00          | Read 1 element                                      |
        |                   |                |                                                     |
        |                   |                |                                                     |
        | Request Service   | 8A             | Multiple Service Packet (Reply)                     |
        | Reserved          | 00             |                                                     |
        | General Status    | 00             | Success                                             |
        | Extended Sts Size | 00             | No extended status                                  |
        | ----------------- | -------------- | --------------------------------------------------- |
        | Reply Data        | 02 00          | Number of Service Replies                           |
        |                   | -------------- | --------------------------------------------------- |
        |                   | 06 00          | Offsets for each Reply, from start of Reply Data    |
        |                   | 10 00          |                                                     |
        |                   | -------------- | --------------------------------------------------- |
        |                   | CC 00 00 00    | Read Tag Service Reply, Status: Success             |
        |                   | C4 00          | DINT Tag Type Value                                 |
        |                   | 2A 00 00 00    | Value: 0x0000002A (42 decimal)                      |
        |                   | -------------- | --------------------------------------------------- |
        |                   | CC 00 00 00    | Read Tag Service Reply, Status: Success             |
        |                   | C4 00          | DINT Tag Type Value                                 |
        |                   | DC 01 00 00    | Value: 0x000001DC (476 decimal)                     |
        """
        result			= b''
        if cls.MULTIPLE_CTX in data and data.setdefault( 'service', cls.MULTIPLE_REQ ) == cls.MULTIPLE_REQ:
            offsets		= []
            reqdata		= b''
            for r in reversed( data.multiple.request ):
                req		= cls.produce( r )
                offsets		= [ 0 ] + [ o + len( req ) for o in offsets ]
                reqdata		= req + reqdata

            result	       += USINT.produce(        data.service )
            result	       += EPATH.produce(        data.path if 'path' in data
                                    else dotdict( segment=[{ 'class': cls.class_id }, { 'instance': 1 }] ))
            result	       += UINT.produce( 	len( offsets ))
            for o in offsets:
                result	       += UINT.produce( 	2 + 2 * len( offsets ) + o )
            result	       += reqdata
        elif data.get( 'service' ) == cls.MULTIPLE_RPY: # If error status, no '.multiple' required
            # Collect up all (already produced) request results stored in each request[...].input
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce(	data )
            if data.status in (0x00, 0x1E):
                offsets		= []
                rpydata		= b''
                for r in reversed( data.multiple.request ):
                    rpy		= octets_encode( r.input ) if 'input' in r else cls.produce( r )
                    offsets	= [ 0 ] + [ o + len( rpy ) for o in offsets ]
                    rpydata	= rpy + rpydata
                result         += UINT.produce(		len( offsets ))
                for o in offsets:
                    result     += UINT.produce(	       2 + 2 * len( offsets ) + o )
                result         += rpydata
        else:
            result		= super( Message_Router, cls ).produce( data )

        return result

class state_multiple_service( state ):
    """Find the specified target Object parser via the path specified, defaulting to the Message
    Router's parser (if any) in play (eg. to parse reply), or the Logix' parser if no path
    (ie. we're just parsing a reply).  This requires that a Message_Router derived class has been
    instantiated that understands all protocol elements that could be included in the Multiple
    Service Packet response (if the EtherNet/IP dialect is not Logix)

    """
    def terminate( self, exception, machine, path, data ):
        # Only operate if we have completed our state transitions without exception (that Exception
        # will be raised as soon as terminate is done cleaning up).  We can raise our own (fresh)
        # Exception here in terminate, if we fail to complete processing, and it will destroy the
        # session.
        target			= None
        try:
            if not exception:
                if path+'.path' in data:
                    # There is a specific Message Router object specified.  Better exist...
                    ids		= resolve( data[path+'.path'] )
                    target	= lookup( *ids )
                    assert target and hasattr( target, 'parser' ), \
                        "No Message Router Object found at %r, for parsing Multiple Service Packet" % ( ids, )
                else:
                    # There is no request path specified.  We're probably just parsing a response.  If
                    # we (also) just happen to have a Message_Router object in play, use it.  Otherwise,
                    # just default to this state machine parser itself.  If the client wants a
                    # specified dialect/style of Message Router, they'd better create one.
                    ids		= (Message_Router.class_id, 1, None)
                    target	= lookup( *ids )
                    if not target:
                        assert dialect, \
                            "No Message Router, and EtherNet/IP dialect default not provided"
                        target	= dialect	#  eg. logix.Logix
        except Exception as exc:
            # We've generated an exception here (could only happen if no exception was already
            # present)!  Don't operate, and present this exception to our Super's terminate.
            log.warning( "Multiple Service failure: %s\n%s",
                         ''.join( traceback.format_exception( *sys.exc_info() )),
                         ''.join( traceback.format_stack() ))
            exception		= exc
            raise
        finally:
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Target: %s", target, enip_format( data ))

        super( state_multiple_service, self ).terminate( exception, machine, path, data )
        if exception:
            return

        # No Exception has failed the state machinery, and we have found a Message Router Object (or
        # Logix) parser target to use to parse the Multiple Service Packet's payload.
        def closure():
            """Closure capturing data, to parse the data.multiple.request_data and append the resultant
            decoded requests to data.multiple.request.

            Match up pairs of offsets[oi,oi+1], and use the target Object to parse the snippet of
            request data payload into request[oi].  Last request offset gets balance of request
            data.  If the DFA is in use (eg. we're using our own Object's parser), schedule it for
            post-processing.

            """
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Process: %s", target, enip_format( data ))
            request		= data[path+'.multiple.request'] = []
            reqdata		= data[path+'.multiple.request_data']
            offsets		= data[path+'.multiple.offsets']
            for oi in range( len( offsets )):
                beg		= offsets[oi  ] - ( 2 + 2 * len( offsets ))
                if ( oi < len( offsets ) - 1 ):
                    end		= offsets[oi+1] - ( 2 + 2 * len( offsets ))
                else:
                    end		= len( reqdata )
                if log.isEnabledFor( logging.DETAIL ):
                    log.detail( "%s Parsing: %3d-%3d of %r", target, beg, end, reqdata )
                req		= dotdict()
                req.input	= reqdata[beg:end]
                with target.parser as machine:
                    source	= peekable( req.input )
                    with contextlib.closing( machine.run( source=source, data=req )) as engine:
                        for m,s in engine:
                            pass
                    assert machine.terminal, \
                        "%s: Failed to parse Multiple Service Packet request %d" % (
                            machine.name_centered(), oi )
                request.append( req )

        # If anyone holds the lock, post-process the closure.  In a multi-threaded environment, this
        # _requires_ that any parser that uses this class _must_ be locked during use -- or, these
        # closures will not be run.  All Object parsers are derived from dfa_post, which is capable
        # of post-processing a Thread's closures after being unlocked.
        if target.parser.lock.locked():
            target.parser.post_process_closure( closure )
        else:
            closure()
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Parsed: %s", target, enip_format( data ))

def __multiple():
    """Multiple Service Packet request.  Parses only the header and .number, .offsets[...]; the
    remainder of the payload is the encapsulated requests, each of which must be parsed by the
    appropriate Object parser.

    Note that this request parser cannot deduce the length of the encapsulated command data; all
    remaining data is absorbed into .request_data.  Also, as with other encapsulation schemes, such
    as EtherNet/IP frames, CPF frames, etc., this only partially decodes the packet; the payload
    requests/replies remain undecoded.

    """
    srvc			= USINT(	context='service' )
    srvc[True]		= path	= EPATH(	context='path' )
    path[True]		= numr	= UINT(		'number',	context='multiple', extension='.number' )

    # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .offsets list
    off_			= UINT(		'offset',	context='multiple', extension='.UINT' )
    off_[None]			= move_if( 	'offset',	source='.multiple.UINT',
                                        destination='.multiple.offsets', initializer=lambda **kwds: [] )
    off_[None]			= state( 	'offset',
                                                terminal=True )

    # Parse each of the .offset__ --> .offsets[...] values in a sub-dfa, repeating .number times
    numr[None]		= offs	= dfa(		'offsets',
                                                initial=off_,	repeat='.multiple.number' )
    # And finally, absorb all remaining data as the request data.
    offs[None]		= reqd	= octets(	'requests',	context='multiple',
                                                octets_extension=".request_data",
                                                terminal=True )
    reqd[True]			= reqd
    reqd[None]			= state_multiple_service( 'requests',
                                                terminal=True )
    return srvc
Message_Router.register_service_parser( number=Message_Router.MULTIPLE_REQ, name=Message_Router.MULTIPLE_NAM,
                                        short=Message_Router.MULTIPLE_CTX, machine=__multiple() )

def __multiple_reply():
    """Multiple Service Packet reply.  We could make use of Message_Router.parser to decode the payload
    contents.  This is, strictly speaking, not correct -- if the original target path specifies
    an object that understands different Services (very likely), our parser may not have the
    capability to decode.

    Therefore, we look for an indication of that target object to be provided in data.target.  If
    provided, we will use it to decode the payload requests.

    """
    srvc			= USINT(	context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= schk	= octets_noop(	'check',
                                                terminal=True )
    # Next comes the number of replies encapsulated; only if general reply status is 0x00/Success or
    # 0x1E/Embedded service error.
    numr			= UINT(		'number',	context='multiple', extension='.number' )
    schk[None]			= decide(	'ok',	state=numr,
        predicate=lambda path=None, data=None, **kwds: data[path+'.status' if path else 'status'] in (0x00, 0x1E) )

    # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .offsets list
    off_			= UINT(		'offset',	context='multiple', extension='.UINT' )
    off_[None]			= move_if( 	'offset',	source='.multiple.UINT',
                                        destination='.multiple.offsets', initializer=lambda **kwds: [] )
    off_[None]			= state( 	'offset',
                                             terminal=True )
    # Parse each of the .offset__ --> .offsets[...] values in a sub-dfa, repeating .number times
    numr[None]		= offs	= dfa(		'offsets',
                                             initial=off_,	repeat='.multiple.number' )
    # And finally, absorb all remaining data as the request data.
    offs[None]		= reqd	= octets(	'requests',	context='multiple',
                                             octets_extension=".request_data",
                                             terminal=True )
    reqd[True]			= reqd

    # If target Object can be found, decode the request payload
    reqd[None]			= state_multiple_service( 'requests',
                                             terminal=True )
    return srvc
Message_Router.register_service_parser( number=Message_Router.MULTIPLE_RPY, name=Message_Router.MULTIPLE_NAM + " Reply",
                                        short=Message_Router.MULTIPLE_CTX, machine=__multiple_reply() )


class Connection_Manager( Object ):
    """The Connection Manager (Class 0x06, Instance 1) Handles Unconnected Send (0x82) requests, such as:

        "unconnected_send.service": 82, 
        "unconnected_send.path.size": 2, 
        "unconnected_send.path.segment[0].class": 6, 
        "unconnected_send.path.segment[1].instance": 1, 
        "unconnected_send.priority": 5, 
        "unconnected_send.timeout_ticks": 157
        "unconnected_send.length": 16, 
        "unconnected_send.request.input": "array('B', [82, 4, 145, 5, 83, 67, 65, 68, 65, 0, 20, 0, 2, 0, 0, 0])", 
        "unconnected_send.route_path.octets.input": "array('B', [1, 0, 1, 0])", 

    If the message contains an request (.length > 0), we get the Message Router (Class 0x02,
    Instance 1) to parse and process the request, eg:

        "unconnected_send.request.service": 82, 
        "unconnected_send.request.path.size": 4, 
        "unconnected_send.request.path.segment[0].length": 5, 
        "unconnected_send.request.path.segment[0].symbolic": "SCADA", 
        "unconnected_send.request.read_frag.elements": 20, 
        "unconnected_send.request.read_frag.offset": 2, 

    We assume that the Message Router will convert the .request to a Response and fill it its .input
    with the encoded response.

    It also handles process of Forward Open requests.

    """
    class_id			= 0x06

    # We only understand our own services; don't inherit from CIP Object (nor support
    # post-processing of Multiple Service Packet closures)
    service			= {} # Service number/name mappings
    transit			= {} # Symbol to transition to service parser on
    lock			= threading.Lock()
    parser			= dfa( service, initial=state( 'CM svc' ),
                                                terminal=True )

    # A simple parser that parses only the .service and .path of a request, for routing purposes.
    srvc			= USINT(	context='service' )
    srvc[True]			= EPATH(	context='path',
                                                terminal=True )
    parser_service_path		= dfa( 'target', initial=srvc, terminal=True )

    FWD_OPEN_NAM		= "Forward Open"
    FWD_OPEN_CTX		= "forward_open"
    FWD_OPEN_REQ		= 0x54 # == 0x0101_0100 (Small)
    FWD_OPEN_RPY		= FWD_OPEN_REQ | 0x80

    FWD_OPLG_REQ		= 0x5B # == 0x0101_1011 (Large)
    FWD_OPLG_RPY		= FWD_OPLG_REQ | 0x80

    FWD_CLOS_NAM		= "Forward Close"
    FWD_CLOS_CTX		= "forward_close"
    FWD_CLOS_REQ		= 0x4E
    FWD_CLOS_RPY		= FWD_CLOS_REQ | 0x80

    # Keep track of each Originating peer by a unique triplet, to its defined Forward Open data, and
    # the resultant implicit connection to its ultimate Target (or None, if this is the Target --
    # there is only 1 more address left in the connection_path)
    forwards			= {}	# vendor,serial,connection_serial --> <forward_open request>,<implicit connection>|None

    def forward_open( self, data, addr ):
        """Pretty much only the Connection Manager knows how to handle a Forward Open.  It'll come back to
        us, for typical Forward Open requests with a path @0x02/1.  The Message_Router will
        typically process the request, locate the Connection_Manager by its address, and dispatch
        the forward_open request.

        Dispatch a parsed Forward Open request, converting the 'data' dotdict contents to an
        appropriate response.  Particularly, ensure that data.status reflects the CIP error status
        of the request.

        This base class implementation does nothing but report success (returning the appropriate
        bits of the request, and pick a random T->O Connection ID.

        Subsequent requests coming in on this connection need to be routed to this connection_path.

        TODO: The UCMM or the Connection_Manager needs to handle the establishment of connections to
        the targets of a route_path (for Unconnected requests) and/or a connection_path (for
        Connected requests).

        """
        fo			= data.forward_open

        # Actual Packet Interval will be the same as the Requested Packet Interval
        fo.O_T.API		= fo.O_T.RPI
        fo.T_O.API		= fo.T_O.RPI

        # Decode the supplied Connection parameters.
        O_T			= defaults.Connection( **fo.O_T )
        T_O			= defaults.Connection( **fo.T_O )

        # TODO: Only if we're the Target (final hop)! Otherwise, pass thru via implicit connection's Forward Open request/reply.
        if O_T.decoding.type == O_T.TYPE_P2P: # Originator -> Target is Point-to-Point: Target picks connection ID
            O_T.connection_ID	=  random.randint( 0, 2**32-1 )
        if T_O.decoding.type == T_O.TYPE_MC: # Target -> Originator is Multicast: Target picks connection ID
            T_O.connection_ID	=  random.randint( 0, 2**32-1 )
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Forward Open from %s:%s O->T: %s, T->O: %s: %s", self, addr[0], addr[1],
                        O_T.description, T_O.description,
                        enip_format( data ) if log.isEnabledFor( logging.INFO )
                        else ", ".join( " ".join( "%s: %r" % ( k, v ) for k,v in s.items() )
                                        for s in data.forward_open.connection_path.segment ))

        fo.O_T			= O_T.decoding
        fo.T_O			= T_O.decoding

        # Every Forward Open must present a unique vendor/serial/connection_serial.  If its already
        # set up, and the exact same Forward Open connection parameters were used (same connection
        # being re-opened), signal success. However: each Connected session request only comes with
        # a copy of the O_T.connection_ID, which is *not* generated by the Target! Thus, no
        # information present in each request is sufficient to uniquely identify the carry-on
        # connection to use.  The peer (addr,O_T.connection_ID) is sufficiently unique: each
        # incoming TCP/IP session can carry one or more Forward Open request(s), each of which must
        # have a unique O_T.connection_ID.  Later, each CIP request must carry a CPF.item[0]
        # containing the O_T.connection_ID.

        triplet			= fo.O_vendor,fo.O_serial,fo.connection_serial
        unique			= addr[0],addr[1],fo.O_T.connection_ID # eg ("1.2.3.4",12345,234567)
        if unique in self.forwards:
            ufo,uci		= self.forwards[unique]
            assert all( ufo.getattr( a ) == fo.getattr( a )
                        for a in ( 'O_T.NCP', 'O_T.RPI', 'T_O.NCP', 'T_O.RPI', 'transport_class_triggers', 'connection_path' )), \
                "Already have an incompatible Forward Open from device Vendor: %s, Serial: %s, Connection Serial: %s" % triplet
        else:
            # TODO: Create an implicit connection w/ remainder of connection_path
            if fo.connection_path.segment and hasattr( fo.connection_path.segment[0], 'port' ):
                via,to		= fo.connection_path.segment[0],fo.connection_path.segment[1:]
                log.detail( "Establishing an implicit connection for %s:%s (O->T ID: %s) via: %r to: %r",
                            unique[0], unique[1], unique[2], via, to )
            self.forwards[unique] = fo,None # <forward_open>,<connection>

    def forward_close( self, data, addr ):
        """Convert the data into a forward_close response; nothing to do. Remove any matching self..forwards
        entry.  We do not have an O_T.connection_ID, just a connection_serial. Since we store the
        forwards addr[0],addr[1],O_T.connection_ID to speed lookups while processing Connected
        requests, we need to iterate all self.forwards 'til we find the one with matching key
        addr[0],addr[1],* having a matching connection_serial.

        Furthermore, when a connection closes, we want to purge all self.forwards established via
        that connection. If an empty/None data is provided, purge them all.

        """
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Forward Close: %s", self,
                        "<all>" if not data
                        else enip_format( data ) if log.isEnabledFor( logging.INFO )
                        else", ".join( " ".join( "%s: %r" % ( k, v ) for k,v in s.items() )
                                        for s in data.forward_close.connection_path.segment ))
        for k in list( self.forwards.keys() ): # we'll be mutating the dict...
            if (addr[0],addr[1]) != k[:2]:
                continue
            ufo,uci		= self.forwards[k]
            if not data or data.forward_close.connection_serial == ufo.connection_serial:
                logging.detail( "Closing Connected Session %s w/ connection_serial == %s", k, ufo.connection_serial )
                del self.forwards[k]

    def request( self, data, addr=None ):
        """Handles an unparsed request.input, parses it and processes the request with the Message
        Router @6/1 (probably). Must parse the .service code and .path to know for certain what the
        target is. Some encapsulated service requests (eg. Forward Open) actually target the
        Connection_Manager @2/1.  Each CIP request should always start with the SINT Service Code
        followed by an EPATH.

        For Connected sessions (w/ an O_T.connection_ID in CFP.items[0]), we don't need to parse an
        EPATH from the incoming request -- it will have been provided by the Forward Open and
        available in the self.forwards. This is necessary, for when the target Object doesn't
        actually parse CIP requests (ie. ones with a service number and EPATH at the start, but some
        other command format, such as PCCC/DF1).  These kind of Objects can only be accessed by
        Connected (Forward Open) sessions, which have established the final destination Object.

        Thus, this request method for Connection Manager objects accept an additional, optional 3rd
        element in the 'addr' keyword parameter: <host>,<port>,<T_O_connection_ID>.  If supplied,
        then we'll either route the request via the matching "implicit" connection, or get the
        target local Object's ID from the self.forwards dict.

        """
        if not data:
            # Empty requests, indicates the termination of a session. Clean up all matching self.forward
            self.forward_close( data, addr=addr )
            return

        if (   self.FWD_OPEN_CTX in data and data.get( 'service' ) in (self.FWD_OPEN_REQ, self.FWD_OPLG_REQ)
            or self.FWD_CLOS_CTX in data and data.setdefault( 'service', self.FWD_CLOS_REQ ) == self.FWD_CLOS_REQ ):
            # The only request a Connection Manager handles directly is the Forward Open/Close.
            try:
                # Forward Open.  Parsed here (until we get proper "split" parsing for CIP requests,
                # where service and EPATH is parsed centrally, then remainder of parsering is
                # dispatched to the correct target Object?)  The Message Router will normally
                # forward it here to the Connection Manager (where it was addressed) to be handled.
                data.service   |= 0x80
                data.status	= 8			# Service not supported, if anything blows up
                if data.service == self.FWD_CLOS_RPY:
                    self.forward_close( data, addr=addr )
                else:
                    self.forward_open( data, addr=addr )
                data.status	= 0
            except Exception as exc:
                # On Exception, if we haven't specified a more detailed error code, return General
                # Error.  Remember: 0x06 (Insufficent Packet Space) is a NORMAL response to a successful
                # Read Tag Fragmented that returns a subset of the requested data.
                log.normal( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s", self,
                             data.service if 'service' in data else 0,
                             ( self.service[data.service]
                               if 'service' in data and data.service in self.service
                               else "(Unknown)"), exc, enip_format( data ),
                             ( '' if log.getEffectiveLevel() >= logging.NORMAL # is at/below NORMAL
                               else ''.join( traceback.format_exception( *sys.exc_info() ))))
                assert data.status, \
                  "Implementation error: must specify non-zero .status before raising Exception!"

            # Always produce a response payload; if a failure occurred, will contain an error status
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Response: Service 0x%02x %s %s", self,
                            data.service if 'service' in data else 0,
                            ( self.service[data.service]
                              if 'service' in data and data.service in self.service
                              else "(Unknown)"), enip_format( data ))
            data.input		= bytearray( self.produce( data ))
            return True

        # See if it's a "Connected" request to a remote Target via self.forwards.  If remote, send
        # the request. If local, get the targetpath from self.forwards.
        targetpath		= dotdict()
        if addr in self.forwards:
            ufo,uci		= self.forwards[addr]
            if uci:
                # TODO: use connected_send to transmit request, get reply, using T_O_connection_ID in addr[2].
                assert False, "Remote Connected requests not yet handled"
                return True
            # A Connected request to a local Object.
            targetpath.path	= ufo.connection_path
            # TODO: No need to discard leading port/link segments, once we're handling remote
            # Connected requests; only a single CIP Object address will remain.
            while targetpath.path and hasattr( targetpath.path.segment[0], 'port' ):
                targetpath.path.segment.pop( 0 )

        # Must be an Unconnected Send (Send RR Data, 0x52) or a Connected Send (Send Unit Data) to a
        # local Object (now in targetpath.path).

        # We don't check for Unconnected Send 0x52, because replies (and some requests) don't
        # include the full wrapper, just the raw command.  This is quite confusing; especially since
        # some of the commands have the same code (eg. Read Tag Fragmented, 0x52).  Of course, their
        # replies don't (0x52|0x80 == 0xd2).  The CIP.produce recognizes the absence of the
        # .command, and simply copies the encapsulated request.input as the response payload.  We
        # don't encode the response here; it is done by the UCMM.
        assert 'request' in data and 'input' in data.request, \
            "%s message with absent or empty request: %s\nvia: %s" % (
                "Connected Send" if targetpath  else "Unconnected Send",
                enip_format( data ), ''.join( traceback.format_stack() ))

        # Get the target object (usually a Message Router) to parse and process the request into a
        # response, producing a data.request.input encoded response, which we will pass back as our
        # own encoded response. Note that we assume, here, that we are dealing with CIP Requests
        # (ie. a .service code without bit 0x80 set), thus always followed by an EPATH.
        try:
            if not targetpath: # Not required for "Connected" requests; otherwise, parse request EPATH
                source		= rememberable( data.request.input )
                with self.parser_service_path as machine:
                    with contextlib.closing( machine.run( source=source, data=targetpath )) as engine:
                        for i,(m,s) in enumerate( engine ):
                            pass
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Routing request to target Object at address %s", self, enip_format( targetpath ))
            # We have the service and path. Find the target Object (see state_multiple_service.closure)
            ids			= resolve( targetpath.path )
            target		= lookup( *ids )
            assert target, "Unknown CIP Object in request: %s" % ( enip_format( targetpath ))
            source		= rememberable( data.request.input )
            with target.parser as machine:
                with contextlib.closing( machine.run( path='request', source=source, data=data )) as engine:
                    for i,(m,s) in enumerate( engine ):
                        pass
                        #log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %s",
                        #            machine.name_centered(), i, s, source.sent, source.peek(),
                        #            repr( data ) if log.getEffectiveLevel() < logging.DETAIL else misc.reprlib.repr( data ))

            target.request( data.request, addr=addr )
        except:
            # Parsing failure.  We're done.  Suck out some remaining input to give us some context.
            processed		= source.sent
            memory		= bytes(bytearray(source.memory))
            pos			= len( source.memory )
            future		= bytes(bytearray( b for b in source ))
            where		= "at %d total bytes:\n%s\n%s (byte %d)" % (
                processed, repr(memory+future), '-' * (len(repr(memory))-1) + '^', pos )
            log.error( "EtherNet/IP CIP error %s\n", where )
            raise

        if log.isEnabledFor( logging.INFO ):
            log.info( "%s Response: %s", self, enip_format( data ))
        return True

    @classmethod
    def produce( cls, data ):
        result			= b''
        if cls.FWD_OPEN_CTX in data and data.get( 'service' ) not in (cls.FWD_OPEN_RPY, cls.FWD_OPLG_RPY):
            fo			= data.forward_open
            # Must deduce if Small or Large Forward Open is desired.  Both O_T and T_O Connection
            # parameters must be encoded appropriately.  If the data.service is not defined, and
            # *either* Connection's NCP decoding.large is True, re-encode both as Large.  Finally,
            # replace the supplied Connections with the complete Connection.decoding.
            T_O			= defaults.Connection( **fo.T_O )
            O_T			= defaults.Connection( **fo.O_T )
            service		= data.get( 'service' )
            large		= T_O.large or O_T.large
            if service is None:
                data.service	= cls.FWD_OPLG_REQ if large else cls.FWD_OPEN_REQ
            assert data.service == cls.FWD_OPLG_REQ if large else cls.FWD_OPEN_REQ, \
                "Forward Open service code incompatible with T_O or O_T connection size"
            T_O.large = O_T.large = large
            fo.T_O		= T_O.decoding
            fo.O_T		= O_T.decoding

            result	       += USINT.produce( data.service )
            result	       += EPATH.produce( data.path )
            result	       += USINT.produce( fo.priority_time_tick )
            result	       += USINT.produce( fo.timeout_ticks )
            result	       += UDINT.produce( fo.O_T.connection_ID )
            result	       += UDINT.produce( fo.T_O.connection_ID )
            result	       += UINT.produce( fo.connection_serial )
            result	       += UINT.produce( fo.O_vendor )
            result	       += UDINT.produce( fo.O_serial )
            result	       += USINT.produce( fo.connection_timeout_multiplier )
            result	       += b'\x00' * 3 # reserved
            result	       += UDINT.produce( fo.O_T.RPI )
            result	       += DWORD.produce( fo.O_T.NCP ) if fo.O_T.large else WORD.produce( fo.O_T.NCP )
            result	       += UDINT.produce( fo.T_O.RPI )
            result	       += DWORD.produce( fo.T_O.NCP ) if fo.T_O.large else WORD.produce( fo.T_O.NCP )
            result	       += USINT.produce( fo.transport_class_triggers )
            result	       += EPATH.produce( fo.connection_path )

        elif data.get( 'service' ) in (cls.FWD_OPEN_RPY, cls.FWD_OPLG_RPY):
            result	       += USINT.produce( data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( data )
            fo			= data.forward_open
            if data.status == 0x00:
                result	       += UDINT.produce( fo.O_T.connection_ID )
                result	       += UDINT.produce( fo.T_O.connection_ID )
                result	       += UINT.produce( fo.connection_serial )
                result	       += UINT.produce( fo.O_vendor )
                result	       += UDINT.produce( fo.O_serial )
                result	       += UDINT.produce( fo.O_T.API )
                result	       += UDINT.produce( fo.T_O.API )

                # The forward_open.application data in the reply is typed data, by default USINT.  It
                # must be an even number of bytes, so pad it out if not.
                app			= fo.setdefault( 'application', dotdict() )
                if 'data' not in app:
                    app.data	= []
                if app.data:
                    # Something has been provided
                    if 'type' not in app and 'tag_type' not in app:
                        app.tag_type= USINT.tag_type
                    app.input	= typed_data.produce( app )
                    if len( app.input ) % 2:
                        app.input  += b'\x00'
                    app.size	= len( app.input ) // 2 # words
                else:
                    app.size	= 0

                result	       += USINT.produce( app.size ) # application data size (words)
                result	       += b'\x00' # pad
                if app.size:
                    result     += app.input
            else:
                # Failure response; see Vol1_3.15 table 3-5.21
                result	       += UINT.produce( fo.connection_serial )
                result	       += UINT.produce( fo.O_vendor )
                result	       += UDINT.produce( fo.O_serial )
                if 'remaining_path_size' in fo: # iff "routing type errors"; # words in original route path
                    result     += USINT.produce( fo.remaining_path_size )
                    result     += b'\x00' # reserved

        elif cls.FWD_CLOS_CTX in data and data.setdefault( 'service', cls.FWD_CLOS_REQ ) == cls.FWD_CLOS_REQ:
            result	       += USINT.produce( data.service )
            result	       += EPATH.produce( data.path )
            fc			= data.forward_close
            result	       += USINT.produce( fc.priority_time_tick )
            result	       += USINT.produce( fc.timeout_ticks )
            result	       += UINT.produce( fc.connection_serial )
            result	       += UINT.produce( fc.O_vendor )
            result	       += UDINT.produce( fc.O_serial )
            result	       += EPATH_padded.produce( fc.connection_path )

        elif data.get( 'service' ) == cls.FWD_CLOS_RPY:
            result	       += USINT.produce( data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( data )
            fc			= data.setdefault( 'forward_close', True )
            if isinstance( fc, dict ): # May be just a failure status code (ie. == True)
                result	       += UINT.produce( fc.connection_serial )
                result	       += UINT.produce( fc.O_vendor )
                result	       += UDINT.produce( fc.O_serial )

                # The forward_close.application data in the reply is typed data, by default USINT.  It
                # must be an even number of bytes, so pad it out if not.
                app		= fc.setdefault( 'application', dotdict() )
                if 'data' not in app:
                    app.data	= []
                if app.data:
                    # Something has been provided
                    if 'type' not in app and 'tag_type' not in app:
                        app.tag_type = USINT.tag_type
                    app.input	= typed_data.produce( app )
                    if len( app.input ) % 2:
                        app.input += b'\x00'
                    app.size	= len( app.input ) // 2 # words
                else:
                    app.size	= 0

                result	       += USINT.produce( app.size ) # application data size (words)
                result	       += b'\x00' # pad
                if app.size:
                    result     += app.input
        else:
            # Connection Manager only recognizes its own services (not the generic CIP Object's)
            raise RequestUnrecognized( "%s doesn't recognize request/reply format: %r" % ( cls.__name__, data ))
        return result


class Connection_decode( decide ):
    def __init__( self, name, large=None, source=None, **kwds ):
        super( Connection_decode, self ).__init__( name=name, **kwds )
        self.lrg		= large or False
        self.src		= source # eg. forward_open.O_T

    def execute( self, truth, machine=None, source=None, path=None, data=None ):
        target			= super( Connection_decode, self ).execute(
            truth, machine=machine, source=source, path=path, data=data )
        if truth:
            pathsrc		= path + '.' + self.src
            parameters		= defaults.Connection( **data[pathsrc] )
            data[pathsrc]	= parameters.decoding

        return target


def __forward_open():
    """Handle Forward Open request.
    """
    srvc			= USINT(	 	context='service' )
    srvc[True]		= path	= EPATH(		context='path')
    path[True]		= prio	= USINT(		context='forward_open', extension='.priority_time_tick' )
    prio[True]		= timo	= USINT(		context='forward_open', extension='.timeout_ticks' )
    timo[True]		= otid	= UDINT(		context='forward_open.O_T', extension='.connection_ID' )
    otid[True]		= toid	= UDINT(		context='forward_open.T_O', extension='.connection_ID' )
    toid[True]		= cser	= UINT(			context='forward_open', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_open', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_open', extension='.O_serial' )
    oser[True]		= tmul	= USINT(		context='forward_open', extension='.connection_timeout_multiplier' )
    tmul[True]		= rsvd	= octets_drop(		'pad', repeat=3 )
    rsvd[True]		= otrpi	= UDINT(		context='forward_open.O_T', extension='.RPI' )
    otrpi[True]		= otncp	= WORD(			context='forward_open.O_T', extension='.NCP' )
    otncp[True]		= torpi	= UDINT(		context='forward_open.T_O', extension='.RPI' )
    torpi[True]		= toncp	= WORD(			context='forward_open.T_O', extension='.NCP' )
    toncp[True]		= tclt	= USINT( 		context='forward_open', extension='.transport_class_triggers' )
    # 33 bytes from Path to start of Connection Path Size; Connection Path begins on a Word boundary
    tclt[True]		= cpth	= EPATH(	 	context='forward_open', extension='.connection_path' )
    cpth[None]		= done	= octets_noop( 'done',
                                               terminal=True )
    done.initial[None]		= Connection_decode( 'O_T', source ='forward_open.O_T', large=False )
    done.initial[None]		= Connection_decode( 'T_O', source= 'forward_open.T_O', large=False )
    return srvc

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_OPEN_REQ, name=Connection_Manager.FWD_OPEN_NAM,
                                            short=Connection_Manager.FWD_OPEN_CTX, machine=__forward_open() )

def __forward_open_large():
    """Handle Large Forward Open request.
    """
    srvc			= USINT(	 	context='service' )
    srvc[True]		= path	= EPATH(		context='path')
    path[True]		= prio	= USINT(		context='forward_open', extension='.priority_time_tick' )
    prio[True]		= timo	= USINT(		context='forward_open', extension='.timeout_ticks' )
    timo[True]		= otid	= UDINT(		context='forward_open.O_T', extension='.connection_ID' )
    otid[True]		= toid	= UDINT(		context='forward_open.T_O', extension='.connection_ID' )
    toid[True]		= cser	= UINT(			context='forward_open', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_open', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_open', extension='.O_serial' )
    oser[True]		= tmul	= USINT(		context='forward_open', extension='.connection_timeout_multiplier' )
    tmul[True]		= rsvd	= octets_drop(		'pad', repeat=3 )
    rsvd[True]		= otrpi	= UDINT(		context='forward_open.O_T', extension='.RPI' )
    otrpi[True]		= otncp	= DWORD(		context='forward_open.O_T', extension='.NCP' )
    otncp[True]		= torpi	= UDINT(		context='forward_open.T_O', extension='.RPI' )
    torpi[True]		= toncp	= DWORD(		context='forward_open.T_O', extension='.NCP' )
    toncp[True]		= tclt	= USINT( 		context='forward_open', extension='.transport_class_triggers' )
    # 37 bytes from Path to start of Connection Path Size; Connection Path begins on a Word boundary
    tclt[True]		= cpth	= EPATH(	 	context='forward_open', extension='.connection_path' )
    cpth[None]		= done	= octets_noop( 'done',
                                               terminal=True )
    done.initial[None]		= Connection_decode( 'O_T', source ='forward_open.O_T', large=True )
    done.initial[None]		= Connection_decode( 'T_O', source= 'forward_open.T_O', large=True )
    return srvc

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_OPLG_REQ, name=Connection_Manager.FWD_OPEN_NAM + " Large",
                                            short=Connection_Manager.FWD_OPEN_CTX, machine=__forward_open_large() )

def __forward_open_reply():
    srvc			= USINT(	context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    # A minimal Forward Open reply may be just a success/failure status?  Not supported, but we'll parse...
    stts[None]		= mark	= octets_noop(	'check',context='forward_open',
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )

    # Successful reply, if status is 0x00
    otid			= UDINT(		context='forward_open.O_T', extension='.connection_ID' )
    otid[True]		= toid	= UDINT(		context='forward_open.T_O', extension='.connection_ID' )
    toid[True]		= cser	= UINT(			context='forward_open', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_open', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_open', extension='.O_serial' )
    oser[True]		= otapi	= UDINT(		context='forward_open.O_T', extension='.API' )
    otapi[True]		= toapi	= UDINT(		context='forward_open.T_O', extension='.API' )
    toapi[True]		= rsiz	= USINT(		context='forward_open', extension='.application_size' )
    rsiz[True]		= rsvd	= octets_drop(		'pad', repeat=1 )

    # Parse all segments in a sub-dfa limited by the parsed application.size (in words; double) If
    # the size is zero, we won't be parsing anything; initialize data to [].  Also moves the parsed
    # .application_size into application.size.  Triggers only if there is data following the pad.
    def size_data( path=None, data=None, **kwds ):
        app			= data[path].setdefault( 'application', {} )
        app.size		= data[path].pop( 'application_size' )
        octets			= app.size * 2
        if not octets:
            app.data		= []
        return octets

    rsvd[None]			= dfa(		'data',		context='forward_open',
                                                initial=typed_data(
                                                    context='application', tag_type=USINT.tag_type,
                                                    terminal=True ),
                                                limit=size_data,
                                                terminal=True )
    # Choose between Successful reply (otid), or if status is not 0x00, fall through and parse Failure reply
    stts[True]			= decide(	'ok',	state=otid,
        predicate=lambda path=None, data=None, **kwds: data[path+'.status' if path else 'status'] == 0x00 )
    stts[True]		= cser	= UINT(			context='forward_open', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_open', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_open', extension='.O_serial' )
    oser[None]			= octets_noop(	'check',
                                                terminal=True )
    
    # Optionally may include a remaining_path_size
    oser[True]		= rpth	= USINT(		context='forward_open', extension='.remaining_path_size' )
    rpth[True]		= rsvd	= octets_drop(	'reserved',	repeat=1,
    						terminal=True )

    return srvc

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_OPEN_RPY, name=Connection_Manager.FWD_OPEN_NAM + " Reply",
                                            short=Connection_Manager.FWD_OPEN_CTX, machine=__forward_open_reply() )

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_OPLG_RPY, name=Connection_Manager.FWD_OPEN_NAM + " Large Reply",
                                            short=Connection_Manager.FWD_OPEN_CTX, machine=__forward_open_reply() )


def __forward_close():
    """Handle Forward Close request.  Note that the Connection Path Size / Connection Path has a pad byte (vs.
    Forward Open, which does not).
    """
    srvc			= USINT(	 	context='service' )
    srvc[True]		= path	= EPATH(		context='path')
    path[True]		= prio	= USINT(		context='forward_close', extension='.priority_time_tick' )
    prio[True]		= timo	= USINT(		context='forward_close', extension='.timeout_ticks' )
    timo[True]		= cser	= UINT(			context='forward_close', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_close', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_close', extension='.O_serial' )
    # 10 bytes from Path to start of Connection Path Size; a pad byte is required for Connection Path
    # to begin on a Word boundary.
    oser[True]		= cpth	= EPATH_padded(	 	context='forward_close', extension='.connection_path',
                                                    terminal=True )
    return srvc

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_CLOS_REQ, name=Connection_Manager.FWD_CLOS_NAM,
                                            short=Connection_Manager.FWD_CLOS_CTX, machine=__forward_close() )


def __forward_close_reply():
    srvc			= USINT(	context='service' )
    srvc[True]		= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    # A minimal Forward Close reply may be just a success/failure status?  Yes, we've observed these from C*Logix.
    stts[None]		= mark	= octets_noop(		context='forward_close',
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )

    stts[True]		= cser	= UINT(			context='forward_close', extension='.connection_serial' )
    cser[True]		= ovnd	= UINT(			context='forward_close', extension='.O_vendor' )
    ovnd[True]		= oser	= UDINT(		context='forward_close', extension='.O_serial' )
    oser[True]		= rsiz	= USINT(		context='forward_close', extension='.application_size' )
    rsiz[True]		= rsvd	= octets_drop(		'pad', repeat=1 )

    # Parse all segments in a sub-dfa limited by the parsed application.size (in words; double) If
    # the size is zero, we won't be parsing anything; initialize data to [].  Also moves the parsed
    # .application_size into application.size.  Triggers only if there is data following the pad.
    def size_data( path=None, data=None, **kwds ):
        app			= data[path].setdefault( 'application', {} )
        app.size		= data[path].pop( 'application_size' )
        octets			= app.size * 2
        if not octets:
            app.data		= []
        return octets

    rsvd[None]			= dfa(		'data',		context='forward_close',
                                                initial=typed_data(
                                                    context='application', tag_type=USINT.tag_type,
                                                    terminal=True ),
                                                limit=size_data,
                                                terminal=True )
    return srvc

Connection_Manager.register_service_parser( number=Connection_Manager.FWD_CLOS_RPY, name=Connection_Manager.FWD_CLOS_NAM + " Reply",
                                            short=Connection_Manager.FWD_CLOS_CTX, machine=__forward_close_reply() )
