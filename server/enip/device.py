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
enip.device	-- support for implementing an EtherNet/IP device Objects and Attributes

"""
__all__				= ['lookup', 'resolve', 'resolve_element',
                                   'redirect_tag', 'resolve_tag', 
                                   'Object', 'Attribute',
                                   'UCMM', 'Connection_Manager', 'Message_Router', 'Identity']

import array
import codecs
import errno
import logging
import os
import random
import sys
import threading
import time
import traceback
try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
import cpppo.server
from   cpppo.server import network

from .parser import *

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
directory			= cpppo.dotdict()

def __directory_path( class_id, instance_id=0, attribute_id=None ):
    """It is not possible to in produce a path with an attribute_id=0; this is
    not a invalid Attribute ID.  The '0' entry is reserved for the Object, which is
    only accessible with attribute_id=None."""
    assert attribute_id != 0, \
        "Class %5d/0x%04x, Instance %3d; Invalid Attribute ID 0"
    return str( class_id ) \
        + '.' + str( instance_id ) \
        + '.' + ( str( attribute_id if attribute_id else 0 ))

def lookup( class_id, instance_id=0, attribute_id=None ):
    """Lookup by path ("#.#.#" string type), or class/instance/attribute ID, or """
    exception			= None
    try:
        key			= class_id
        if not isinstance( class_id, cpppo.type_str_base ):
            assert type( class_id ) is int
            key			= __directory_path(
                class_id=class_id, instance_id=instance_id, attribute_id=attribute_id )
        res			= directory.get( key, None )
    except Exception as exc:
        exception		= exc
        res			= None
    finally:
        log.detail( "Class %5d/0x%04x, Instance %3d, Attribute %5r ==> %s",
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
symbol				= {}
symbol_keys			= ('class', 'instance', 'attribute')

def redirect_tag( tag, address ):
    """Establish (or change) a tag, redirecting it to the specified class/instance/attribute address.
    Make sure we stay with only str type tags (mostly for Python2, in case somehow we get a Unicode
    tag)"""
    tag				= str( tag )
    assert isinstance( address, dict )
    assert all( k in symbol_keys for k in address )
    assert all( k in address     for k in symbol_keys )
    symbol[tag]			= address

def resolve_tag( tag ):
    """Return the (class_id, instance_id, attribute_id) tuple corresponding to tag, or None if not specified"""
    address			= symbol.get( str( tag ), None )
    if address:
        return tuple( address[k] for k in symbol_keys )
    return None


def resolve( path, attribute=False ):
    """Given a path, returns the fully resolved (class,instance[,attribute]) tuple required to lookup an
    Object/Attribute.  Won't allow over-writing existing elements (eg. 'class') with symbolic data
    results.  Call with attribute=True to force resolving to the Attribute level; otherwise, always
    returns None for the attribute.

    """

    result			= { 'class': None, 'instance': None, 'attribute': None }

    for term in path['segment']:
        if ( result['class'] is not None and result['instance'] is not None
             and ( not attribute or result['attribute'] is not None )):
            break # All desired terms specified; done!
        working		= dict( term )
        while working:
            # Each term is something like {'class':5}, {'instance':1}, or (from symbol table):
            # {'class':5,'instance':1}.  Pull each key (eg. 'class') from working into result,
            # but only if 
            for key in result:
                if key in working:
                    assert result[key] is None, \
                        "Failed to override %r==%r with %r from path segment %r in path %r" % (
                            key, result[key], working[key], term, path['segment'] )
                    result[key] = working.pop( key )
            if working:
                assert 'symbolic' in working, \
                    "Invalid term %r found in path %r" % ( working, path['segment'] )
                sym	= str( working['symbolic'] )
                assert sym in symbol, \
                    "Unrecognized symbolic name %r found in path %r" % ( sym, path['segment'] )
                working	= dict( symbol[sym] )

    assert ( result['class'] is not None and result['instance'] is not None
             and ( not attribute or result['attribute'] is not None )), \
        "Failed to resolve required Class (%r), Instance (%r) %s Attribute(%r) from path: %r" % (
            result['class'], result['instance'], "and the" if attribute else "but not",
            result['attribute'], path['segment'] )
    result		= result['class'], result['instance'], result['attribute'] if attribute else None
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

    """
    def __init__( self, name, type_cls, default=0, error=0x00 ):
        self.name		= name
        self.default	       	= default
        self.scalar		= isinstance( default, cpppo.type_str_base ) or not hasattr( default, '__len__' )
        self.parser		= type_cls()
        self.error		= error		# If an error code is desired on access

    @property
    def value( self ):
        return self.default
    @value.setter
    def value( self, v ):
        assert self.scalar, "Scalar assignment to %s not supported" % type( self.default )
        self.default		= type(self.default)( v )

    def __str__( self ):
        return "%-12s %5s[%4d] == %s" % (
            self.name, self.parser.__class__.__name__, len( self ), reprlib.repr( self.value ))
    __repr__ 			= __str__

    def __len__( self ):
        """Scalars are limited to 1 indexable element, while arrays (implemented as lists) are limited to
        their length. """
        return 1 if self.scalar else len( self.value )

    # Indexing.  This allows us to get/set individual values in the Attribute's underlying data
    # repository.  Simple, linear slices are supported.
    def _validate_key( self, key ):
        """Support simple, linear beg:end slices within Attribute len with no truncation; even on scalars,
        allows [0:1].  Returns type of index, which must be slice or int.

        """
        if isinstance( key, slice ):
            idx			= key.indices( len( self ))
            if idx[2] == 1 and idx[0] < idx[1] and idx[1] <= len( self ) and idx[1] == key.stop:
                return slice
            raise KeyError( "%r indices %r too complex, empty, or beyond Attribute length %d" % (
                key, idx, len( self )))
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
class Object( object ):
    """An EtherNet/IP device.Object is capable of parsing and processing a number of requests.  It has
    a class_id and an instance_id; an instance_id of 0 indicates the "class" instance of the
    device.Object, which has different (class level) Attributes (and may respond to different commands)
    than the other instance_id's.

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

        data = cpppo.dotdict()
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

    """
    max_instance		= 0
    lock			= threading.Lock()
    service			= {} # Service number/name mappings
    transit			= {} # Symbol to transition to service parser on

    # The parser doesn't add a layer of context; run it with a path= keyword to add a layer
    parser			= cpppo.dfa_post( service, initial=cpppo.state( 'select' ),
                                                  terminal=True )

    @classmethod
    def register_service_parser( cls, number, name, short, machine ):
        """Registers a parser with the Object.  May be invoked during import; no logging."""

        assert number not in cls.service and name not in cls.service, \
            "Duplicate service #%d: %r registered for Object %s" % ( number, name, cls.__name__ )

        cls.service[number]	= name
        cls.service[name]	= number
        cls.transit[number]	= chr( number ) if sys.version_info.major < 3 else number
        cls.parser.initial[cls.transit[number]] \
				= cpppo.dfa( name=short, initial=machine, terminal=True )

    
    GA_ALL_NAM			= "Get Attributes All"
    GA_ALL_CTX			= "get_attributes_all"
    GA_ALL_REQ			= 0x01
    GA_ALL_RPY			= GA_ALL_REQ | 0x80
    GA_SNG_NAM			= "Get Attribute Single"
    GA_SNG_REQ			= 0x0e
    GA_SNG_RPY			= GA_SNG_REQ | 0x80
    SA_SNG_NAM			= "Set Attribute Single"
    SA_SNG_REQ			= 0x10
    SA_SNG_RPY			= SA_SNG_REQ | 0x80

    def __init__( self, name=None, instance_id=None ):
        """Create the instance (default to the next available instance_id).  An instance_id of 0 holds
        the "class" attributes/commands.

        """
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
            "CIP Object class %x, instance %x already exists" % ( self.class_id, self.instance_id )

        # 
        # directory.1.2.None 	== self
        # self.attribute 	== directory.1.2 (a dotdict), for direct access of our attributes
        # 
        self.attribute		= directory.setdefault( str( self.class_id )+'.'+str( instance_id ),
                                                        cpppo.dotdict() )
        self.attribute['0']	= self

        # Check that the class-level instance (0) has been created; if not, we'll create one using
        # the default parameters.  If this isn't appropriate, then the user should create it using
        # the appropriate parameters.
        if lookup( self.class_id, 0 ) is None:
            self.__class__( name='meta-'+self.name, instance_id=0 )

        if self.instance_id == 0:
            # Set up the default Class-level values.
            self.attribute['1']= Attribute( 	'Revision', 		INT, default=0 )
            self.attribute['2']= MaxInstance( 'Max Instance',		INT,
                                                class_id=self.class_id )
            self.attribute['3']= NumInstances( 'Num Instances',		INT,
                                                class_id=self.class_id )
            # A UINT array; 1st UINT is size (default 0)
            self.attribute['4']= Attribute( 	'Optional Attributes',	INT, default=0 )
            

    def __str__( self ):
        return self.name
    
    def __repr__( self ):
        return "(0x%02x,%3d) %s" % ( self.class_id, self.instance_id, self )

    def request( self, data ):
        """Handle a request, converting it into a response.  Must be a dotdict data artifact such as is
        produced by the Object's parser.  For example, a request data containing either of the
        following:

            {
                'service':		0x01,
                'get_attributes_all':	True,
            }

        should run the Get Attribute All service, and return True if the channel should continue.
        In addition, we produce the bytes used by any higher level encapsulation.

        TODO: Validate the request.
        """
        result			= b''
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Request: %s", self, enip_format( data ))
        try:
            # Validate the request.  As we process, ensure that .status is set to reflect the
            # failure mode, should an exception be raised.  Return True iff the communications
            # channel should continue.
            data.status		= 0x08		# Service not supported, if not recognized
            data.pop( 'status_ext', None )

            if ( data.get( 'service' ) == self.GA_ALL_REQ
                 or 'get_attributes_all' in data and data.setdefault( 'service', self.GA_ALL_REQ ) == self.GA_ALL_REQ ):
                pass
            else:
                raise AssertionError( "Unrecognized Service Request" )

            # A recognized request; process the request data artifact, converting it into a reply.
            data.service           |= 0x80
                
            if data.service == self.GA_ALL_RPY:
                # Get Attributes All.  Collect up the bytes representing the attributes.  Replace
                # the place-holder .get_attribute_all=True with a real dotdict.
                data.status	= 0x08 # Service not supported, if we fail to access an Attribute
                result		= b''
                a_id		= 1
                while str(a_id) in self.attribute:
                    result     += self.attribute[str(a_id)].produce()
                    a_id       += 1
                data.get_attributes_all = cpppo.dotdict()
                data.get_attributes_all.data = bytearray( result )

                data.status	= 0x00
                data.pop( 'status_ext', None )

                # TODO: Other request processing here... 
            else:
                raise AssertionError( "Unrecognized Service Reply" )
        except Exception as exc:
            log.warning( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s\nStack %s", self,
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
        data.input		= bytearray( self.produce( data ))
        log.detail( "%s Response: %s: %s", self, self.service[data.service], enip_format( data ))
        return True # We shouldn't be able to terminate a connection at this level

    @classmethod
    def produce( cls, data ):
        result			= b''
        if ( data.get( 'service' ) == cls.GA_ALL_REQ 
             or 'get_attributes_all' in data and data.setdefault( 'service', cls.GA_ALL_REQ ) == cls.GA_ALL_REQ ):
            # Get Attributes All
            result	       += USINT.produce(	data.service )
            result	       += EPATH.produce(	data.path )
        elif data.get( 'service' ) == cls.GA_ALL_RPY:
            # Get Attributes All Reply
            result	       += USINT.produce(	data.service )
            result	       += b'\x00' # reserved
            result	       += status.produce( 	data )
            result	       += octets_encode( 	data.get_attributes_all.data )
        else:
            assert False, "%s doesn't recognize request/reply format: %r" % ( cls.__name__, data )
        return result

# Register the standard Object parsers
def __get_attributes_all():
    srvc			= USINT(		 	context='service' )
    srvc[True]		= path	= EPATH(			context='path')
    path[None]		= mark	= octets_noop(			context='get_attributes_all',
                                                terminal=True )
    mark.initial[None]		= move_if( 	'mark',		initializer=True )
    return srvc

Object.register_service_parser( number=Object.GA_ALL_REQ, name=Object.GA_ALL_NAM, 
                                short=Object.GA_ALL_CTX, machine=__get_attributes_all() )

def __get_attributes_all_reply():
    srvc			= USINT(		 	context='service' )
    srvc[True]	 	= rsvd	= octets_drop(	'reserved',	repeat=1 )
    rsvd[True]		= stts	= status()
    stts[None]		= data	= octets(			context='get_attributes_all',
                                                octets_extension='.data',
                                            	terminal=True )
    data[True]		= data	# Soak up all remaining data

    return srvc

Object.register_service_parser( number=Object.GA_ALL_RPY, name=Object.GA_ALL_NAM + " Reply", 
                                short=Object.GA_ALL_CTX, machine=__get_attributes_all_reply() )



class Identity( Object ):
    class_id			= 0x01

    def __init__( self, name=None, **kwds ):
        super( Identity, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes (these example defaults are from a Rockwell Logix PLC)
            self.attribute['1']	= Attribute( 'Vendor Number', 		INT,	default=0x0001 )
            self.attribute['2']	= Attribute( 'Device Type', 		INT,	default=0x000e )
            self.attribute['3']	= Attribute( 'Product Code Number',	INT,	default=0x0036 )
            self.attribute['4']	= Attribute( 'Product Revision', 	INT,	default=0x0b14 )
            self.attribute['5']	= Attribute( 'Status Word', 		INT,	default=0x3160 )
            self.attribute['6']	= Attribute( 'Serial Number', 		DINT,	default=0x006c061a )
            self.attribute['7']	= Attribute( 'Product Name', 		SSTRING,default='1756-L61/B LOGIX5561' )


class UCMM( Object ):
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

    parser			= CIP()
    command			= {
        0x0065: "Register Session",
        0x0066: "Unregister Session",
        0x006f: "SendRRData",
    }
    lock			= threading.Lock()
    sessions			= {}		# All known session handles, by addr

    def request( self, data ):
        """Handles a parsed enip.* request, and converts it into an appropriate response.  For
        connection related requests (Register, Unregister), handle locally.  Return True iff request
        processed and connection should proceed to process further messages.

        """
        if log.isEnabledFor( logging.INFO ):
            log.info( "%r Request: %s", self, enip_format( data ))

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

                # In this implementation, we can *only* process un-routed requests, or requests
                # routed to the local backplane: port 1, link 0.  All Unconnected Requests have a
                # NULL Address in CPF item 0.
                assert 'enip.CIP.send_data.CPF' in data \
                    and data.enip.CIP.send_data.CPF.count == 2 \
                    and data.enip.CIP.send_data.CPF.item[0].length == 0, \
                    "EtherNet/IP UCMM remote routed requests unimplemented"
                unc_send		= data.enip.CIP.send_data.CPF.item[1].unconnected_send
                if 'path' in unc_send:
                    ids			= resolve( unc_send.path )
                    assert ids[0] == 0x06 and ids[1] == 1, \
                        "Unconnected Send targeted Object other than Connection Manager: 0x%04x/%d" % ( ids[0], ids[1] )
                if 'route_path.segment' in unc_send:
                    assert len( unc_send.route_path.segment ) == 1 \
                        and unc_send.route_path.segment[0] == {'link': 0, 'port':1}, \
                        "Unconnected Send routed to link other than backplane link 1, port 0: %r" % unc_send.route_path
                CM			= lookup( class_id=0x06, instance_id=1 )
                CM.request( unc_send )
                
                # After successful processing of the Unconnected Send on the target node, we
                # eliminate the Unconnected Send wrapper (the unconnected_send.service = 0x52,
                # route_path, etc), and replace it with a simple encapsulated raw request.input.  We
                # do that by emptying out the unconnected_send, except for the bare request.
                # Basically, all the Unconnected Send encapsulation and routing is used to deliver
                # the request to the target Object, and then is discarded and the EtherNet/IP
                # envelope is simply returned directly to the originator carrying the response
                # payload.
                if log.isEnabledFor( logging.DEBUG ):
                    log.debug( "%s Repackaged: %s", self, enip_format( data ))
                
                data.enip.CIP.send_data.CPF.item[1].unconnected_send  = cpppo.dotdict()
                data.enip.CIP.send_data.CPF.item[1].unconnected_send.request = unc_send.request

                # And finally, re-encapsulate the CIP SendRRData, with its (now unwrapped)
                # Unconnected Send request response payload.
                if log.isEnabledFor( logging.DEBUG ):
                    log.debug( "%s Regenerating: %s", self, enip_format( data ))
                data.enip.input		= bytearray( self.parser.produce( data.enip ))
                
        except Exception as exc:
            # On Exception, if we haven't specified a more detailed error code, return Service not
            # supported.  This 
            log.warning( "%r Command 0x%04x %s failed with Exception: %s\nRequest: %s\n%s", self,
                         data.enip.command if 'enip.command' in data else 0,
                         ( self.command[data.enip.command]
                           if 'enip.command' in data and data.enip.command in self.command
                           else "(Unknown)"), exc, enip_format( data ),
                         ''.join( traceback.format_exception( *sys.exc_info() )))
            if 'enip.status' not in data or data.enip.status == 0x00:
                data['enip.status']	= 0x08 # Service not supported
            pass


        # The enip.input EtherNet/IP encapsulation is assumed to have been filled in.  Otherwise, no
        # encapsulated response is expected.
        if log.isEnabledFor( logging.INFO ):
            log.info( "%s Response: %s", self, enip_format( data ))
        return proceed
            

class Message_Router( Object ):
    """Processes incoming requests.  Normally a derived class would expand the normal set of Services
    with any specific to the actual device.

    """
    class_id			= 0x02

    MULTIPLE_NAM		= "Multiple Service Packet"
    MULTIPLE_CTX		= "multiple"
    MULTIPLE_REQ		= 0x0a
    MULTIPLE_RPY		= MULTIPLE_REQ | 0x80

    ROUTE_FALSE			= 0	# Return False if invalid route
    ROUTE_RAISE			= 1	# Raise an Exception if invalid route

    def route( self, data, fail=ROUTE_FALSE ):
        """If the request is not for this object, return the target, else None.  On invalid route (no such
        object found), either raise Exception or return False.  Thus, we're returning a non-truthy
        value iff not routing to another object, OR if the route was invalid.

        """
        try:
            path, ids, target	= None, None, None
            path		= data.path
            ids			= resolve( path )
            if ( ids[0] == self.class_id and ids[1] == self.instance_id ):
                return None
            target		= lookup( *ids )
        except Exception as exc:
            # The resolution/lookup fails (eg. bad symbolic Tag); Either ignore it (return False)
            # and continue processing, so we can return a proper .status error code from the actual
            # request processing code, or raise an Exception.
            log.warning( "%s Failed attempting to resolve path %r: class,inst,addr: %r, target: %r",
                         self, path, ids, target )
            if ( fail == self.ROUTE_FALSE ):
                return False
            raise
        return target

    def request( self, data ):
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
        if ( data.get( 'service' ) == self.MULTIPLE_REQ
             or 'multiple' in data and data.setdefault( 'service', self.MULTIPLE_REQ ) == self.MULTIPLE_REQ ):
            # Multiple Service Packet Request
            pass
        else:
            # Not recognized; more generic command?
            return super( Message_Router, self ).request( data )

        # It is a Multiple Service Packet request; turn it into a reply.  Any exception processing
        # one of the sub-requests will fail this request; normally, the sub-request should just
        # return a non-zero Response Status in its payload...  If we cannot successfully iterate the
        # request payload, return a generic Service not supported.
        data.service	       |= 0x80
        try:
            data.status		= 0x16			# Object does not exist, if path invalid
            data.pop( 'status_ext', None )
            # If no data.path, default to self; If path, None if target is self.  Otherwise, an
            # invalid path with raise Exception.
            target		= None
            if 'path' in data:
                target		= self.route( data, fail=self.ROUTE_RAISE )
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Routing to %s: %s", self, target or "(self)", enip_format( data ))
            if target is None:
                target		= self

            data.status		= 8			# Service not supported, if anything blows up
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Parsed  on %s: %s", self, target, enip_format( data ))

            # We have a fully parsed Multiple Service Packet request, including sub-requests
            # Now, convert each sub-request into a response.
            for r in data.multiple.request:
                if log.isEnabledFor( logging.DETAIL ):
                    log.detail( "%s Process on %s: %s", self, target, enip_format( data ))
                target.request( r )
            data.status		= 0x00

        except Exception as exc:
            # On Exception, if we haven't specified a more detailed error code, return General
            # Error.  Remember: 0x06 (Insufficent Packet Space) is a NORMAL response to a successful
            # Read Tag Fragmented that returns a subset of the requested data.
            log.warning( "%r Service 0x%02x %s failed with Exception: %s\nRequest: %s\n%s", self,
                         data.service if 'service' in data else 0,
                         ( self.service[data.service]
                           if 'service' in data and data.service in self.service
                           else "(Unknown)"), exc, enip_format( data ),
                         ( '' if log.getEffectiveLevel() >= logging.NORMAL
                           else ''.join( traceback.format_exception( *sys.exc_info() ))))
            assert data.status, \
                "Implementation error: must specify non-zero .status before raising Exception!"
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
        """Produces an encoded Multiple Service Packet request or reply.  Defaults to produce the
        request, if no .service specified, and just .multiple_request.  Expects multiple_request to
        be an array of Message_Router requests, each one individually able to produce() a serialized
        result, using this same cls.produce() method.

            "unconnected_send.service": 0x0A,					# default, if '.multiple' seen
            "unconnected_send.multiple.path": { 'class': 0x06, 'instance': 1}	# default, if no path provided
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
        if ( data.get( 'service' ) == cls.MULTIPLE_REQ
             or 'multiple' in data and data.setdefault( 'service', cls.MULTIPLE_REQ ) == cls.MULTIPLE_REQ ):
            offsets		= []
            reqdata		= b''
            for r in reversed( data.multiple.request ):
                req		= cls.produce( r )
                offsets		= [ 0 ] + [ o + len( req ) for o in offsets ]
                reqdata		= req + reqdata

            result	       += USINT.produce(        data.service )
            result	       += EPATH.produce(        data.path if 'path' in data
                                    else cpppo.dotdict( segment=[{ 'class': cls.class_id }, { 'instance': 1 }] ))
            result	       += UINT.produce( 	len( offsets ))
            for o in offsets:
                result	       += UINT.produce( 	2 + 2 * len( offsets ) + o )
            result	       += reqdata
        elif data.get( 'service' ) == cls.MULTIPLE_RPY:
            # Collect up all (already produced) request results stored in each request[...].input
            result	       += USINT.produce(	data.service )
            result	       += USINT.produce(	0x00 )	# fill
            result	       += status.produce(	data )
            if data.status == 0x00:
                offsets		= []
                rpydata		= b''
                for r in reversed( data.multiple.request ):
                    rpy		= bytes( r.input ) # bytearray --> bytes
                    offsets	= [ 0 ] + [ o + len( rpy ) for o in offsets ]
                    rpydata	= rpy + rpydata
                result	       += UINT.produce(		len( offsets ))
                for o in offsets:
                    result     += UINT.produce( 	2 + 2 * len( offsets ) + o )
                result	       += rpydata
        else:
            result		= super( Message_Router, cls ).produce( data )

        return result

class state_multiple_service( cpppo.state ):
    def terminate( self, exception, machine, path, data ):
        super( state_multiple_service, self ).terminate( exception, machine, path, data )

        # Find the specified target Object, defaulting to the Message Router (eg. to parse reply).
        # This requires that a Message_Router derived class has been instantiated that understands
        # all protocol elements that could be included in the Multiple Service Packet response.
        target			= None
        if path+'.path' in data:
            ids			= resolve( data[path+'.path'] )
        else:
            ids			= (Message_Router.class_id, 1, None)
        try:
            target		= lookup( *ids )
        except:
            log.warning( "Multiple Service failure: %s\n%s",
                         ''.join( traceback.format_exception( *sys.exc_info() )),
                         ''.join( traceback.format_stack() ))
            return
        finally:
            if log.isEnabledFor( logging.DETAIL ):
                log.detail( "%s Target: %s", target, enip_format( data ))

        def closure():
            """Closure capturing data, to parse the data.multiple.request_data and append the resultant
            decoded requests to data.multiple.request.

            Match up pairs of offsets[oi,oi+1], and use the target Object to parse the snippet of
            request data payload into request[oi].  Last request offset gets balance request data.
            If the DFA is in use (eg. we're using our own Object's parser), schedule it for
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
                req		= cpppo.dotdict()
                with target.parser as machine:
                    for m,s in machine.run( source=cpppo.peekable( reqdata[beg:end] ), data=req ):
                        pass
                request.append( req )

        if target.parser.lock.locked():
            target.parser.post.append( closure )
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
    off_[None]			= cpppo.state( 	'offset',
                                                terminal=True )

    # Parse each of the .offset__ --> .offsets[...] values in a sub-dfa, repeating .number times
    numr[None]		= offs	= cpppo.dfa(    'offsets',
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
    stts[True]		= numr	= UINT(		'number',	context='multiple', extension='.number' )
    
    # Prepare a state-machine to parse each UINT into .UINT, and move it onto the .offsets list
    off_			= UINT(		'offset',	context='multiple', extension='.UINT' )
    off_[None]			= move_if( 	'offset',	source='.multiple.UINT',
                                        destination='.multiple.offsets', initializer=lambda **kwds: [] )
    off_[None]			= cpppo.state( 	'offset',
                                             terminal=True )
    # Parse each of the .offset__ --> .offsets[...] values in a sub-dfa, repeating .number times
    numr[None]		= offs	= cpppo.dfa(    'offsets',
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

    """
    class_id			= 0x06

    UC_SND_REQ			= 0x52 		# Unconnected Send
    FW_OPN_REQ			= 0x54		# Forward Open (unimplemented)
    FW_CLS_REQ			= 0x4E		# Forward Close (unimplemented)

    def request( self, data ):
        """
        Handles an unparsed request.input, parses it and processes the request with the Message Router.
        

        """
        # We don't check for Unconnected Send 0x52, because replies (and some requests) don't
        # include the full wrapper, just the raw command.  This is quite confusing; especially since
        # some of the commands have the same code (eg. Read Tag Fragmented, 0x52).  Of course, their
        # replies don't (0x52|0x80 == 0xd2).  The CIP.produce recognizes the absence of the
        # .command, and simply copies the encapsulated request.input as the response payload.  We
        # don't encode the response here; it is done by the UCMM.
        assert 'request' in data and 'input' in data.request, \
            "Unconnected Send message with absent or empty request"
        if log.isEnabledFor( logging.INFO ):
            log.info( "%s Request: %s", self, enip_format( data ))

        #log.info( "%s Parsing: %s", self, enip_format( data.request ))
        # Get the Message Router to parse and process the request into a response, producing a
        # data.request.input encoded response, which we will pass back as our own encoded response.
        MR			= lookup( class_id=0x02, instance_id=1 )
        source			= cpppo.rememberable( data.request.input )
        try: 
            with MR.parser as machine:
                for i,(m,s) in enumerate( machine.run( path='request', source=source, data=data )):
                    pass
                    #log.detail( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %s",
                    #            machine.name_centered(), i, s, source.sent, source.peek(),
                    #            repr( data ) if log.getEffectiveLevel() < logging.DETAIL else reprlib.repr( data ))

            #log.info( "%s Executing: %s", self, enip_format( data.request ))
            MR.request( data.request )
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

