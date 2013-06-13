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
enip.device	-- support for implementing an EtherNet/IP device Objects and Attributes

"""
__all__				= [ 'lookup', 'resolve', 'resolve_element',
                                    'Object', 'Attribute',
                                    'Connection_Manager', 'Message_Router', 'Identity' ]

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
from   cpppo import misc
import cpppo.server
from   cpppo.server import network

from .parser import *

if __name__ == "__main__":
    logging.basicConfig( **cpppo.log_cfg )
    #logging.getLogger().setLevel( logging.DETAIL )

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
    """Lookup by path (string type), or class/instance/attribute ID"""
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
    finally:
        log.detail( "Class %5d/0x%04x, Instance %3d, Attribute %5r ==> %s",
                    class_id, class_id, instance_id, attribute_id, 
                    res if not exception else "Failed: %s" % exception )
    return res

# 
# symbol	-- All known symbolic address
# resolve()	-- Resolve the class, instance [and attribute] from a path.
# 
# A path is something of the form:
# 
#     {
#         'size':6,
#         'segment':[
#             {'symbolic':'SCADA','length':5}, 
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
                sym	= working['symbolic']
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
    """A simple Attribute just has a default value of 0.  We'll instantiate an instance of the supplied
    enip.TYPE/STRUCT class as the Attribute's .parser property.  This can be used to parse incoming
    data, and produce the current value in bytes form.
    
    The value defaults to a scalar 0, but may be configured as an array by setting default to a list
    of values of the desired array size.

    """
    def __init__( self, name, type_cls, default=0 ):
        self.name		= name
        self.default	       	= default
        self.parser		= type_cls()

    def __str__( self ):
        value			= self.value
        return "%-24.24s %8s[%3d] == %s" % (
            self.name, self.parser.__class__.__name__, len( self ), reprlib.repr( self.value ))
    __repr__ 			= __str__

    def __len__( self ):
        """Scalars are limited to 1 indexable element, while arrays (implemented as lists) are limited to
        their length. """
        return 1 if not isinstance( self.value, list ) else len( self.value )

    @property
    def value( self ):
        return self.default

    def produce( self, start=0, stop=None ):
        """Output the binary rendering of the current value, using enip type_cls instance configured, to
        produce the value in binary form ('produce' is normally a classmethod on the type_cls)."""
        if isinstance( self.value, list ):
            # Vector
            if stop is None:
                stop		= len( self.value )
            return b''.join( self.parser.produce( v ) for v in self.value[start:stop] )
        # Scalar
        return self.parser.produce( self.value )
        

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


class NumInstances( MaxInstance ):
    def __init__( self, name, type_cls, **kwds ):
        super( NumInstances, self ).__init__( name=name, type_cls=type_cls, **kwds )

    @property
    def value( self ):
        """Count how many instances are presently in existence; use the parent class MaxInstances.value."""
        return sum( lookup( class_id=self.class_id, instance_id=i_id ) is not None
                    for i_id in range( 1, super( NumInstances, self ).value + 1 ))


# 
# EtherNet/IP CIP Object
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
            'input':			array.array( 'B', [	# encoded response payload
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
    parser			= cpppo.dfa( 'service', initial=cpppo.state( 'select' ))

    service			= {} # Service number/name mappings
    transit			= {} # Symbol to transition to service parser on

    @classmethod
    def register_service_parser( cls, number, name, machine ):
        assert number not in cls.service and name not in cls.service, \
            "Duplicate service #%d: %r registered for Object %s" % ( number, name, cls.__name__ )

        cls.service[number]	= name
        cls.service[name]	= number
        cls.transit[number]	= chr( number ) if sys.version_info.major < 3 else number
        cls.parser.initial[cls.transit[number]] \
				= cpppo.dfa( name, initial=machine, terminal=True )

    
    GA_ALL_NAM			= "Get Attributes All"
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

        ( log.normal if self.instance_id else log.info )( 
            "%16s, Class ID %02x, Instance ID %d created",
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
    __repr__ 			= __str__

    def request( self, data ):
        """Handle a request, converting it into a response.  Must be a dotdict data artifact such as is
        produced by the Object's parser.  For example, a request data containing either of the
        following:

            {
                'service':		0x01,
                'get_attributes_all':	True,
            }

        should run the Get Attribute All service, and return the binary payload that results from
        the command.  This may include any erroneous status codes that result from errors detected
        during the attempt to process the command.

        TODO: Validate the request.

        """
        result			= b''
        if 'get_attributes_all' in data or data.setdefault( 'service', 0x01 ) == 0x01:
            a_id		= 1
            while str(a_id) in self.attribute:
                result	       += self.attribute[str(a_id)].produce()
                a_id	       += 1
                
            return result

        assert False, "%s (Class %x, Instance %x): Failed to process unknown service request: %s" % (
            self.class_id, self.instance_id, data )


# Register the standard Object parsers
def __get_attributes_all():
    gasv			= USINT(		 	context='service' )
    gasv[True]	= gapt		= EPATH(			context='path')
    gapt[None]			= move_if( 	'get_attr_all',	destination='.get_attributes_all',
                                                initializer=True, # was: lambda **kwds: cpppo.dotdict(),
                                                state=octets_noop( terminal=True ))
    return gasv

Object.register_service_parser( number=Object.GA_ALL_REQ, name=Object.GA_ALL_NAM,
                                 machine=__get_attributes_all() )






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

        

class Connection_Manager( Object ):
    class_id			= 0x06

    def __init__( self, name=None, **kwds ):
        super( Connection_Manager, self ).__init__( name=name, **kwds )

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes
            pass


class Message_Router( Object ):
    """Manages underlying EtherNet/IP connection, and processes incoming EtherNet/IP requests.  Parses
    encapsulated message according to available CIP device objects, and then forwards parsed
    messages to the appropriate object.  

    Handles basic EtherNet/IP connection related messages itself (Register, Unregister).

    No externally visible Attributes.  Does not parse or respond to normal service requests
    """
    class_id			= 0x02
    parser			= CIP() # TODO: must pass device Object lookup function...

    def __init__( self, name=None, **kwds ):
        super( Message_Router, self ).__init__( name=name, **kwds )

        # All known session handles.
        self.sessions		= set()

        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes
            pass

    def request( self, data ):
        """Handles a parsed request.enip.*, and produces an appropriate response.enip.*.  For connection
        related requests (Register, Unregister), handle locally.  Return True iff request processed
        and connection should proceed to process further messages.

        """
        # Create a data.response with a structural copy of the request.enip.header.  This means that
        # the dictionary structure is new (we won't alter the request.enip... when we add entries in
        # the resonse...), but the actual mutable values (eg. array.array ) are copied.  If we need
        # to change any values, replace them with new values instead of altering them!
        data.response		= cpppo.dotdict( data.request )

        if 'enip.CIP.register' in data.request:
            # Allocates a new session_handle, and returns the register.protocol_version and
            # .options_flags unchanged (if supported)

            # TODO: Check if supported
            session		= random.randint( 0, 2**32 )
            while not session or session in self.sessions:
                session		= random.randint( 0, 2**32 )
            self.sessions.add( session )
            data.response.enip.session_handle \
                		= session
            return True

        super( Message_Router, self ).request( data )
