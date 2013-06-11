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
enip.device	-- support for implementing an EtherNet/IP device


"""

import array
import codecs
import errno
import logging
import os
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
# path		-- Returns the path for an object to class, instance or attribute level
# lookup	-- Find a class/instance/attribute
# 
#     Object/Attribute lookup.    For example:
# 
#         directory.6.0		Class 6 "Class" level Object and Attributes
#         directory.6.1		Class 6, Instance 1 Object and Attributes
#         directory.6.1.None	Class 6, Instance 1 device.Object (python instance)
#         directory.6.1.1	Class 6, Instance 1, Attribute 1 device.Attribute (python instance)
# 
directory			= cpppo.dotdict()

def path( class_id, instance_id=0, attribute_id=None ):
    return '.'.join( str( term ) 
                     for term in ( class_id, instance_id, attribute_id ))

def lookup( class_id, instance_id=0, attribute_id=None ):
    """Lookup by path (string type), or class/instance/attribute ID"""
    key				= class_id
    if not isinstance( class_id, cpppo.type_str_base ):
        assert type( class_id ) is int
        key			= path(
            class_id=class_id, instance_id=instance_id, attribute_id=attribute_id )
    res				= directory.get( key, None )
    log.info( "device directory[%r] == %s", key, res )
    return res

# 
# EtherNet/IP CIP Object Attribute
# 
class Attribute( object ):
    """A simple Attribute just has a default value of 0.  We'll instantiate an instance of the supplied
    enip.TYPE/STRUCT class as the Attribute's .parser property.  This can be used to parse incoming
    data, and produce the current value in bytes form."""
    def __init__( self, name, type_cls, default=0 ):
        self.name		= name
        self.default	       	= default
        self.parser		= type_cls()

    def __str__( self ):
        return "%-32.32s == %s" % ( self.name, self.value )
    __repr__ 			= __str__

    @property
    def value( self ):
        return self.default

    def produce( self ):
        """Output the binary rendering of the current value, using enip type_cls instance configured, to
        produce the value in binary form ('produce' is normally a classmethod on the type_cls)."""
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
    device.Object, which has different (class level) Attributes (and responds to different commands)
    than the other instance_id's.

    """
    max_instance		= 0

    def __init__( self, name, instance_id=None ):
        """Create the instance (default to the next available instance_id).  An instance_id of 0 holds
        the "class" attributes/commands.

        """
        self.name		= name

        # Allocate and/or keep track of maximum instance ID assigned thus far.
        if instance_id is None:
            instance_id		= self.__class__.max_instance + 1
        if instance_id > self.__class__.max_instance:
            self.__class__.max_instance = instance_id
        self.instance_id	= instance_id

        log.normal( "%s, Instance ID %d created", self, instance_id )

        instance		= lookup( self.class_id, instance_id )
        assert instance is None, \
            "CIP Object class %x, instance %x already exists" % ( self.class_id, self.instance_id )

        # 
        # directory.1.2.None 	== self
        # self.attribute 	== directory.1.2 (a dotdict), for direct access of our attributes
        # 
        self.attribute		= directory.setdefault( str( self.class_id )+'.'+str( instance_id ),
                                                        cpppo.dotdict() )
        self.attribute['None']	= self

        # Check that the class-level instance (0) has been created; if not, we'll create one using
        # the default parameters.  If this isn't appropriate, then the user should create it using
        # the appropriate parameters.
        if lookup( self.class_id, 0 ) is None:
            self.__class__( 'meta-'+name, 0 )

        if instance_id == 0:
            # Set up the default Class-level values.
            self.attribute['1']= Attribute( 	'Revision', 		UINT, default=0 )
            self.attribute['2']= MaxInstance( 'Max Instance',		UINT,
                                                class_id=self.class_id )
            self.attribute['3']= NumInstances( 'Num Instances',	UINT,
                                                class_id=self.class_id )
            # A UINT array; 1st UINT is size (default 0)
            self.attribute['4']= Attribute( 	'Optional Attributes',	UINT, default=0 )
            

    def __str__( self ):
        return self.name
    __repr__ 			= __str__

    @property
    def path( self ):
        return self._path( self.class_id, self.instance_id )

    def request( self, data ):
        """Process a request.  Must be a dotdict data artifact such as is produced by the Object's parser.
        For example, a request data containing either of the following:

            {
                'service':		0x01,
                'get_attribute_all':	True,
            }

        should run the Get Attribute All service, and return the binary payload that results from
        the command.  This may include any erroneous status codes that result from errors detected
        during the attempt to process the command.

        This is hacky, and we don't validate any request.

        """
        result			= b''
        if 'get_attribute_all' in data or data.service == 0x01:
            a_id		= 1
            while str(a_id) in self.attribute:
                result	       += self.attribute[str(a_id)].produce()
                a_id	       += 1
                
            return result

        assert False, "%s (Class %x, Instance %x): Unknown service request: %s" % (
            self.class_id, self.instance_id, data )


class Identity( Object ):
    class_id			= 0x01

    def __init__( self, name, instance_id=None ):
        super( Identity, self ).__init__( name=name, instance_id=instance_id )

        if instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes (these example defaults are from a Rockwell Logix PLC)
            self.attribute['1']	= Attribute( 'Vendor Number', 		UINT, default=0x0001 )
            self.attribute['2']	= Attribute( 'Device Type', 		UINT, default=0x000e )
            self.attribute['3']	= Attribute( 'Product Code Number',	UINT, default=0x0036 )
            self.attribute['4']	= Attribute( 'Product Revision', 	UINT, default=0x0b14 )
            self.attribute['5']	= Attribute( 'Status Word', 		UINT, default=0x3160 )
            self.attribute['6']	= Attribute( 'Serial Number', 		UDINT,default=0x006c061a )
            self.attribute['7']	= Attribute( 'Product Name', 		SSTRING, default='1756-L61/B LOGIX5561' )

        

class Connection_Manager( Object ):
    class_id			= 0x06

    def __init__( self, name, vendor_number=None,   ):
        super( Connection_Manager, self ).__init__( name=name, instance_id=instance_id )

        if instance_id == 0:
            # Extra Class-level Attributes
            pass
        else:
            # Instance Attributes
            pass

        
