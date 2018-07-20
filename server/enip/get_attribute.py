#!/usr/bin/env python

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

try:
    from future_builtins import map
except ImportError:
    pass # already available in Python3

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ['attribute_operations', 'proxy', 'proxy_simple', 'main']


"""Get Attributes (Single/All) interface from a target EtherNet/IP CIP device.

    $ # Get Attribute Single from Class 2, Instance 1, Attribute 1
    $ python -m cpppo.server.enip.get_attribute -a controller '@2/1/1'
    $ # Get Attributes All from Class 2, Instance 1
    $ python -m cpppo.server.enip.get_attribute -a controller '@2/1'

Also provides flexible proxy class for a "routing" CIP device (eg. a *Logix controller) or
proxy_simple for a "simple" CIP device (eg. a simple EtherNet/IP CIP device such as an AB
MicroLogix, or a sensor or actuator such as the AB PowerFlex AC Drive):

mysensors.py:

    from cpppo.server.enip.get_attribute import proxy_simple

    class some_sensor( proxy_simple ):
        '''A simple (non-routing) CIP device with one parameter named: 'A Sensor Parameter' '''
        PARAMETERS		= dict( proxy_simple.PARAMETERS,
            a_sensor_parameter	= proxy_simple.parameter( '@0x93/1/10',	'REAL',	'Hz' ),
        )


Object class identifiers are divided into two types of open objects: publicly defined (ranging from
0x00 - 0x63 and 0x00F0 - 0x02FF) and vendor-specific objects (ranging from 0x64 - 0xC7 and 0x0300 -
0x04FF). All other class identifiers are reserved for future use. In some cases, e.g., within the
assembly object class, instance identifiers are divided into two types of open instances: publicly
defined (ranging from 0x01 - 0x63 and 0x0100 - 0x02FF) and vendor-specific (ranging from 0x64 - 0xC7
and 0x0300 - 0x04FF). All other instance identifiers are reserved for future use. Attribute
identifiers are divided into two types of open attributes: publicly defined (ranging from 0x00 -
0x63) and vendor-specific (ranging from 0x64 - 0xC7). All other attribute identifiers are reserved
for future use. While vendor-specific objects can be created with a great deal of flexibility, these
objects must adhere to certain rules specified for CIP, e.g., they can use whatever instance and
attribute IDs the developer wishes, but their class attributes must follow guidelines detailed in
the CIP Volume section of each network specification.

"""

import argparse
import collections
import contextlib
import functools
import itertools
import json
import logging
import sys
import threading
import time
import traceback

import cpppo
from .. import enip
from . import client

log				= logging.getLogger( "enip.get" )

def attribute_operations( paths, int_type=None, **kwds ):
    """Replace any tag/attribute-level operations with Get Attribute Single, otherwise Get Attributes
    All.  This is probably beyond "compability" with *Logix or other CIP devices, as they only allow
    Read/Write Tag [Fragmented] services to use Tags (Get/Set Attribute Single services require
    numeric Class, Instance, Attribute addressing); in real CIP devices, only CIP Class, Instance
    and Attribute EPATH elements are generally allowed.

    Does not check if elements == len( data ), or for presence of offset, etc.  Only conversion of
    simple read or write operations would generally be valid.

    If no 'int_type' entry is specified, then we will assume that 'SINT' is intended (we accept an
    enhanced range of values, up to the "unsigned" limit of the same sized integral value container.)

    """
    for op in client.parse_operations( paths, int_type=int_type or 'SINT', **kwds ):
        path_end		= op['path'][-1]
        if 'instance' in path_end:
            op['method'] = 'get_attributes_all'
            assert 'data' not in op, "All Attributes cannot be operated on using Set Attribute services"
        elif 'symbolic' in path_end or 'attribute' in path_end or 'element':
            op['method'] = 'set_attribute_single' if 'data' in op else 'get_attribute_single'
        else:
            raise AssertionError( "Path invalid for Attribute services: %r", op['path'] )
        yield op


# 
# get_attribute.is_...
# 
#     Methods for identifying certain types of Python objects
# 
def is_iterator( thing ):
    """Detects if 'thing' is already an iterator/generator."""
    return hasattr( thing, '__next__' if sys.version_info[0] < 3 else 'next' )


def is_listlike( thing ):
    """Something like a list or tuple; indexable, but not a string or a class (some may have
    __getitem__, eg. cpppo.state, based on a dict).

    """
    return not isinstance( thing, (cpppo.type_str_base,type) ) and hasattr( thing, '__getitem__' )

# 
# get_attribute.proxy		-- for devices that can "route" CIP requests
# get_attribute.proxy_simple	-- for simple end-devices (eg. sensors, actuators)
# 
#     Access an EtherNet/IP CIP device using either generic Get Attribute{s All, Single}, or *Logix
# Read Tag [Fragmented] services, as desired.  Data is delivered converted to target format.
# 
class proxy( object ):
    """Monitor/control an EtherNet/IP CIP device, using either Get Attribute Single/All or Read Tag
    [Fragmented] services.  The EtherNet/IP CIP gateway is discarded and re-opened on any Exception;
    it is created as required; if accessing the EtherNet/IP CIP device via this interface results in
    an Exception, the caller must signal the enip_proxy to discard the connection, by invoking the
    .close_gateway method.

    The simplest way to ensure that the proxy's gateway is correctly closed, is to use its "context" API, which
    ensures via's gateway is opened, and that .close_gateway is invoked on Exception:
    
        via = proxy( 'hostname' )

        with via:
            vendor,product_name = via.read( [('@1/1/1','INT'), ('@1/1/7','SSTRING)] )

        # via is now ready for future I/O, even if last I/O raised Exception


    Provides general "Unconnected" read/write access to CIP attributes, using either *Logix
    "Read/Write Tag [Fragmented]" service requests, or (if a type is specified), then uses the more
    basic "Get/Set Attribute Single" service requests.

    If the target EtherNet/IP CIP device that is capable of "routing" requests to other devices
    (eg. a *Logix Controller), then the default configuration should be usable.  However, for simple
    devices that are not capable of routing CIP requests to other devices, the use of the
    "Unconnected Request" service must be avoided;

    NOTE

    Iterators which satisfy the requirements of read/write may be supplied; otherwise, 'read' will
    attempt to iterate the supplied (list-like or string) value, and 'write' will attempt to invoke the
    '.items' method on its supplied (dict-like) value.

    The reason read/write accept iterators instead of simply performing an I/O operation for each
    call, is because the underlying EtherNet/IP CIP protocol is capable of both pipe-lining (having
    multiple requests in-flight before receiving earlier responses), *and* can package multiple
    requests into a single Multiple Service Packet request.  In order to do that, the underlying
    cpppo.server.enip.client APIs require an iterable sequence of operations to perform.

    """
    CIP_TYPES			= {
        "real":		( enip.REAL,	"REAL" ),		# <name>: (<class>, <data-path> )
        "sint":		( enip.SINT,	"SINT" ),
        "usint":	( enip.USINT,	"USINT" ),
        "int":		( enip.INT,	"INT" ),
        "uint":		( enip.UINT,	"UINT" ),
        "dint":		( enip.DINT,	"DINT" ),
        "udint":	( enip.UDINT,	"UDINT" ),
        "bool":		( enip.BOOL,	"BOOL" ),
        "word":		( enip.WORD,	"WORD" ),
        "dword":	( enip.DWORD,	"DWORD" ),
        "ipaddr":	( enip.IPADDR,	"IPADDR" ),		# a network-order UDINT as a dotted-quad
        "string":	( enip.STRING,	"STRING.string" ),
        "sstring":	( enip.SSTRING,	"SSTRING.string" ),
        "epath":	( enip.EPATH_padded, "EPATH_padded.segment" ), # Supports padded EPATH: <words> 0x00 <EPATH> [<pad>]
    }

    # 
    # parameter		-- An attribute address, its underlying type(s) and units
    # PARAMETERS	-- Transformations from parameter "bare name" ==> parameter( attribute, types, units )
    # parameter_substitution -- perform parameter name to ( attribute, types, units ) transformations
    # 
    # In order to access any defined PARAMETERS, pass
    # 
    parameter			= collections.namedtuple(
        'parameter', [
            'attribute',	# eg. "@0x93/3/10"
            'types',		# eg. "REAL" or ("UINT",...,"SSTRING")
            'units',		# eg. "Hz" or None
        ] )

    PARAMETERS			= dict( # { 'Parameter Name': parameter(...), }
        product_name	= parameter( "@1/1/7", "SSTRING", None ),
        identity	= parameter( "@1/1",	[
            "INT", "INT", "INT", "INT", "INT", "DINT", "SSTRING", "USINT"
        ], "Identity" ),
        tcpip		= parameter( "@0xF5/1",	[
            "DWORD", "DWORD", "DWORD", "EPATH",
            "IPADDR", "IPADDR", "IPADDR", "IPADDR", "IPADDR", "STRING",
            "STRING"
        ], "TCPIP" )
    )

    def parameter_substitution( self, iterable, parameters=None, pass_thru=None ):
        """Lookup bare names in the given parameters dict (or self.PARAMETERS, if None); pass
        everything else (eg. tuples of CIP (<attribute>, <cip_type>, <units>)) thru unchanged (if
        pass_thru==True).

        If the iterable consists of a single bare name, it will be converted to a single-entry list
        before processing.
    
        Transforms bare names by stripping surrounding whitespace, lowering case, and substituting
        intervening whitespace with underscores, eg.

        ' Output Freq ' --> parameters['output_freq']
    
        Default to use the class' PARAMETERS, and default pass_thru to True.

        """
        if isinstance( iterable, cpppo.type_str_base ):
            iterable		= [ iterable ]
        if parameters is None:
            parameters		= self.PARAMETERS
        if pass_thru is None:
            pass_thru		= True
        for tag in iterable:
            if isinstance( tag, cpppo.type_str_base ):
                # Capture any ... = <value>, to pass w/ substitued attribute address
                val		= tag.split( '=', 1 )[1] if '=' in tag else None
                prm 		= tag.split( '=', 1 )[0].strip().lower().replace( ' ', '_' )
                if prm in parameters:
                    att,typ,uni	= parameters[prm]
                    if val is not None:
                        att    += '=' + val		# restore written value
                    log.info( "Parameter %r (%s) --> %r", tag, uni, (att,typ) )
                    tag		= att,typ
                else:
                    # Don't allow plain text Tags; must be named parameters!
                    assert pass_thru, "Unrecognized parameter name: %r" % ( tag )
            yield tag
    
    def __init__( self, host, port=44818, timeout=None, depth=None, multiple=None,
                  gateway_class=client.connector, route_path=None, send_path=None,
                  identity_default=None, **gateway_kwds ):
        """Capture the desired I/O parameters for the target CIP Device.

        By default, the CIP Device will be identified using a List Identity request each time a CIP
        session is registered; provide a identity_default containing (at least) an attribute
        product_name == 'Some Product Name', to avoid this initial List Identity request
        (self.identity it will still be updated if .list_identity is invoked successfully).

        """
        self.host		= host
        self.port		= port
        self.timeout		= 5 if timeout is None else timeout
        self.depth		= 2 if depth is None else depth
        self.multiple		= 0 if multiple is None else multiple
        self.route_path		= route_path
        self.send_path		= send_path
        self.gateway_kwds	= gateway_kwds	# Any additional args to gateway
        self.gateway_class	= gateway_class
        self.gateway		= None
        self.gateway_lock	= threading.Lock()
        if isinstance( identity_default, cpppo.type_str_base ):
            identity_default	= cpppo.dotdict( product_name = identity_default )
        assert not identity_default or hasattr( identity_default, 'product_name' )
        self.identity_default	= identity_default
        self.identity		= identity_default

    def __str__( self ):
        return "%s at %s" % ( self.identity.product_name if self.identity else None, self.gateway )

    def __enter__( self ):
        """Ensures that the gateway is open."""
        self.open_gateway()
        return self

    def __exit__( self, typ, val, tbk ):
        """If an Exception occurs, ensures that the gateway is closed."""
        if typ is not None:
            self.close_gateway()
        return False

    def close_gateway( self, exc=None ):
        """Discard gateway; also forces re-reading of identity value upon next gateway connection"""
        if self.gateway is not None:
            self.gateway.close()
            ( log.warning if exc else log.normal )(
                "Closed EtherNet/IP CIP gateway %s due to: %s%s",
                self.gateway, exc or "(unknown)",
                "" if log.getEffectiveLevel() > logging.INFO
                else ''.join( traceback.format_exc() ))
            self.gateway	= None
            self.identity	= self.identity_default

    def open_gateway( self ):
        """Ensure that the gateway is open, in a Thread-safe fashion.  First Thread in creates the
        gateway_class instance and registers a session, and (if necessary) queries the identity of the
        device -- all under the protection of the gateway_lock Mutex."""
        with self.gateway_lock:
            if self.gateway is None:
                self.gateway = self.gateway_class(
                    host=self.host, port=self.port, timeout=self.timeout, **self.gateway_kwds )
                if not self.identity:
                    try:
                        rsp,ela = self.list_identity_details()
                        if rsp and rsp.enip.status == 0:
                            self.identity = rsp.enip.CIP.list_identity.CPF.item[0].identity_object
                    except Exception as exc:
                        self.close_gateway( exc )
                        raise
                log.normal( "Opened EtherNet/IP CIP gateway %s", self )

    def maintain_gateway( function ):
        """A decorator to open the gateway (if necessary), and discard it on any Exception.  Atomically
        instantiates self.gateway, attempting to perform a List Identity and update self.identity.

        This implementation is somewhat subtle, as there is no safe way to schedule the I/O required
        to satisfy the self.identity -- it must be done immediately upon establishment of the
        gateway, in the same Thread that opens the gateway.

        After this, multiple Threads may attempt to perform I/O, and each Thread will retain
        exclusive access via the self.gateway.frame.lock threading.Lock mutex, blocking other
        threads from beginning their I/O 'til the current thread is done harvesting all of its
        responses.

        """
        @functools.wraps( function )
        def wrapper( inst, *args, **kwds ):
            with inst:
                return function( inst, *args, **kwds )
        return wrapper

    @maintain_gateway
    def list_identity( self ):
        """List Identity for target device.  Synchronous (waits for and returns response value).  Updates
        self.identity w/ latest value returned.

        """
        rsp,ela			= self.list_identity_details()
        assert rsp.enip.status == 0, \
            "List Identity responded with EtherNet/IP error status: %r" % (
                rsp.enip.status )
        self.identity		= rsp.enip.CIP.list_identity.CPF.item[0].identity_object
        log.normal( "Device Identity: %r", self.identity )
        return self.identity

    def list_identity_details( self ):
        """For simplicity, we'll assume that the send is instantaneous (correct, for all but the most
        extreme TCP/IP output buffer conditions).  An Exception raised indicates that self.gateway
        is no longer valid (unparsable response, or a delayed response may be in transit), and
        .close_gateway must be invoked.  Returns the full response, and the elapsed time.

        """
        with self.gateway as connection: # waits 'til any Thread's txn. completes
            connection.list_identity( timeout=self.timeout )
            rsp,ela		= client.await_( connection, timeout=self.timeout )
            assert rsp, \
                "No response to List Identity within timeout: %r" % ( self.timeout )
            return rsp,ela

    @staticmethod
    def is_request( req ):
        """Return True iff the given item is potentially a read/write request target:
        
            <address>		-- "Tag|@<Class>/<Instance>/<Attribute>"
            ( <address>, <CIP-type> [, <units> ] )
            ( <address>, "CIP-type-name" [, <units> ] )
            ( <address>, (<CIP-type>, <CIP-type>, ...) [, <units> ])

        No validation of the provided <units> is done; it is passed thru unchanged.
        """
        log.detail( "Validating request: %r", req )
        if isinstance( req, cpppo.type_str_base ):
            return True
        if is_listlike( req ) and 2 <= len( req ) <= 3:
            try:
                add,typ,_	= req
            except ValueError:
                add,typ		= req
            if isinstance( add, cpppo.type_str_base ):
                if isinstance( typ, (cpppo.type_str_base, type) ):
                    return True
                if is_listlike( typ ):
                    if all( isinstance( t, (cpppo.type_str_base, type) ) for t in typ ):
                        return True
        return False

    @maintain_gateway
    def read( self, attributes, printing=False, checking=False ):
        """Yields all values, raising Exception at end if any failed.  This is the main external API;
        maintains self.gateway before operating.

        Note that an unsuccessful read of an attribute will successfully return the value None,
        which is Falsey!  All other valid, successful responses will return an array with 1 or more
        values, which is Truthy. Since there is no other way to get a Falsey response, each yielded
        result can simply be tested for Truthyness to determine if it is valid.

        If 'checking' is True, an Exception is raised if any erroneous reply status is detected,
        even if all operations completed without raising Exception.  This will (unnecessarily) close
        the gateway, causing a delay on the next I/O attempt.  However, it allows the use of the
        proxy without worrying about whether or not the surrounding code correctly catches
        Exceptions and invokes .close_gateway.  If efficiency is paramount, it is better to
        individually check the results for Truthyness, to determine which (if any) failed, and to
        ensure that Exceptions are caught, or the context manager is used to ensure .close_gateway
        is invoked.

        """
        bad			= []
        with contextlib.closing( self.read_details( attributes )) as reader:
            # PyPy compatibility; avoid deferred destruction of generators
            for val,(sts,(att,typ,uni)) in reader:
                if printing:
                    # eg.   Output Current == 16.8275 Amps
                    print( "%16s == %s %s" % (
                        att, val if val in (None,True) else ', '.join( map( str, val )), uni or '' ))
                yield val
                if sts not in (0,6):
                    bad.append( "%s: status %r" % ( att, sts ))

        if checking:
            assert len( bad ) == 0, \
                "read failed to access %d attributes: %s" % ( len( bad ), ', '.join( bad ))

    def read_details( self, attributes ):
        """Assumes that self.gateway has been established; does not close_gateway on Exception.  If you
        use this interface, ensure that you maintain the gateway (eg. ):

            via = proxy( 'hostname' )
            with via:
                for val,(sts,(att,typ,uni) in via.read_details( [...] ):

        Read the specified CIP Tags/Attributes in the string or iterable 'attributes', using Read
        Tag [Fragmented] (returning the native type), or Get Attribute Single/All (converting it to
        the specified EtherNet/IP CIP type(s)).

        The reason iterables are used and a generator returned, is to allow the underlying
        cpppo.server.enip.client connector to aggregate multiple CIP operations using Multiple
        Service Packet requests and/or "pipeline" multiple requests in-flight, while receiving the
        results of earlier requests.

        The 'attributes' must be either a simple string Tag name (no Type, implying the use of
        *Logix Read Tag [Fragmented] service), eg:

            "Tag"

        or an iterable containing 2 or 3 values; a Tag/address, a type/types (may be None, to force
        Tag I/O), and an optional description (eg. Units)

            [
                "Tag",
                ( "Tag", None, "kWh" ),
                ( "@1/1/1", "INT" )
                ( "@1/1/1", "INT", "Hz" )
                ( "@1/1", ( "INT", "INT", "INT", "INT", "INT", "DINT", "SSTRING", "USINT" ))
                ( "@1/1", ( "INT", "INT", "INT", "INT", "INT", "DINT", "SSTRING", "USINT" ), "Identity" )
            ]

        Produces a generator yielding the corresponding sequence of results and details for the
        supplied 'attributes' iterable.  Each individual request may succeed or fail with a non-zero
        status code (remember: status code 0x06 indicates successful return of a partial result).

        Upon successful I/O, a tuple containing the result value and details about the result (a
        status, and the attribute's details (address, type, and units)) corresponding to each of the
        supplied 'attributes' elements is yielded as a sequence.  Each result value is always a list
        of values, or None if the request failed:

            (
                ([0],(0, ("Tag", enip.INT, None))),
                ([1.23],(0, "Tag", enip.REAL, "kWh"))),
                ([1], (0, ("@1/1/1", enip.INT, None))),
                ([1], (0, ("@1/1/1", enip.INT, "Hz"))),
                ([1, 2, 3, 4, 5 6, "Something", 255],
                    (0, ("@1/1", [
                        enip.INT, enip.INT, enip.INT,  enip.INT,
                        enip.INT, enip.DINT, enip.STRING, enip.USINT ], None ))),
                ([1, 2, 3, 4, 5 6, "Something", 255],
                    (0, ("@1/1", [
                        enip.INT, enip.INT, enip.INT,  enip.INT,
                        enip.INT, enip.DINT, enip.STRING, enip.USINT ], "Identity" ))),
            )

        The read_details API raises exception on failure to parse request, or result data type
        conversion problem.  The simple 'read' API also raises an Exception on attribute access
        error, the return of failure status code.  Not all of these strictly necessitate a closure
        of the EtherNet/IP CIP connection, but should be sufficiently rare (once configured) that
        they all must signal closure of the connection gateway (which is re-established on the next
        call for I/O).

        EXAMPLES

            proxy		= enip_proxy( '10.0.1.2' )
            try:
                with contextlib.closing( proxy.read( [ ("@1/1/7", "SSTRING") ] )) as reader: # CIP Device Name
                    value	= next( reader )
            except Exception as exc:
                proxy.close_gateway( exc )

            # If CPython (w/ reference counting) is your only target, you can use the simpler:
            proxy		= enip_proxy( '10.0.1.2' )
            try:
                value,		= proxy.read( [ ("@1/1/7", "SSTRING") ] ) # CIP Device Name
            except Exception as exc:
                proxy.close_gateway( exc )

        """
        if isinstance( attributes, cpppo.type_str_base ):
            attributes		= [ attributes ]

        def opp__att_typ_uni( i ):
            """Generate sequence containing the enip.client operation, and the original attribute
            specified, its type(s) (if any), and any description.  Augment produced operation with
            data type (if known), to allow estimation of reply sizes (and hence, Multiple Service
            Packet use); requires cpppo>=3.8.1.

            Yields: (opp,(att,typ,dsc))

            """
            for a in i:
                assert self.is_request( a ), \
                    "Not a valid read/write target: %r" % ( a, )
                try:
                    # The attribute description is either a plain Tag, an (address, type), or an
                    # (address, type, description)
                    if is_listlike( a ):
                        att,typ,uni = a if len( a ) == 3 else a+(None,)
                    else:
                        att,typ,uni = a,None,None
                    # No conversion of data type if None; use a Read Tag [Fragmented]; works only
                    # for [S]STRING/SINT/INT/DINT/REAL/BOOL.  Otherwise, conversion of data type
                    # desired; get raw data using Get Attribute Single.
                    parser	= client.parse_operations if typ is None else attribute_operations
                    opp,	= parser( ( att, ), route_path=self.route_path, send_path=self.send_path )
                except Exception as exc:
                    log.warning( "Failed to parse attribute %r; %s", att, exc )
                    raise
                # For read_tag.../get_attribute..., tag_type is never required; but, it is used (if
                # provided) to estimate data sizes for Multiple Service Packets.  For
                # write_tag.../set_attribute..., the data has specified its data type, if not the
                # default (INT for write_tag, SINT for set_attribute).
                if typ is not None and not is_listlike( typ ) and 'tag_type' not in opp:
                    t		= typ
                    if isinstance( typ, cpppo.type_str_base ):
                        td	= self.CIP_TYPES.get( t.strip().lower() )
                        if td is not None:
                            t,d	= td
                    if hasattr( t, 'tag_type' ):
                        opp['tag_type'] = t.tag_type

                log.detail( "Parsed attribute %r (type %r) into operation: %r", att, typ, opp )
                yield opp,(att,typ,uni)

        def types_decode( types ):
            """Produce a sequence of type class,data-path, eg. (enip.REAL,"SSTRING.string").  If a
            user-supplied type (or None) is provided, data-path is None, and the type is passed.

            """
            for t in typ if is_listlike( typ ) else [ typ ]:
                d		= None 		# No data-path, if user-supplied type
                if isinstance( t, cpppo.type_str_base ):
                    td		= self.CIP_TYPES.get( t.strip().lower() )
                    assert td, "Invalid EtherNet/IP CIP type name %r specified" % ( t, )
                    t,d		= td
                assert type( t ) in (type,type(None)), \
                    "Expected None or CIP type class, not %r" % ( t, )
                yield t,d

        # Get duplicate streams; one to feed the the enip.client's connector.operate, and one for
        # post-processing based on the declared type(s).
        operations,attrtypes	= itertools.tee( opp__att_typ_uni( attributes ))

        # Process all requests w/ the specified pipeline depth, Multiple Service Packet
        # configuration.  The 'idx' is the EtherNet/IP CIP request packet index; 'i' is the
        # individual I/O request index (for indexing att/typ/operations).
        # 
        # This Thread may block here attempting to gain exclusive access to the cpppo.dfa used
        # by the cpppo.server.enip.client connector.  This uses a threading.Lock, which will raise
        # an exception on recursive use, but block appropriately on multi-Thread contention.
        # 
        # assert not self.gateway.frame.lock.locked(), \
        #     "Attempting recursive read on %r" % ( self.gateway.frame, )
        log.info( "Acquiring gateway connection: %s",
                      "locked" if self.gateway.frame.lock.locked() else "available" )
        with self.gateway as connection: # waits 'til any Thread's txn. completes
            for i,(idx,dsc,req,rpy,sts,val) in enumerate( connection.operate(
                    ( opr for opr,_ in operations ),
                    depth=self.depth, multiple=self.multiple, timeout=self.timeout )):
                log.detail( "%3d (pkt %3d) %16s %-12s: %r ", 
                                i, idx, dsc, sts or "OK", val )
                opr,(att,typ,uni) = next( attrtypes )
                if typ is None or sts not in (0,6) or val in (True,None):
                    # No type conversion; just return whatever type produced by Read Tag.  Also, if
                    # failure status (OK if no error, or if just not all data could be returned), we
                    # can't do any more with this value...  Also, if actually a Write Tag or Set
                    # Attribute ..., then val True/None indicates success/failure (no data returned).
                    yield val,(sts,(att,typ,uni))
                    continue

                # Parse the raw data using the type (or list of types) desired.  If one type, then
                # all data will be parsed using it.  If a list, then the data will be sequentially
                # parsed using each type.  Finally, the target data will be extracted from each
                # parsed item, and added to the result.  For example, for the parsed SSTRING
                # 
                #     data = { "SSTRING": {"length": 3, "string": "abc"}}
                # 
                # we just want to return data['SSTRING.string'] == "abc"; each recognized CIP type
                # has a data path which we'll use to extract just the result data.  If a
                # user-defined type is supplied, of course we'll just return the full result.
                source		= cpppo.peekable( bytes( bytearray( val ))) # Python2/3 compat.
                res		= []
                typ_is_list	= is_listlike( typ )
                typ_dat		= list( types_decode( typ if typ_is_list else [typ] ))
                for t,d in typ_dat:
                    with t() as machine:
                        while source.peek() is not None: # More data available; keep parsing.
                            data= cpppo.dotdict()
                            for m,s in machine.run( source=source, data=data ):
                                assert not ( s is None and source.peek() is None ), \
                                    "Data exhausted before completing parsing a %s" % ( t.__name__, )
                            res.append( data[d] if d else data )
                            # If t is the only type, keep processing it 'til out of data...
                            if len( typ_dat ) == 1:
                                continue
                            break
                typ_types	= [t for t,_ in typ_dat] if typ_is_list else typ_dat[0][0]
                yield res,(sts,(att,typ_types,uni))

    # Supply "Tag = <value>" to perform a write.
    write = read

class proxy_simple( proxy ):
    """Monitor/Control a simple non-routing CIP device (eg. an AB MicroLogix, AB PowerFlex AC Drive).

    Defaults to disable route_path and send_path, to avoid generating CIP router-specific
    Unconnected Send encapsulation in CIP SendRRData requests.

    When overriding the default values, avoid changing the API parameter defaults from None;
    instead, test for None and override the value in the body of the __init__ method.  This allows
    us to more reliably supply new values, or retain the default behaviours when creating new
    instances (see poll.py's poll function).

    """
    def __init__( self, host, route_path=None, send_path=None, **kwds ):
        if route_path is None:
            route_path		= False
        if send_path is None:
            send_path		= ''
        super( proxy_simple, self ).__init__(
            host=host, route_path=route_path, send_path=send_path, **kwds )


def main( argv=None ):
    """Get Attribute(s) Single/All the specified Instance or Attribute level address(es)

    """
    ap				= argparse.ArgumentParser(
        description = "An EtherNet/IP Get Attribute Single/All and Set Attribute Single client",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """\

One or more EtherNet/IP CIP Object/Instance Attributes may be read or
written.  The full format for specifying a tag and an operation is:

    @<Object>/<Instance>/<Attribute>[=<value>,<value>...]

The default Send Path is '@6/1', and the default Route Path is [{"link": 0,
"port":1}].  This should work with a device that can route requests to links
(eg. a *Logix Controller), with the Processor is slot 1 of the chassis.  If you
have a simpler device (ie. something that does not route requests, such as an AB
PowerFlex for example), then you may want to specify:

    --send-path='' --route-path=false

to eliminate the *Logix-style Unconnected Send (service 0x52) encapsulation
which is required to carry this Send/Route Path data. """ )

    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to connect to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
    ap.add_argument( '--no-print', action='store_false', dest='print',
                     help="Disable printing of summary of operations to stdout" )
    ap.add_argument( '--print', action='store_true',
                     default=True, # inconsistent default from client.py, for historical reasons
                     help="Printing a summary of operations to stdout (default: True)" )
    ap.add_argument( '-m', '--multiple', action='store_true',
                     help="Use Multiple Service Packet request targeting ~500 bytes (default: False)" )
    ap.add_argument( '-d', '--depth',
                     default=0,
                     help="Pipelining depth" )
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )
    ap.add_argument( '-v', '--verbose', action="count",
                     default=0, 
                     help="Display logging information." )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '--route-path',
                     default=None,
                     help="Route Path, in JSON (default: %r); 0/false to specify no/empty route_path" % (
                         str( json.dumps( client.connector.route_path_default ))))
    ap.add_argument( '--send-path',
                     default=None,
                     help="Send Path to UCMM (default: @6/1); Specify an empty string '' for no Send Path" )
    ap.add_argument( '-S', '--simple', action='store_true',
                     default=False,
                     help="Access a simple (non-routing) EtherNet/IP CIP device (eg. MicroLogix)")
    ap.add_argument( '-P', '--profile', action='store_true',
                     help="Activate profiling (default: False)" )
    ap.add_argument( 'tags', nargs="+",
                     help="Class/Instance[/Attribute] to get (- to read from stdin), eg: @2/1 @2/1/1" )

    args			= ap.parse_args( argv )

    # Set up logging level (-v...) and --log <file>
    levelmap 			= {
        0: logging.WARNING,
        1: logging.NORMAL,
        2: logging.DETAIL,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )
    if args.log:
        cpppo.log_cfg['filename'] = args.log

    logging.basicConfig( **cpppo.log_cfg )

    addr			= args.address.split(':')
    assert 1 <= len( addr ) <= 2, "Invalid --address [<interface>]:[<port>}: %s" % args.address
    addr			= ( str( addr[0] ) if addr[0] else enip.address[0],
                                    int( addr[1] ) if len( addr ) > 1 and addr[1] else enip.address[1] )
    timeout			= float( args.timeout )
    depth			= int( args.depth )
    multiple			= 500 if args.multiple else 0
    route_path			= json.loads( args.route_path ) if args.route_path \
                                  else [] if args.simple else None # may be None/0/False/[]
    send_path			= args.send_path                if args.send_path \
                                  else '' if args.simple else None # uses '@2/1/1' by default

    if '-' in args.tags:
        # Collect tags from sys.stdin 'til EOF, at position of '-' in argument list
        minus			= args.tags.index( '-' )
        tags			= itertools.chain( args.tags[:minus], sys.stdin, args.tags[minus+1:] )
    else:
        tags			= args.tags

    profiler			= None
    if args.profile:
        import cProfile as profile
        import pstats
        import StringIO
        profiler		= profile.Profile()

    failures			= 0
    with client.connector( host=addr[0], port=addr[1], timeout=timeout, profiler=profiler ) as connection:
        idx			= -1
        start			= cpppo.timer()
        operations		= attribute_operations( tags, route_path=route_path, send_path=send_path )
        for idx,dsc,op,rpy,sts,val in connection.pipeline(
                operations=operations, depth=depth, multiple=multiple, timeout=timeout ):
            if args.print:
                print( "%s: %3d: %s == %s" % ( time.ctime(), idx, dsc, val ))
            failures	       += 1 if sts else 0
        elapsed			= cpppo.timer() - start
        log.normal( "%3d requests in %7.3fs at pipeline depth %2s; %7.3f TPS" % (
            idx+1, elapsed, args.depth, (idx+1) / elapsed ))

    if profiler:
        s			= StringIO.StringIO()
        ps			= pstats.Stats( profiler, stream=s )
        for sortby in [ 'cumulative', 'time' ]:
            ps.sort_stats( sortby )
            ps.print_stats( 25 )
        print( s.getvalue() )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit( main() )
