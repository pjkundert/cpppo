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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ['attribute_operations', 'main']

"""Get Attributes (Single/All) from a target EtherNet/IP CIP device.

    $ # Get Attribute Single from Class 2, Instance 1, Attribute 1
    $ python -m cpppo.server.enip.getattr -a controller '@2/1/1'
    $ # Get Attributes All from Class 2, Instance 1
    $ python -m cpppo.server.enip.getattr -a controller '@2/1'

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
import itertools
import json
import logging
import sys
import time

import cpppo
from .. import enip
from . import client


def attribute_operations( paths, **kwds ):
    """Replace any tag/attribute-level operations with Get Attribute Single, otherwise Get Attributes
    All.  This is probably beyond "compability" with *Logix or other CIP devices, as they only allow
    Read/Write Tag [Fragmented] services to use Tags (Get/Set Attribute Single services require
    numeric Class, Instance, Attribute addressing).  

    """
    for op in client.parse_operations( paths, **kwds ):
        path_end		=  op['path'][-1]
        if 'attribute' in path_end or 'symbolic' in path_end:
            op['method'] = 'get_attribute_single'
        else:
            op['method'] = 'get_attributes_all'
        yield op


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
    route_path			= json.loads( args.route_path ) if args.route_path else None # may be None/0/False
    send_path			= args.send_path

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
            print( "%s: %3d: %s == %s" % ( time.ctime(), idx, dsc, val ))
            failures	       += 1 if sts else 0
        elapsed			= cpppo.timer() - start
        logging.normal( "%3d requests in %7.3fs at pipeline depth %2s; %7.3f TPS" % (
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
