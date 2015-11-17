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

__all__				= ['main']

"""Get Attributes (Single/All) from a target EtherNet/IP CIP device.

    $ # Get Attribute Single from Class 2, Instance 1, Attribute 1
    $ python -m cpppo.server.enip.getattr -a controller '@2/1/1'
    $ # Get Attributes All from Class 2, Instance 1
    $ python -m cpppo.server.enip.getattr -a controller '@2/1'

Object class identifiers are divided into two types of open objects: publicly defined (ranging from
0x00 – 0x63 and 0x00F0 – 0x02FF) and vendor-specific objects (ranging from 0x64 – 0xC7 and 0x0300 –
0x04FF). All other class identifiers are reserved for future use. In some cases, e.g., within the
assembly object class, instance identifiers are divided into two types of open instances: publicly
defined (ranging from 0x01 – 0x63 and 0x0100 – 0x02FF) and vendor-specific (ranging from 0x64 – 0xC7
and 0x0300 – 0x04FF). All other instance identifiers are reserved for future use. Attribute
identifiers are divided into two types of open attributes: publicly defined (ranging from 0x00 –
0x63) and vendor-specific (ranging from 0x64 – 0xC7). All other attribute identifiers are reserved
for future use. While vendor-specific objects can be created with a great deal of flexibility, these
objects must adhere to certain rules specified for CIP, e.g., they can use whatever instance and
attribute IDs the developer wishes, but their class attributes must follow guidelines detailed in
the CIP Volume section of each network specification.

"""

import argparse
import itertools
import logging
import sys

import cpppo
from cpppo.history import timestamp
from cpppo.server import enip
from cpppo.server.enip import client


def main( argv=None ):
    """Get Attriburte(s) Single/All the specified Instance or Attribute level address(es)"""
    ap				= argparse.ArgumentParser()
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to connect to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
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
                     help="""Route Path, in JSON, eg. '[{"link":0,"port":0}]' (default: None)""" )
    ap.add_argument( '--send-path',
                     default=None,
                     help="Send Path to UCMM, eg. '@6/1' (default: None)" )
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
    route_path			= json.loads( args.route_path ) if args.route_path else None
    send_path			= args.send_path

    if '-' in args.tags:
        # Collect tags from sys.stdin 'til EOF, at position of '-' in argument list
        minus			= args.tags.index( '-' )
        tags			= itertools.chain( args.tags[:minus], sys.stdin, args.tags[minus+1:] )
    else:
        tags			= args.tags

    def attribute_operations( paths, **kwds ):
        """Replace any attribute-level operations with Get Attribute Single, otherwise Get Attributes All"""
        for op in client.parse_operations( paths, **kwds ):
            if 'attribute' in op['path'][-1]:
                op['method'] = 'get_attribute_single'
            else:
                op['method'] = 'get_attributes_all'
            yield op

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
                operations=operations, depth=depth, multiple=False, timeout=timeout ):
            print( "%s: %3d: %s == %s" % ( timestamp(), idx, dsc, val ))
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
