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
from __future__ import print_function


import argparse
import itertools
import logging
import sys

import cpppo
from cpppo.history import timestamp
from cpppo.server.enip import client

if __name__ == "__main__":
    ap				= argparse.ArgumentParser()
    ap.add_argument( '-a', '--address',  default='localhost',
                     help="Hostname of target Controller" )
    ap.add_argument( '-d', '--depth',    default=0,
                     help="Pipelining depth" )
    ap.add_argument( '-t', '--timeout',  default=None,
                     help="I/O timeout seconds (default: None)" )
    ap.add_argument( '-v', '--verbose',  default=0, action="count",
                     help="Display logging information." )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( 'tags', nargs="+",
                     help="Class/Instance[/Attribute] to get (- to read from stdin), eg: @2/1 @2/1/1" )
    args			= ap.parse_args()

    depth			= int( args.depth )
    timeout			= None
    if args.timeout is not None:
        timeout			= float( args.timeout )
    if '-' in args.tags:
        # Collect tags from sys.stdin 'til EOF, at position of '-' in argument list
        minus			= args.tags.index( '-' )
        tags			= itertools.chain( args.tags[:minus], sys.stdin, args.tags[minus+1:] )
    else:
        tags			= args.tags

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

    def attribute_operations( paths ):
        for op in client.parse_operations( paths ):
            if 'attribute' in op['path'][-1]:
                op['method'] = 'get_attribute_single'
            else:
                op['method'] = 'get_attributes_all'
            yield op

    with client.connector( host=args.address, timeout=timeout ) as conn:
        idx			= -1
        start			= cpppo.timer()
        for idx,dsc,op,rpy,sts,val in conn.pipeline(
                operations=attribute_operations( tags ), depth=depth,
                multiple=False, timeout=timeout ):
            print( "%s: %3d: %s == %s" % ( timestamp(), idx, dsc, val ))
        elapsed			= cpppo.timer() - start
        logging.normal( "%3d requests in %7.2fs at pipeline depth %2s; %5.1f TPS" % (
            idx+1, elapsed, args.depth, idx / elapsed ))
