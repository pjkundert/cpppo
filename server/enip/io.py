
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
enip.io		-- basic EtherNet/IP client I/O operation API and module entry point
"""


import argparse
import logging
import sys

import cpppo
from cpppo.server import enip
from cpppo.server.enip import client

# 
# A very simple example of client I/O to an EtherNet/IP CIP Controller 
# 
# Describe one or more Tag I/O operations on the command line, and the results
# are printed on separate lines.
# 
def batch( operations, host, port=enip.address[1], printing=False, depth=1, multiple=0, timeout=None ):
    """Issue a bunch of requests in 'operations', returning a list of the results:
    None	-- Request failure
    True	-- Request successful write (no resultant data)
    [...]	-- Request successful read
    """
    conn			= client.connector( host=host, port=port )
    return [ val
             for idx,dsc,req,rpy,sts,val in conn.validate(
                     harvested=conn.pipeline(
                         operations, depth=depth, multiple=multiple, timeout=timeout ),
                     printing=printing )]


if __name__ == "__main__":
    ap				= argparse.ArgumentParser(
        description = "An EtherNet/IP Client simple example",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """\
A single EtherNet/IP CIP Tags may be read or written.  The full format for
specifying a tag and an operation is:

    Tag[<first>-<last>]+<offset>=(SINT|INT|DINT|REAL)<value>,<value>

All components except Tag are optional.  Specifying a +<offset> (in bytes)
forces the use of the Fragmented command, regardless of whether --[no-]fragment
was specified.  If an element range [<first>] or [<first>-<last>] was specified
and --no-fragment selected, then the exact correct number of elements must be
provided.""" )

    ap.add_argument( '-v', '--verbose',
                     default=0, action="count",
                     help="Display logging information." )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP interface[:port] to connect to (default: %s:%d)" % (
                         enip.address[0], enip.address[1] ))
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )
    ap.add_argument( '-m', '--multiple', action='store_true',
                     help="Use Multiple Service Packet request (default: False)" )
    ap.add_argument( '-d', '--depth', default=1,
                     help="Pipeline requests to this depth (default: 1)" )
    ap.add_argument( 'tags', nargs="+")
    args			= ap.parse_args()

    addr			= args.address.split(':')
    assert 1 <= len( addr ) <= 2, "Invalid --address [<interface>]:[<port>}: %s" % args.address
    addr			= ( str( addr[0] ) if addr[0] else enip.address[0],
                                    int( addr[1] ) if len( addr ) > 1 and addr[1] else enip.address[1] )

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

    # Issue a batch of tag 'operations', printing each result on a line.  For each operation:
    #
    # None	-- Request failure
    # True	-- Request successful write (no resultant data)
    # [...]	-- Request successful read
    
    timeout			= float( args.timeout )
    depth			= int( args.depth )
    multiple			= 500 if args.multiple else 0
    operations			= client.parse_operations( args.tags )
    connection			= client.connector( host=addr[0], port=addr[1], timeout=timeout )
    results			= connection.pipeline(
        operations=operations, depth=depth, multiple=multiple, timeout=timeout )
    failures			= 0
    for idx,dsc,req,rpy,sts,val in results:
        if val is None:
            failures	       += 1
        print( "%r" % ( val ))

    sys.exit( 1 if failures else 0 )

