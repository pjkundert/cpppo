"""Example of pipelined access to EtherNet/IP CIP Tags on remote Controller.  Assuming you have a
Controller at hostname 'controller', containing the tags "Volume" and "Temperature", test its base
synchronous thruput using:

        $ python -m cpppo.server.enip.thruput -a controller "Volume" "Temperature"

    To start a simulated Controller hosting two tags, run this on a remote Linux host:

        $ pip install cpppo
        $ python -m cpppo.server.enip --print -v Volume=REAL Temperature=REAL

Adjust --depth to allow many requests in-flight, and --multiple for more operation per request, and
observe its effect on thruput TPS (Transactions Per Second).

"""
from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import argparse

import cpppo
from   cpppo.history import timestamp
from   cpppo.server.enip import client

if __name__ == "__main__":
    ap				= argparse.ArgumentParser()
    ap.add_argument( '-d', '--depth',    default=0, help="Pipelining depth" )
    ap.add_argument( '-m', '--multiple', default=0, help="Multiple Service Packet size limit" )
    ap.add_argument( '-r', '--repeat',   default=1, help="Repeat requests this many times" )
    ap.add_argument( '-a', '--address',  default='localhost', help="Hostname of target Controller" )
    ap.add_argument( '-t', '--timeout',  default=None, help="I/O timeout seconds (default: None)" )
    ap.add_argument( 'tags', nargs='+', help="Tags to read/write" )
    args			= ap.parse_args()

    depth			= int( args.depth )
    multiple			= int( args.multiple )
    repeat			= int( args.repeat )
    operations			= client.parse_operations( args.tags * repeat )
    timeout			= None
    if args.timeout is not None:
        timeout			= float( args.timeout )

    with client.connector( host=args.address, timeout=timeout ) as conn:
        start			= cpppo.timer()
        num,idx			= -1,-1
        for num,(idx,dsc,op,rpy,sts,val) in enumerate( conn.pipeline(
                operations=operations, depth=depth,
                multiple=multiple, timeout=timeout )):
            print( "%s: %3d: %s" % ( timestamp(), idx, val ))
    
        elapsed			= cpppo.timer() - start
        print( "%3d operations using %3d requests in %7.2fs at pipeline depth %2s; %5.1f TPS" % (
            num+1, idx+1, elapsed, args.depth, num / elapsed ))
