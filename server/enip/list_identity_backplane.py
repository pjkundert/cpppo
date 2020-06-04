
"""python -m cpppo.server.enip.list_identity_backplane <network>

Scans any List Identity responders from the network (eg. 192.168.0.0/16) or hostname/address
(eg. 192.168.0.123).  Default is network 0.0.0.0/0, using broadcast address 255.255.255.255.  All
responses received before timeout (default: 1.0 second) expires are interrogated.

As EtherNet/IP CIP devices respond, they are scanned to see if any devices respond with Identity
information, at various backplane addresses.

"""

from __future__ import print_function, division, absolute_import

import argparse
import socket
import ipaddress
import logging
import sys

import cpppo
from cpppo.server import enip
from cpppo.server.enip import client
from cpppo.server.enip.get_attribute import proxy, proxy_simple # Devices w/ a backplane route_path

if sys.version_info[0] >= 3:
    def unicode( s ):
        return str( s )

def main( argv=None, address=None ):
    ap				= argparse.ArgumentParser(
        description = "An EtherNet/IP Network CIP Identity Scanner",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """\
Scans a network or address for CIP devices using the UDP/IP List Identity request, and then
scans each device backplane for installed cards, printing their Identity string and Serial number.
""" )

    # Default is to broadcast to entire network, on default EtherNet/IP CIP port
    # 
    # >>> nw=ipaddress.ip_network(unicode("0.0.0.0/0"))
    # >>> nw
    # IPv4Network(u'0.0.0.0/0')
    # >>> nw.broadcast_address
    # IPv4Address(u'255.255.255.255')
    # >>>
    if address is None:
        address			= ("0.0.0.0/0",enip.address[1])

    ap.add_argument( '-v', '--verbose',
                     default=0, action="count",
                     help="Display logging information." )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % enip.address ),
                     help="EtherNet/IP network or address:port to connect to (default: %s:%d)" % (
                         address[0] or 'localhost', address[1] or 44818 ))
    ap.add_argument( '-t', '--timeout',
                     default=5.0,
                     help="EtherNet/IP timeout (default: 5s)" )

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
    logging.basicConfig( **cpppo.log_cfg )

    # See if an address and/or port was specified.  If no address/network portion, assume broadcast.
    addr			= args.address.split(':')
    assert 1 <= len( addr ) <= 2, \
        "Invalid --address [<interface>|<network>/<bits>][:<port>]: %s" % args.address
    addr			= ( str( addr[0] ) if addr[0] else address[0],
                                    int( addr[1] ) if len( addr ) > 1 and addr[1] else address[1] )
    broadcast			= False
    # Convert network to broadcast address, or resolve IP address
    if '/' in addr[0]:
        # A network; get the dest network broadcast address
        ip			= ipaddress.ip_network( unicode( addr[0] ))
        dest			= str( ip.broadcast_address ),addr[1]
        broadcast		= True
    else:
        # Not a network; must be a dest IP address
        ip			= ipaddress.ip_address( unicode( socket.gethostbyname( addr[0] )))
        dest			= str( ip ),addr[1]
    print( "Scanning %s %s, w/ %s %s:%s" % (
           ', '.join( att[3:] for att in dir( address ) # eg. loopback, private
                      if att.startswith( 'is_' ) and getattr( address, att )),
           addr[0], "broadcast" if broadcast else "address", dest[0], dest[1] ))

    timeout			= float( args.timeout )

    chassis,devices		= search_lan( address=dest, broadcast=broadcast, timeout=timeout )

    return 0 if chassis else 1 # Indicate failure if no CIP chassis


def search_lan( address, broadcast=True, timeout=1.0 ):
    """Discover the number of CIP chassis and backplane devices in the address/network."""
    chassis,devices		= 0,0
    for target in list_identity( address=address, broadcast=broadcast, timeout=timeout ):
        identity_object		= target.enip.CIP.list_identity.CPF.item[0].identity_object
        chassis		       += 1
        print( enip.enip_format( identity_object ))
        print()
        print( "%-32s @ %s:%s" % ( identity_object.product_name,
                                   identity_object.sin_addr, identity_object.sin_port ))
        for route_path,module in scan_backplane(
                address=(identity_object.sin_addr,identity_object.sin_port)):
            print( "  %24s: %s" % ( route_path, module ))
            if route_path:
                print( "  Slot %3s: %-32s (Ser. #%s)" % (
                        route_path[0]['link'], str( module[6] ), module[5] ))
            else:
                # No route_path; Must be a simple non-routing device (eg. MicroLogix)
                print( "          : %-32s (Ser. #%s)" % (
                        str( module[6] ), module[5] ))

            devices	       += 1
    return chassis,devices


def list_identity( address=('255.255.255.255',enip.address[1]), broadcast=True, timeout=1.0, udp=True ):
    """Yields a sequence of 0 or more List Identity responses from the target IP or Broadcast
    (address,port) address.  Defaults to UDP/IP.

    """
    with client.client( host=address[0], port=address[1], broadcast=broadcast, udp=udp ) as conn:
        begin			= cpppo.timer()
        conn.list_identity( timeout=timeout )
        while True:
            used		= cpppo.timer() - begin
            response,elapsed	= client.await_response( conn, timeout=max( 0, timeout - used ))
            if not response:
                break # No response (None) w'in timeout or EOF ({})
            yield response


def scan_backplane( address, slots=16 ):
    """Establishes an EtherNet/IP CIP connection and scans the device backplane, yielding any
    (<route_path>,<identity>) data found.

    """
    # Try a routing request; if that fails, it may be a "simple" device (eg. like MicroLogix)
    try:
        for link in range( slots ):
            route_path		= [{'link':link,'port':1}]
            with proxy( host=address[0], port=address[1], route_path=route_path ) as via:
                identity,	= via.read( via.parameter_substitution( "Identity" ))
            if identity:
                yield route_path,identity
    except Exception as exc:
        # No joy.  A simple non-routing device?
        with proxy_simple( host=address[0], port=address[1] ) as via:
            identity,		= via.read( via.parameter_substitution( "Identity" ))
            if identity:
                yield None,identity
            
if __name__ == "__main__":
    sys.exit( main( ))
