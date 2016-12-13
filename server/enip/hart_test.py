from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import ast
import errno
import logging
import os
import re
import socket
import struct
import sys
import time
import threading

import pytest

if __name__ == "__main__":
    if __package__ is None:
        __package__	= "cpppo.server.enip"
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    logging.getLogger().setLevel( logging.NORMAL )

import cpppo
from cpppo.dotdict import dotdict
from cpppo.misc import timer, near
from cpppo.modbus_test import nonblocking_command
from cpppo.server import enip, network
from cpppo.server.enip import poll, client

from cpppo.server.enip.get_attribute import proxy
from cpppo.server.enip.hart import HART, proxy_hart # Class, proxy

def start_hart_simulator( *options, **kwds ):
    """Start a simple EtherNet/IP CIP simulator w/ a HART I/O module (execute this file as __main__),
    optionally with Tag=<type>[<size>] (or other) positional arguments appended to the command-line.
    Return the command-line used, and the detected (host,port) address bound.  Looks for something
    like:

        11-11 11:46:16.301     7fff7a619000 network  NORMAL   server_mai enip_srv server PID [ 7573] running on ('', 44818)

    containing a repr of the (<host>,<port>) tuple.  Recover this address using the safe ast.literal_eval.

    At least one positional parameter containing a Tag=<type>[<size>] must be provided.

    """
    command                     = nonblocking_command( [
        'python',
        os.path.abspath( __file__ ),
        '-vvv',
        '--log', 'hart_test.log',
    ] + list( options ))

    # For python 2/3 compatibility (can't mix positional wildcard, keyword parameters in Python 2)
    CMD_WAIT			= kwds.pop( 'CMD_WAIT', 10.0 )
    CMD_LATENCY			= kwds.pop( 'CMD_LATENCY', 0.1 )
    assert not kwds, "Unrecognized keyword parameter: %s" % ( ", ".join( kwds ))

    begun			= timer()
    address			= None
    data			= ''
    while address is None and timer() - begun < CMD_WAIT:
        # On Python2, socket will raise IOError/EAGAIN; on Python3 may return None 'til command started.
        try:
            raw			= command.stdout.read()
            logging.debug( "Socket received: %r", raw)
            if raw:
                data  	       += raw.decode( 'utf-8' )
        except IOError as exc:
            logging.debug( "Socket blocking...")
            assert exc.errno == errno.EAGAIN, "Expected only Non-blocking IOError"
        except Exception as exc:
            logging.warning("Socket read return Exception: %s", exc)
        if not data:
            time.sleep( CMD_LATENCY )
        while data.find( '\n' ) >= 0:
            line,data		= data.split( '\n', 1 )
            logging.info( "%s", line )
            m			= re.search( "running on (\([^)]*\))", line )
            if m:
                address		= ast.literal_eval( m.group(1).strip() )
                logging.normal( "EtherNet/IP CIP Simulator started after %7.3fs on %s:%d",
                                    timer() - begun, address[0], address[1] )
                break
    return command,address


@pytest.fixture( scope="module" )
def simulated_hart_gateway():
    return start_hart_simulator( 'SCADA=INT[100]' )


def test_hart_packet():
    """
    0000   00 1d 9c c9 3e 2a b0 5a da b4 f9 1f 08 00 45 00
    0010   00 66 30 3f 40 00 80 06 00 00 64 64 66 01 64 64
    0020   66 0a c4 50 af 12 f7 0d 5f c5 44 a0 85 e2 50 18
    0030   00 fb 95 2c 00 00 6f 00 26 00 04 00 31 00 00 00
    0040   00 00 6c 74 00 00 88 f9 59 07 00 00 00 00 00 00
    0050   00 00 08 00 02 00 00 00 00 00 b2 00 16 00 52 02
    0060   20 06 24 01 05 f7 08 00 4b 03 21 00 5d 03 24 08
    0070   01 00 01 02
    """

hart_kwds			= dict(
    timeout		= 15.0,
    depth		= 5,		# max. requests in-flight
    multiple		= 0,		# max. bytes of req/rpy per Multiple Service Packet
)

def test_hart_simple( simulated_hart_gateway ):
    # No Multiple Service Packet supported by HART I/O Card simulator

    logging.getLogger().setLevel( logging.INFO )
    command,address             = simulated_hart_gateway
    try:
        assert address, "Unable to detect HART EtherNet/IP CIP Gateway IP address"
        hio				= client.connector( host=address[0], port=address[1] )
        PV			= 1.23
        operations		= [
            'HART_7_Data.PV = (REAL)0', # may fail 'til first HART Read Dynamic Variable is done
            {
                "method":	"service_code",
                "code":		HART.RD_VAR_REQ,
                "data":		[],			# No payload
                "data_size":	2+36,			# Known response size: command,status,<payload>
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
            },
            'HART_7_Data.PV = (REAL)%s' % PV,
            {
                "method":	"service_code",
                "code":		HART.RD_VAR_REQ,
                "data":		[],			# No payload
                "data_size":	2+36,			# Known response size: command,status,<payload>
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
            },
        ]

        # Now, use the underlying client.connector to issue a HART "Read Dynamic Variable" Service Code
        with hio:
            results		= []
            failures		= 0
            for idx,dsc,req,rpy,sts,val in hio.pipeline(
                    operations=client.parse_operations( operations ), **hart_kwds ):
                logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))
                if not val:
                    logging.warning( "Client %s harvested %d/%d results; failed request: %s",
                                     hio, len( results ), len( operations ), rpy )
                    failures   += 1
                results.append( (dsc,val,rpy) )
            rpylast	       	= results[-1][-1]
            assert failures in (0,1)
            assert near( rpylast.read_var.PV, PV )

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise


def test_hart_pass_thru( simulated_hart_gateway ):

    logging.getLogger().setLevel( logging.INFO )
    command,address             = simulated_hart_gateway

    # For testing, we'll hit a specific device
    address			= ("100.100.201.10", 44818)
    address			= ("localhost", 44818)
    try:
        assert address, "Unable to detect HART EtherNet/IP CIP Gateway IP address"
        hio				= client.connector( host=address[0], port=address[1] )

        operations		= [
            {
                "method":	"service_code",
                "code":		HART.PT_INI_REQ,
                "data":		[1, 0],			# HART: Read primary variable
                "data_size":	2+2,			# Known response size: command,status,<payload>
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
            },
            {
                "method":	"service_code",
                "code":		HART.PT_QRY_REQ,
                "data":		[99],			# HART: Pass-thru Query handle
                "data_size":	2+5,			# Known response size: 5 (units + 4-byte real in network order)
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
            },
        ]

        # Now, use the underlying client.connector to issue a HART "Read Dynamic Variable" Service Code
        with hio:
            results		= []
            failures		= 0
            for idx,dsc,req,rpy,sts,val in hio.pipeline(
                    operations=client.parse_operations( operations ), **hart_kwds ):
                logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))
                if not val:
                    logging.warning( "Client %s harvested %d/%d results; failed request: %s",
                                     hio, len( results ), len( operations ), rpy )
                    failures   += 1
                results.append( (dsc,val,rpy) )
            # assert failures == 0 # statuses represent HART I/O status, not CIP response status
            assert results[0][-1].status in ( 32, 33, 35 )	# 32 busy, 33 initiated, 35 device offline
            assert results[1][-1].status in ( 0, 34, 35 )	# 0 success, 34 running, 35 dead

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise


def test_hart_pass_thru_poll( simulated_hart_gateway ):
    """To test a remote C*Logix w/ a HART card, set up a remote port forward from another host in the
    same LAN.  Here's a windows example, using putty.  This windows machine (at 100.100.102.1)
    forwards a port 44818 on fat2.kundert.ca, to the PLC at 100.100.102.10:44818:

        C:\Users\Engineer\Desktop\putty.exe -R 44818:100.100.102.10:44818 perry@fat2.kundert.ca


    Now, from another host that can see fat2.kundert.ca:

        $ python -m cpppo.server.enip.list_services --list-identity -a fat2.kundert.ca:44818
        {
            "peer": [
                "fat2.kundert.ca",
                44818
            ],
            ...
            "enip.status": 0,
            "enip.CIP.list_services.CPF.count": 1,
            "enip.CIP.list_services.CPF.item[0].communications_service.capability": 288,
            "enip.CIP.list_services.CPF.item[0].communications_service.service_name": "Communications",
        }
        {
            ...
            "enip.status": 0,
            "enip.CIP.list_identity.CPF.item[0].identity_object.sin_addr": "100.100.102.10",
            "enip.CIP.list_identity.CPF.item[0].identity_object.status_word": 96,
            "enip.CIP.list_identity.CPF.item[0].identity_object.vendor_id": 1,
            "enip.CIP.list_identity.CPF.item[0].identity_object.product_name": "1756-EN2T/D",
            "enip.CIP.list_identity.CPF.item[0].identity_object.sin_port": 44818,
            "enip.CIP.list_identity.CPF.item[0].identity_object.state": 3,
            "enip.CIP.list_identity.CPF.item[0].identity_object.version": 1,
            "enip.CIP.list_identity.CPF.item[0].identity_object.device_type": 12,
            "enip.CIP.list_identity.CPF.item[0].identity_object.sin_family": 2,
            "enip.CIP.list_identity.CPF.item[0].identity_object.serial_number": 11866067,
            "enip.CIP.list_identity.CPF.item[0].identity_object.product_code": 166,
            "enip.CIP.list_identity.CPF.item[0].identity_object.product_revision": 1802,
        }

    """
    logging.getLogger().setLevel( logging.DETAIL )
    command,address             = simulated_hart_gateway

    # For testing, we'll hit a specific device
    address			= ("100.100.201.10", 44818)
    address			= ("localhost", 44818)
    address			= ("fat2.kundert.ca", 44818)
    route_path			= None
    route_path			= [{'link': 2, 'port': 1}]
    try:
        assert address, "Unable to detect HART EtherNet/IP CIP Gateway IP address"
        hio				= client.connector( host=address[0], port=address[1] )

        # Just get the primary variable, to see if the HART device is there.
        operations		= [
            {
                "method":	"service_code",
                "code":		HART.RD_VAR_REQ,
                "data":		[],			# No payload
                "data_size":	2+36,			# Known response size: command,status,<payload>
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
                "route_path":	route_path,
            },
        ]
        
        with hio:
            for idx,dsc,req,rpy,sts,val in hio.pipeline(
                    operations=client.parse_operations( operations ), **hart_kwds ):
                logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))


        # Try to start the Pass-thru "Read primary variable", and get handle
        operations		= [
            {
                "method":	"service_code",
                "code":		HART.PT_INI_REQ,
                "data":		[1, 0],			# HART: Read primary variable
                "data_size":	2+2,			# Known response size: command,status,<payload>
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
                "route_path":	route_path,
            },
        ]

        # Look for a reply status of 33 initiated
        handle			= None
        while handle is None:
            time.sleep( .1 )
            with hio:
                for idx,dsc,req,rpy,sts,val in hio.pipeline(
                        operations=client.parse_operations( operations ), **hart_kwds ):
                    logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))
                    if rpy.status == 33:
                        handle	= rpy.init.handle
        logging.normal( "Read primary variable Handle: %s", handle )

        # Query for success/failure (loop on running)
        operations		= [
            {
                "method":	"service_code",
                "code":		HART.PT_QRY_REQ,
                "data":		[ handle ],		# HART: Pass-thru Query handle
                "data_size":	2+5,			# Known response size: 5 (units + 4-byte real in network order)
                "send_path":	'@0x%X/8' % ( HART.class_id ), # Instance 1-8 ==> HART Channel 0-7
                "route_path":	route_path,
            },
        ]

        reply			= {}
        while not reply or reply.status == 34:
            time.sleep( .1 )
            with hio:
                for idx,dsc,req,rpy,sts,val in hio.pipeline(
                        operations=client.parse_operations( operations ), **hart_kwds ):
                    logging.normal( "Client %s: %s --> %r: %s", hio, dsc, val, enip.enip_format( rpy ))
                    reply	= rpy
            logging.normal( "Read primary variable Status: %s", reply.status )

        value			= None
        if 'query.reply_data.data' in reply and len( reply.query.reply_data.data ) == 5:
            packer		= struct.Struct( enip.REAL_network.struct_format )
            value,		= packer.unpack_from( buffer=bytearray( reply.query.reply_data.data[1:] ))
        logging.normal( "Read primary variable Value: %s", value )
            
    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise
    
# 
# python hart_test.py -- A *Logix w/ a 16-channel HART Interface Card
# 
def main( **kwds ):
    """Set up a *Logix w/ a 16-channel HART Interface card, eg. 1756-IF8H"""

    enip.config_files 	       += [ __file__.replace( '.py', '.cfg' ) ]

    HART( name="HART Channels", instance_id=0 ) # Class Object
    for i in range( 16 ):
        HART( name="HART Channel %d" % i, instance_id=i + 1 )

    # Establish Identity and TCPIP objects w/ some custom data for the test, from a config file
    return enip.main( argv=sys.argv[1:] )


if __name__ == "__main__":
    sys.exit( main() )
