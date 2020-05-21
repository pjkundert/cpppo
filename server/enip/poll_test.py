from __future__ import absolute_import, print_function, division, unicode_literals
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import ast
import errno
import logging
import os
import re
import socket
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

from cpppo.dotdict import dotdict
from cpppo.misc import timer, near
from cpppo.modbus_test import nonblocking_command
from cpppo.server import enip, network
from cpppo.server.enip import poll
from cpppo.server.enip.ab import powerflex, powerflex_750_series


def start_powerflex_simulator( *options, **kwds ):
    """Start a simple EtherNet/IP CIP simulator (execute this file as __main__), optionally with
    Tag=<type>[<size>] (or other) positional arguments appended to the command-line.  Return the
    command-line used, and the detected (host,port) address bound.  Looks for something like:

        11-11 11:46:16.301     7fff7a619000 network  NORMAL   server_mai enip_srv server PID [ 7573] running on ('', 44818)

    containing a repr of the (<host>,<port>) tuple.  Recover this address using the safe ast.literal_eval.

    At least one positional parameter containing a Tag=<type>[<size>] must be provided.

    """
    command                     = nonblocking_command( [
        'python',
        os.path.abspath( __file__ ),
        '-v',
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
            m			= re.search( r"running on (\([^)]*\))", line )
            if m:
                address		= ast.literal_eval( m.group(1).strip() )
                logging.normal( "EtherNet/IP CIP Simulator started after %7.3fs on %s:%d",
                                    timer() - begun, address[0], address[1] )
                break
    return command,address


@pytest.fixture( scope="module" )
def simulated_powerflex_gateway():
    return start_powerflex_simulator( 'SCADA=INT[100]' )


def test_powerflex_simple( simulated_powerflex_gateway ):
    # logging.getLogger().setLevel( logging.INFO )
    command,address             = simulated_powerflex_gateway
    try:
        assert address, "Unable to detect PowerFlex EtherNet/IP CIP Gateway IP address"
        pf				= powerflex( host=address[0], port=address[1], timeout=1 )

        # Reading a list of nothing should work...
        assert list( pf.read( [] )) == []
        # At the least, it ensures we have a non-None .identity
        print( "PowerFlex Identity: %s" % pf )
        assert "None" not in str( pf ), "No EtherNet/IP CIP connection, or no Identity"

        # Simple read of Tag, using Read Tag; returns list of bare list of data elements
        tag			= "SCADA[0-9]"
        value,			= pf.read( [ tag ] )
        print( "Tag:            %15s: %r" % ( tag, value ))
        assert type( value ) is list and all( v == 0 for v in value )

        # Read of CIP Object/Instance/Attribute using Get Attribute Single, interpreted as an
        # arbitrary CIP data type.  Returns list of result values, each a dict of decoded data.
        # Providing a type to use to decode the data produces whatever dictionary the type parses
        # into, unchanged:
        get			= ( "@1/1/1", enip.INT )
        value,			= pf.read( [ get ] )
        print( "Vendor Number:  %15s: %r" % ( get[0], value ))
        assert len( value ) == 1 and 'INT' in value[0] and value[0]['INT'] == 0x0001

        get			= ( "@1/1/7", enip.SSTRING )
        value,			= pf.read( [ get] )
        print( "Product Name:   %15s: %r" % ( get[0], value ))
        assert len( value ) == 1 and 'SSTRING' in value[0] and value[0].SSTRING.string == 'PowerFlex/20-COMM-E'

        # Get the DPI Parameter 0x93, Instance 3, Attribute 9 Output_Current attribute, interpreted
        # as REAL.  1 element.
        get			= ( "@0x93/7/10", enip.REAL )
        value,			= pf.read( [ get] )
        print( "Output_Current: %15s: %r" % ( get[0], value ))
        assert len( value ) == 1 and 'REAL' in value[0] and near( value[0].REAL, 123.45 )

        # Get the DPI parameter 0x93, Instance 3, Attribute 9 Output_Current attribute, interpreted
        # as INT.  1 element.  Providing named CIP types shucks the dictionary container, and
        # produces just the target typed data:
        get			= ( "@0x93/140/10", "INT" )
        value,			= pf.read( [ get] )
        print( "Accel_Time_1:   %15s: %r" % ( get[0], value ))
        assert len( value ) == 1 and value[0] == 567
        get			= ( "@1/1", [ "INT", "INT", "INT", "INT", "INT", "DINT", "SSTRING", "USINT" ])
        value,			= pf.read( [ get] )
        print( "Identity (all): %15s: %r" % ( get[0], value ))
        assert value == [1, 14, 54, 2836, 12640, 7079450, u'PowerFlex/20-COMM-E', 255]

        # TCPIP Object
        get			= ( "@0xF5/1", [
            "DWORD", "DWORD", "DWORD", "EPATH",
            "IPADDR", "IPADDR", "IPADDR", "IPADDR", "IPADDR", "STRING",
            "STRING"
            ])
        value,			= pf.read( [ get] )
        print( "TCPIP (all):    %15s: %r" % ( get[0], value ))
        assert value == [2, 48, 16, [{'class': 246}, {'instance': 1}], '10.0.0.4', '255.255.252.0', '10.0.0.1', '10.0.0.1', '8.8.8.8', u'example.com', u'powerflex']
        
        # List Identity
        ident			= pf.list_identity()
        assert ident.sin_addr == "10.0.0.4"

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise


def test_powerflex_poll_success( simulated_powerflex_gateway ):
    #logging.getLogger().setLevel( logging.INFO )
    command,address             = simulated_powerflex_gateway
    try:
        assert address, "Unable to detect PowerFlex EtherNet/IP CIP Gateway IP address"
        values			= {}
        def process( p, v ):
            print( "%s: %16s == %s" % ( time.ctime(), p, v ))
            values[p]		= v    
        process.done		= False
    
        poller			= threading.Thread(
            target=poll.poll, args=(powerflex_750_series,), kwargs={ 
                'address': 	address,
                'cycle':	1.0,
                'timeout':	0.5,
                'process':	process,
            })
        poller.deamon		= True
        poller.start()

        try:
            # Polling starts immediately
            time.sleep(.5)
            assert len( values ) == 2

            # Make sure it repeats
            values.clear()
            assert len( values ) == 0
            time.sleep(1.0)
            assert len( values ) == 2

            # Allow time to refresh values on next poll
            values['Output Current'] = 1.0
            time.sleep(1.0)
        finally:
            process.done	= True

        poller.join( 1.0 )
        assert not poller.is_alive(), "Poller Thread failed to terminate"
    
        assert 'Output Current' in values and near( values['Output Current'][0], 123.45 )
        assert 'Motor Velocity' in values and near( values['Motor Velocity'][0], 789.01 )

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise


def test_powerflex_poll_failure():
    """No PowerFlex simulator alive; should see exponential back-off.  Test that the poll.poll API can
    withstand gateway failures, and robustly continue polling.

    """
    #logging.getLogger().setLevel( logging.NORMAL )

    def null_server( conn, addr, server=None ):
        """Fake up an EtherNet/IP server that just sends a canned EtherNet/IP CIP Register and Identity
        string response, to fake the poll client into sending a poll request into a closed socket.
        Immediately does a shutdown of the incoming half of the socket, and then closes the
        connection after sending the fake replies, usually resulting in an excellent EPIPE/SIGPIPE
        on the client.  Use port 44819, to avoid interference by (possibly slow-to-exit) simulators
        running on port 44818.

        """
        logging.normal( "null_server on %s starting" % ( addr, ))
        conn.shutdown( socket.SHUT_RD )
        time.sleep( 0.1 )
        conn.send( b'e\x00\x04\x00\xc9wH\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' )
        conn.send( b'c\x00;\x00\xd4/\x9dm\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0c\x005\x00\x01\x00\x00\x02\xaf\x12\n\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x0e\x006\x00\x14\x0b`1\x1a\x06l\x00\x13PowerFlex/20-COMM-E\xff' )
        conn.close()
        while server and not server.control.done:
            time.sleep( .1 )
        logging.normal( "null_server on %s done" % ( addr, ))

    try:
        values			= {} # { <parameter>: <value> }
        failed			= {} # { <time>: <exc> }

        control			= dotdict()
        control.done		= False

        for _ in range( 3 ):
            server		= threading.Thread(
                target=network.server_main, kwargs={
                    'address': 	('',44819),
                    'target':	null_server,
                    'kwargs': {
                        'server': dotdict({
                            'control': control
                        })
                    },
                    'udp':	False, # no UDP server in this test
                })
            server.daemon		= True
            server.start()
            time.sleep(.5)
            if server.is_alive:
                break
        assert server.is_alive, "Unable to start null_server on INADDR_ANY"

        def process( p, v ):
            logging.normal( "process: %16s == %s", p, v )
            values[p]		= v
        process.done		= False

        def failure( exc ):
            logging.normal( "failed: %s", exc )
            elapsed		= int(( timer() - failure.start ) * 1000 ) # ms.
            failed[elapsed]	= str( exc )
        failure.start		= timer()
    
        backoff_min		= 0.5
        backoff_max		= 4.0
        backoff_multiplier	= 2.0 # --> backoff == .5, 1.0, 2.0, 4.0
        poller			= threading.Thread(
            target=poll.poll, kwargs={ 
                'proxy_class':	powerflex_750_series,
                'address': 	('localhost',44819),
                'cycle':	1.0,
                'timeout':	0.5,
                'backoff_min':	backoff_min,
                'backoff_max':	backoff_max,
                'backoff_multiplier': backoff_multiplier,
                'process':	process,
                'failure':	failure,
            })
        poller.deamon		= True
        poller.start()

        try:
            # Polling starts immediately, but the first poll occurs after an attempt to get the
            # Identity string, hence two timeouts for the first poll failure.
            while len( failed ) < 3 and timer() - failure.start < 10.0:
                time.sleep(.1)
        finally:
            process.done	= True
            control.done	= True
        poller.join( backoff_max + 1.0 ) # allow for backoff_max before loop check
        assert not poller.is_alive(), "Poller Thread failed to terminate"
        server.join( 1.0 )
        assert not server.is_alive(), "Server Thread failed to terminate"

        # Check that each failure is (at least) the expected backoff from the last
        assert len( failed ) > 0
        k_last			= None
        backoff			= backoff_min
        for k in sorted( failed ):
            logging.normal( "Poll failure at %4dms (next backoff: %7.3fs): %s", k, backoff, failed[k] )
            if k_last is not None:
                assert k - k_last >= backoff
            backoff		= min( backoff_max, backoff * backoff_multiplier )
            k_last		= k

        assert len( values ) == 0

    except Exception as exc:
        logging.warning( "Test terminated with exception: %s", exc )
        raise

# 
# python poll_test.py -- AB PowerFlex simulator for testing
# 

class UCMM_no_route_path( enip.UCMM ):
    """The PowerFlex/20-COMM-E UnConnected Messages Manager allows no route_path"""
    route_path			= False


class DPI_Parameters( enip.Object ):
    """Each Instance corresponds to a PowerFlex paramter.  Writing to Attribute 9 updates the EEPROM in
    the device, while writing to Attribute 10 (0xA) updates only the (temporary) RAM memory in the
    PowerFlex.  Therefore, we'll set both Attribute 9/10 to point to the same simulated Attribute.
    
    TODO:

    Parameter Object 0x0F is supported in the PowerFlex 7-Class Drivers, but not in the
    750-Series. DPI Parameter Object 0x93 is supported in both (with restriction); see
    http://literature.rockwellautomation.com/idc/groups/literature/documents/um/20comm-um010_-en-p.pdf,
    Chapter 6-2.

    For this simulation, we'll make the DPI Parameter Object 0x93 Instances, Attributes 9 and 10
    (0x0A) all point to the same Attribute object, and reading/writing these Attributes at any of
    their addresses will all access the same Attribute data.

    """
    class_id			= 0x93

    # Simulated PowerFlex Parameters; correspond to DPI Object's Instance numbers
    OUTPUT_FREQ			= 1
    MTR_VEL_FDBK		= 3
    OUTPUT_CURRENT		= 7
    DC_BUS_VOLTS		= 11
    ELAPSED_KWH			= 14
    ACCEL_TIME_1		= 140
    SPEED_UNITS			= 300
    def __init__( self, name=None, **kwds ):
        super( DPI_Parameters, self ).__init__( name=name, **kwds )
        if self.instance_id == 0:
            # Extra Class-level Attributes
            pass
        elif self.instance_id == self.OUTPUT_FREQ:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Output_Freq',	enip.REAL, default=456.78 )
        elif self.instance_id == self.MTR_VEL_FDBK:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Mtr_Vel_Fdbk',	enip.REAL, default=789.01 )
        elif self.instance_id == self.OUTPUT_CURRENT:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Output_Current',	enip.REAL, default=123.45 )
        elif self.instance_id == self.DC_BUS_VOLTS:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'DC_Bus_Volts',	enip.REAL, default=0.08 )
        elif self.instance_id == self.ELAPSED_KWH:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Elapsed_KwH',	enip.REAL, default=987.65 )
        elif self.instance_id == self.ACCEL_TIME_1:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Accel_Time_1',	enip.INT, default=567 )
        elif self.instance_id == self.SPEED_UNITS:
            self.attribute[ '9']= \
            self.attribute['10']= enip.Attribute( 'Speed_Units',	enip.DINT, default=1 ) # RPM
        else:
            raise AssertionError( "Unrecognized PowerFlex Parameter / Instance ID: %s" % ( self.instance_id ))

        # TODO: Set up all appropriate instance attributes here, as per self.instance_id


def main( **kwds ):
    """Set up PowerFlex/20-COMM-E objects (enip.main will set up other Logix-like objects)"""

    enip.config_files 	       += [ __file__.replace( '.py', '.cfg' ) ]

    DPI_Parameters( name="DPI_Parameters", instance_id=0 ) # Class Object
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.OUTPUT_FREQ )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.MTR_VEL_FDBK )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.OUTPUT_CURRENT )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.DC_BUS_VOLTS )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.ELAPSED_KWH )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.ACCEL_TIME_1 )
    DPI_Parameters( name="DPI_Parameters", instance_id=DPI_Parameters.SPEED_UNITS )

    # Establish Identity and TCPIP objects w/ some custom data for the test, from a config file
    return enip.main( argv=sys.argv[1:], UCMM_class=UCMM_no_route_path )


if __name__ == "__main__":
    sys.exit( main() )
