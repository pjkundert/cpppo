from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import errno
import logging
import multiprocessing
import os
import pytest
import random
import socket
import sys
import threading
import time
import traceback

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    #log_cfg['level'] 		= logging.INFO
    logging.basicConfig( **log_cfg )

from ...dotdict import dotdict, apidict
from ... import misc, tools
from .. import enip, network

log				= logging.getLogger( "cli.test" )

def test_parse_path():
    """EPATH segment parsing, from strings."""
    # Version <= 3.9.2 functionality
    assert enip.client.parse_path( [{"class": 0x22}, {"instance": 1}]) \
        == [{"class": 0x22}, {"instance": 1}]

    # CIP addressing
    assert enip.client.parse_path( '@0x22/1' ) \
        == [{"class": 0x22}, {"instance": 1}]
    assert enip.client.parse_path( '@0x22/1/2' ) \
        == [{"class": 0x22}, {"instance": 1}, {"attribute": 2}]
    assert enip.client.parse_path( '@0x22/1/2/3' ) \
        == [{"class": 0x22}, {"instance": 1}, {"attribute": 2}, {"element": 3}]

    # JSON support
    assert enip.client.parse_path( '@{"class":4}/5/{"connection":100}' ) \
        == [{"class": 0x04}, {"instance": 5}, {"connection": 100}]

    # Tag[<begin>-<end>]
    assert enip.client.parse_path_elements( "Boo" ) \
        == ([{"symbolic": "Boo"}],None,None)
    assert enip.client.parse_path_elements( "Boo[123]" ) \
        == ([{"symbolic": "Boo" }, {"element": 123}],123,None)
    assert enip.client.parse_path_elements( "Boo[123-456]" ) \
        == ([{"symbolic": "Boo" }, {"element": 123}],123,334)

    # CIP + element addressing combined
    assert enip.client.parse_path_elements( "@0x22/1/2[123-456]" ) \
        == ([{"class": 0x22 }, {"instance":1}, {"attribute": 2}, {"element": 123}],123,334)

    # Version >= 3.9.3 functionality.  Support for multiple levels of Tags
    assert enip.client.parse_path_elements( "Foo[1].Boo[123-456]" ) \
        == ([{"symbolic": "Foo" }, {"element": 1}, {"symbolic": "Boo" }, {"element": 123}],123,334)
    # Specify default <element>, <count>
    assert enip.client.parse_path_elements( "Foo", elm=2, cnt=5 ) \
        == ([{"symbolic": "Foo" }, {"element": 2}, ],2,5)
    assert enip.client.parse_path_elements( "Foo[1]", elm=2, cnt=5 ) \
        == ([{"symbolic": "Foo" }, {"element": 1}, ],1,5)
    assert enip.client.parse_path_elements( "Foo[1]*3", elm=2, cnt=5 ) \
        == ([{"symbolic": "Foo" }, {"element": 1}, ],1,3)
    assert enip.client.parse_path_elements( "@1/2/3", elm=2, cnt=5 ) \
        == ([{"class": 1}, {"instance": 2}, {"attribute": 3}, {"element": 2}, ],2,5)
    assert enip.client.parse_path_elements( "@1/2/3[4-9]*3", elm=2, cnt=5 ) \
        == ([{"class": 1}, {"instance": 2}, {"attribute": 3}, {"element": 4}, ],4,6)


def test_parse_route_path():
    assert enip.parse_route_path( '1/0/2/0::1' ) \
        == [{"port": 1, "link":0}, {"port": 2, "link": "::1"}]

    with pytest.raises(Exception) as e:
        assert enip.parse_route_path( '1/0/2/0::1/@2/1' )
    assert "unhandled: ['@2/1']" in str( e.value )
    assert enip.parse_connection_path( '1/0/2/0::1/@2/1' ) \
        == [{"port": 1, "link":0}, {"port": 2, "link": "::1"}, {"class": 2}, {"instance": 1}]


def connector( **kwds ):
    """An enip.client.connector that logs and ignores socket errors (returning None)."""
    beg				= misc.timer()
    try:
        log.info( "Connecting to %s:%s for %s sec. timeout", kwds.get('host'), kwds.get('port'), kwds.get('timeout') )
        return enip.client.connector( **kwds )
    except socket.timeout:
        log.info( "EtherNet/IP CIP connection timed out after %.3fs",
                  misc.timer() - beg )
    except socket.error as exc:
        log.info( "EtherNet/IP CIP connection error %d: %r after %.3fs",
                  exc.errno, exc.strerror, misc.timer() - beg )
    except Exception as exc:
        log.info( "EtherNet/IP CIP connection failure after %.3fs: %s",
                  misc.timer() - beg, exc )
        raise


def test_client_timeout():
    """Both connection and request I/O should respond to the specified timeout (w/ socket.timeout, or
    socket.error, if the host actually exists...).

    """
    conn			= multiprocessing.Process( # So we can actually kill it if blocked...
        target=connector,
        kwargs={ 'host': '10.254.254.253', 'port': 44818, 'timeout': .5 } )
    conn.start()
    # Await the termination of the Process, which should happen just after .5s.
    beg				= misc.timer()
    try:
        assert all( tools.waits.existence( terms=[ lambda: not conn.is_alive() ], timeout=1.0 )), \
            "enip.client.connector to non-existent host didn't time out; took: %.3fs" % ( misc.timer() - beg )
    finally:
        conn.terminate()


def test_dotdict_request():
    d = dotdict()
    o = dotdict({'something': 99})
    d.item = [o,o,o]
    d2 = dotdict( d )
    assert len( d2 ) == 1
    assert len( d2.item ) == 3


def test_client_api_simple():
    taglen			= 100 # able to fit request for Attribute into 1 packet
    server_addr		        = ('localhost', 12398)
    server_kwds			= dotdict({
        'argv': [
            '-v',
            '--address',	'%s:%d' % server_addr,
            'Int@0x99/1/1=INT[%d]' % ( taglen ),
            'Real@0x99/1/2=REAL[%d]' % ( taglen ),
            'DInt@0x99/1/3=DINT[%d]' % ( taglen ),
        ],
        'server': {
            'control':	apidict( enip.timeout, {
                'done': False
            }),
        },
    })
    server_func			= enip.main

    Process			= threading.Thread # multiprocessing.Process
    server			= Process( target=server_func, kwargs=server_kwds )
    server.daemon		= True
    server.start()

    client_timeout		= 15.0

    try:
        connection		= None
        while not connection:
            time.sleep( .1 )
            try:
                connection	= enip.client.implicit( *server_addr, timeout=client_timeout, connection_path=None )
            except socket.error as exc:
                logging.warning( "enip.client.connector socket.error: %r", exc )
                if exc.errno != errno.ECONNREFUSED:
                    raise
            except Exception as exc:
                logging.warning( "enip.client.connector Exception: %r", exc )
                raise

        with connection:
            # Get Attribute Single's payload is an EPATH
            req			= connection.service_code(
                code=enip.Object.GA_SNG_REQ, path='@0x99/1/2' )
            assert 'service_code' in req and req.service_code is True # no payload
            assert connection.readable( timeout=10.0 ) # receive reply
            rpy			= next( connection )
            assert rpy and 'enip.CIP' in rpy and 'send_data.CPF.item[1].connection_data.request.get_attribute_single' in rpy.enip.CIP

            # Set Attribute Single's payload is an EPATH + USINT data
            req			= connection.service_code(
                code=enip.Object.SA_SNG_REQ, path='@0x99/1/2',
                data=list( bytearray(
                    #enip.EPATH.produce( enip.parse_path( '@0x99/1/2' )) +
                    enip.typed_data.produce( { 'data': list( map( float, range( taglen ))) }, tag_type=enip.REAL.tag_type ))))
            assert 'service_code' in req and isinstance( req.service_code, dict ) and 'data' in req.service_code
            assert connection.readable( timeout=10.0 ) # receive reply
            rpy			= next( connection )
            assert rpy and 'enip.CIP' in rpy and 'send_data.CPF.item[1].connection_data.request.set_attribute_single' in rpy.enip.CIP

            '''
            # Try to send some PCCC I/O
            req		= connection.connected_send( b'\x00\x00\x01\x00\x00\x00\x00\x00\x06\x00\x4a\x0a\x03',
                                                     connection=0x8dee0016, sequence=1 )
            logging.normal("PCCC Request: %s", enip.enip_format( req ))
            #assert 'service_code' in req and req.service_code is True # no payload
            assert connection.readable( timeout=10.0 ) # receive reply
            rpy			= next( connection )
            logging.normal("PCCC Response: %s", enip.enip_format( rpy )) # will be EtherNet/IP status 8; nothing implemented
            '''

        if not random.randint( 0, 9 ): # 10% of the time...
            # Try a clean shutdown, closing the outgoing half of the socket, leading to an EOF on
            # the server.  This will cause the subsequent Forward Close to fail w/ an EPIPE
            logging.normal( "Skip Forward Close; send EOF" )
            connection.shutdown()
            assert connection.readable( timeout=1.0 ) # receive EOF
            try:
                connection.close()
            except socket.error as exc:
                if exc.errno != errno.EPIPE:
                    raise
        else:
            # Normal close procedure; send Forward Close + EOF, receive Forward Close + EOF.
            logging.normal( "Send Forward Close; then EOF" )
            del connection
    finally:
        control			= server_kwds.get( 'server', {} ).get( 'control', {} ) if server_kwds else {}
        if 'done' in control:
            log.normal( "Server %r done signalled", misc.function_name( server_func ))
            control['done']	= True	# only useful for threading.Thread; Process cannot see this
        if hasattr( server, 'terminate' ):
            log.normal( "Server %r done via .terminate()", misc.function_name( server_func ))
            server.terminate() 		# only if using multiprocessing.Process(); Thread doesn't have
        server.join( timeout=1.0 )


def test_client_api_random():
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    We'll point the Tags to CIP Class 0x99, Instance 1, starting at Attribute 1.

    """
    taglen			= 100 # able to fit request for Attribute into 1 packet

    svraddr		        = ('localhost', 12399)
    svrkwds			= dotdict({
        'argv': [
            #'-v',
            '--address',	'%s:%d' % svraddr,
            'Int@0x99/1/1=INT[%d]' % ( taglen ),
            'Real@0x99/1/2=REAL[%d]' % ( taglen ),
            'DInt@0x99/1/3=DINT[%d]' % ( taglen ),
        ],
        'server': {
            'control':	apidict( enip.timeout, { 
                'done': False
            }),
        },
    })
    clitimes			= 100
    clitimeout			= 15.0
    clidepth			= 5		# max. requests in-flight
    climultiple			= 500		# max. bytes of req/rpy per Multiple Service Packet
    clicount			= 7
    clipool			= 5

    def tagtests( total, name="Int", length=taglen, tag_class=enip.INT ):
        """Generate random reads and writes to Tag 'name' (default "Int", tag_class enip.INT); can only
        handle types with real, not estimated, sizes (ie. not SSTRING).  All writes write a value
        equal to the index, all reads should report the correct value (or 0, if the element was
        never written).  Randomly supply an offset (force Read/Write Tag Fragmented).

        Yields the effective (elm,cnt), and the tag=val,val,... .

        """
        for i in range( total ):
            elm			= random.randint( 0, length-1 ) 
            cnt			= random.randint( 1, min( 5, length - elm ))
            off			= None # in elements, not bytes
            val			= None
            if not random.randint( 0, 10 ) and cnt > 1:
                off			= random.randint( 0, cnt - 1 )
            if random.randint( 0, 1 ):
                val		= list( range( elm + ( off or 0 ), elm + cnt ))
            tag			= "%s[%d-%d]" % ( name, elm, elm + cnt - 1 )
            if off is not None:
                tag	       += "+%d" % ( off * tag_class.struct_calcsize )
            if val is not None:
                tag	       += '=(%s)' % tag_class.__name__ + ','.join( map( str, val ))

            yield (elm+( off or 0 ),cnt-( off or 0 )),tag

    def clitest_tag( n ):
        times			= clitimes  # How many I/O per client
        # take apart the sequence of ( ..., ((elm,cnt), "Int[1-2]=1,2"), ...)
        # into two sequences: (..., (elm,cnt), ...) and (..., "Int[1-2]=1,2", ...)
        tag_targets		= [('Int',enip.INT), ('DInt',enip.DINT), ('Real',enip.REAL)]
        name,tag_class		= random.choice( tag_targets )
        regs,tags		= zip( *list( tagtests( total=times, name=name, tag_class=tag_class )))
        connection		= None
        while not connection:
            try:
                connection	= enip.client.connector( *svraddr, timeout=clitimeout )
            except socket.error as exc:
                if exc.errno != errno.ECONNREFUSED:
                    raise
                time.sleep( .1 )
         
        results			= []
        failures		= 0
        with connection:
            begins		= misc.timer()
            multiple		= random.randint( 0, 4 ) * climultiple // 4 	# eg. 0, 125, 250, 375, 500
            depth		= random.randint( 0, clidepth )			# eg. 0 .. 5
            for idx,dsc,req,rpy,sts,val in connection.pipeline(
                    operations=enip.client.parse_operations( tags ), timeout=clitimeout,
                    multiple=multiple, depth=depth ):
                log.detail( "Client %3d: %s --> %r ", n, dsc, val )
                if not val:
                    log.warning( "Client %d harvested %d/%d results; failed request: %s",
                                 n, len( results ), len( tags ), rpy )
                    failures       += 1
                results.append( (dsc,val) )
        duration		= misc.timer() - begins
        if len( results ) != len( tags ):
            log.warning( "Client %d harvested %d/%d results", n, len( results ), len( tags ))
            failures	       += 1
        log.normal( "Client (Tags)    %3d: %s TPS", n, duration/times )

        # Now, ensure that any results that reported values reported the correct values -- each
        # value equals its own index or 0.
        for i,(elm,cnt),tag,(dsc,val) in zip( range( times ), regs, tags, results ):
            log.detail( "Running on test %3d: operation %34s (%34s) on %5s[%3d-%-3d] ==> %s",
                i, tag, dsc, name, elm, elm + cnt - 1, val )
            if not val:
                log.warning( "Failure in test %3d: operation %34s (%34s) on %5s[%3d-%-3d]: %s",
                             i, tag, dsc, name, elm, elm + cnt - 1, val )
                failures       += 1
            if isinstance( val, list ): # write returns True; read returns list of data
                #print( "%s testing %10s[%5d-%-5d]: %r" % ( threading.current_thread().name, tag, elm, elm + cnt - 1, val ))
                if not all( v in (e,0) for v,e in zip( val, range( elm, elm + cnt ))):
                    log.warning( "Failure in test %3d: operation %34s (%34s) on %5s[%3d-%-3d] didn't equal indexes: %s",
                                 i, tag, dsc, name, elm, elm + cnt - 1, val )
                    failures       += 1

        return 1 if failures else 0

    def clitest_svc( n ):
        """Issue a series of CIP Service Codes."""
        times			= clitimes  #  How many I/O per client
        connection		= None
        while not connection:
            try:
                connection	= enip.client.connector( *svraddr, timeout=clitimeout )
            except socket.error as exc:
                if exc.errno != errno.ECONNREFUSED:
                    raise
                time.sleep( .1 )

        # Issue a sequence of simple CIP Service Code operations.
        operations = times * [{
            "method":	"service_code",
            "path":	'@0x99/1/2',
            "code":	enip.Object.GA_SNG_REQ,
            "data":	[],
        }]

        results			= []
        failures		= 0
        begins			= misc.timer()
        try:
            with connection:
                multiple	= random.randint( 0, 4 ) * climultiple // 4 	# eg. 0, 125, 250, 375, 500
                depth		= random.randint( 0, clidepth )			# eg. 0 .. 5
                for idx,dsc,req,rpy,sts,val in connection.pipeline(
                        operations=operations, timeout=clitimeout,
                        multiple=multiple, depth=depth ):
                    log.detail( "Client %3d: %s --> %r ", n, dsc, val )
                    if not val:
                        log.warning( "Client %d harvested %d/%d results; failed request: %s",
                                     n, len( results ), len( operations ), rpy )
                        failures += 1
                    results.append( (dsc,val) )
        except Exception as exc:
            logging.warning( "%s: %s", exc, ''.join( traceback.format_exception( *sys.exc_info() )))
            failures	       += 1
        duration		= misc.timer() - begins

        if len( results ) != len( operations ):
            log.warning( "Client %d harvested %d/%d results", n, len( results ), len( operations ))
            failures	       += 1
        log.normal( "Client (service) %3d: %s TPS", n, duration/times )
        return 1 if failures else 0

    # Use a random one of the available testing functions
    def clitest( n ):
        random.choice( [
            clitest_tag,
            clitest_svc,
        ] )( n )

    
    failed			= network.bench( server_func	= enip.main,
                                                 server_kwds	= svrkwds,
                                                 client_func	= clitest,
                                                 client_count	= clicount,
                                                 client_max	= clipool )
    assert failed == 0
