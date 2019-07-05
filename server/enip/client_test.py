from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import errno
import logging
import multiprocessing
#import threading
import os
import random
import socket
import sys
import time

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    #logging.getLogger().setLevel( logging.INFO )

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


def connector( **kwds ):
    """An enip.client.connector that logs and ignores socket errors (returning None)."""
    beg				= misc.timer()
    try:
        log.info( "Connecting to %s:%s for %s sec. timeout", kwds.get('host'), kwds.get('port'), kwds.get('timeout') )
        return enip.client.connector( **kwds )
    except socket.timeout as exc:
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


def test_client_api():
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    """
    #logging.getLogger().setLevel( logging.NORMAL )

    taglen			= 100 # able to fit request for Attribute into 1 packet

    svraddr		        = ('localhost', 12399)
    svrkwds			= dotdict({
        'argv': [
            #'-v',
            '--address',	'%s:%d' % svraddr,
            'Int=INT[%d]' % ( taglen ),
            'Real=REAL[%d]' % ( taglen ),
            'DInt=DINT[%d]' % ( taglen ),
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

    def clitest( n ):
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
            except OSError as exc:
                if exc.errno != errno.ECONNREFUSED:
                    raise
                time.sleep( .1 )
         
        results			= []
        failures		= 0
        with connection:
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
        if len( results ) != len( tags ):
            log.warning( "Client %d harvested %d/%d results", n, len( results ), len( tags ))
            failures	       += 1
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

    failed			= network.bench( server_func	= enip.main,
                                                 server_kwds	= svrkwds,
                                                 client_func	= clitest,
                                                 client_count	= clicount,
                                                 client_max	= clipool )
    assert failed == 0
