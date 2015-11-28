from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

try:
    from future_builtins import map, zip
except ImportError:
    pass

import errno
import logging
import multiprocessing
import random
import socket
import threading
import time

from ...dotdict import dotdict, apidict
from ... import misc, tools
from .. import enip, network

log				= logging.getLogger( "cli.test" )

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
        assert all( tools.await.existence( terms=[ lambda: not conn.is_alive() ], timeout=1.0 )), \
            "enip.client.connector to non-existent host didn't time out; took: %.3fs" % ( misc.timer() - beg )
    finally:
        conn.terminate()


def test_client_api():
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    """
    # TODO: work in progress; not operational yet (only one clitest Thread)

    svraddr		        = ('localhost', 12399)
    svrkwds			= dotdict({
        'argv': [
            #'-v',
            '--address',	'%s:%d' % svraddr,
            'Tag=INT[1000]'
        ],
        'server': {
            'control':	apidict( enip.timeout, { 
                'done': False
            }),
        },
    })
    clitimeout			= 5.0
    clidepth			= 3		# requests in-flight
    climultiple			= 500		# bytes of req/rpy per Multiple Service Packet
    clicount			= 7
    clipool			= 5

    def tagtests( total, name="Tag", length=1000, size=2 ):
        """Generate random reads and writes to Tag.  All writes write a value equal to the index, all
        reads should report the correct value (or 0, if the element was never written).  Randomly
        supply an offset (force Read/Write Tag Fragmented).

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
                tag	       += "+%d" % ( off * size )
            if val is not None:
                tag	       += '=' + ','.join( map( str, val ))

            yield (elm+( off or 0 ),cnt-( off or 0 )),tag

    def clitest( n ):
        times			= 100  # How many I/O per client
        # take apart the sequence of ( ..., ((elm,cnt), "Tag[1-2]=1,2"), ...)
        # into two sequences: (..., (elm,cnt), ...) and (..., "Tag[1-2]=1,2", ...)
        name			= 'Tag'
        regs,tags		= zip( *list( tagtests( total=times, name=name )))
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
            for idx,dsc,req,rpy,sts,val in connection.pipeline( 
                    operations=enip.client.parse_operations( tags ),
                    multiple=climultiple, timeout=clitimeout, depth=clidepth ):
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
            if isinstance( val, list ):
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
