from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import json
import logging
import multiprocessing
import os
import random
import socket
import sys
import threading
import time
import traceback

try:
    import reprlib
except ImportError:
    import repr as reprlib

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    #logging.getLogger().setLevel( logging.NORMAL )

import cpppo
from   cpppo.server import network, enip
from   cpppo.server.enip import logix, client

log				= logging.getLogger( "lgx.prof" )


def logix_performance( repeat=1000 ):
    """Characterize the performance of the logix module."""
    size			= 1000
    Obj				= logix.Logix()
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'Something', enip.parser.INT, default=[n for n in range( size )])

    assert len( Obj_a1 ) == size

    # Set up a symbolic tag referencing the Logix Object's Attribute
    enip.device.symbol['SCADA']	= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':1 }

    # Lets get it to parse a request:
    #     'service': 			0x52,
    #     'path.segment': 		[{'symbolic': 'SCADA', 'length': 5}],
    #     'read_frag.elements':		20,
    #     'read_frag.offset':		2,

    req_1	 		= bytes(bytearray([
        0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
        0x41, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
    ]))

    def test_once():
        source			= cpppo.peekable( req_1 )
        data 			= cpppo.dotdict()
        with Obj.parser as machine:
            for m,w in machine.run( source=source, data=data ):
                pass
        log.normal( "Logix Request parsed: %s", enip.enip_format( data ))
        
        # If we ask a Logix Object to process the request, it should respond.
        processed		= Obj.request( data )
        log.normal( "Logix Request processed: %s", enip.enip_format( data ))
        return processed, data

    processed, data		= False, None
    while repeat > 0:
        processed, data		= test_once()
        repeat		       -= 1

    assert data.status == 0
    assert len( data.read_frag.data ) == 20
    assert data.read_frag.data[ 0] == 1
    assert data.read_frag.data[-1] == 20


# This number of repetitions is the point where the performance of pypy 2.1
# intersects with cpython 2.7/3.3 on my platform (OS-X 10.8 on a 2.3GHz i7:
# ~380TPS on a single thread.
repetitions=2500

@cpppo.assert_tps( 250, scale=repetitions )
def test_logix_performance():
    """Performance of parsing and executing an operation a number of times on an
    existing Logix object.

    """
    logix_performance( repeat=repetitions )

@cpppo.assert_tps( 250, repeat=repetitions )
def test_logix_setup():
    """Performance of parsing and executing an operation once on a newly created
    Logix object, a number of times.

    """
    logix_performance( repeat=1 )

rss_004_request 		= bytes(bytearray([
    # Register Session
                                        0x65, 0x00, #/* 9.....e. */
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, #/* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, #/* ........ */
    0x00, 0x00                                      #/* .. */
]))

def test_logix_remote( count=100 ):
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    """
    svraddr		        = ('localhost', 12345)
    kwargs			= cpppo.dotdict({
        'argv': [
            #'-v',
            #'--log',		'/tmp/logix.log',
            #'--profile',	'/tmp/logix.prof',
            '--address',	'%s:%d' % svraddr,
            'SCADA=INT[1000]'
        ],
        'server': {
            'control':	cpppo.apidict( enip.timeout, { 
                'done': False
            }),
        },
    })

    # This is sort of "inside-out".  This thread will run logix_remote, which will signal the
    # enip.main (via the kwargs.server...) to shut down.  However, to do line-based performance
    # measurement, we need to be running enip.main in the "Main" thread...
    logixthread			= threading.Thread( target=logix_remote, kwargs={
        'count': count,
        'svraddr': svraddr,
        'kwargs': kwargs
    } )
    logixthread.daemon		= True
    logixthread.start()

    enip.main( **kwargs )

    logixthread.join()

def logix_remote( count, svraddr, kwargs ):
    time.sleep(.25)
    data			= cpppo.dotdict()
    data.enip			= {}
    data.enip.options		= 0
    data.enip.session_handle	= 0
    data.enip.status		= 0
    data.enip.sender_context	= {}
    data.enip.sender_context.input = bytearray( [0x00] * 8 )
    	#array.array( cpppo.type_bytes_array_symbol, "\x00" * 8 )
    data.enip.CIP		= {}
    data.enip.CIP.register 	= {}
    data.enip.CIP.register.options 		= 0
    data.enip.CIP.register.protocol_version	= 1

    data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
    data.input			= bytearray( enip.enip_encode( data.enip ))
    log.normal( "Register Request: %r" % data )
    
    assert bytes( data.input ) == rss_004_request


    timeout			= 5

    begun			= cpppo.timer()
    cli				= client.client( host=svraddr[0], port=svraddr[1] )
    assert cli.writable( timeout=timeout )
    elapsed			= cpppo.timer() - begun
    log.normal( "Client Connected in  %7.3f/%7.3fs" % ( elapsed, timeout ))

    begun			= cpppo.timer()
    request			= cli.register( timeout=timeout )
    elapsed			= cpppo.timer() - begun
    log.normal( "Client Register Sent %7.3f/%7.3fs: %r" % ( elapsed, timeout, request ))
    for data in cli:
        elapsed			= cpppo.timer() - begun
        log.detail( "Client Register Resp %7.3f/%7.3fs: %r" % ( elapsed, timeout, data ))
        if data is None:
            if elapsed <= timeout:
                cli.readable( timeout=timeout - elapsed )
                continue
        break
    elapsed			= cpppo.timer() - begun
    log.normal( "Client Register Rcvd %7.3f/%7.3fs: %r" % ( elapsed, timeout, data ))
    assert data is not None and 'enip.CIP.register' in data, "Failed to receive Register response"
    assert data.enip.status == 0, "Register response indicates failure: %s" % data.enip.status

    cli.session			= data.enip.session_handle


    start			= cpppo.timer()
    for _ in range( count ):
        begun			= cpppo.timer()
        request			= cli.read( path=[{'symbolic': 'SCADA'}, {'element': 12}],
                                                elements=1, offset=0, timeout=timeout )
        elapsed			= cpppo.timer() - begun
        log.normal( "Client ReadFrg. Sent %7.3f/%7.3fs: %r" % ( elapsed, timeout, request ))
        for data in cli:
            elapsed		= cpppo.timer() - begun
            log.detail( "Client ReadFrg. Resp %7.3f/%7.3fs: %r" % ( elapsed, timeout, data ))
            if data is None:
                if elapsed <= timeout:
                    cli.readable( timeout=timeout - elapsed )
                    continue
            break
        elapsed			= cpppo.timer() - begun
        log.normal( "Client ReadFrg. Rcvd %7.3f/%7.3fs: %r" % ( elapsed, timeout, data ))

    duration			= cpppo.timer() - start
    log.warning( "Client ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    kwargs['server'].control.done= True



if __name__ == "__main__":

    '''
    # Profile the main thread
    import cProfile
    import pstats
    prof_file			= "logix_test.profile"
    cProfile.run( "test_logix_remote()", prof_file )
    prof			= pstats.Stats( prof_file )
    print( "\n\nTIME:")
    prof.sort_stats(  'time' ).print_stats( 100 )

    print( "\n\nCUMULATIVE:")
    prof.sort_stats(  'cumulative' ).print_stats( 100 )
    '''


    '''
    # Profile all threads
    import yappi
    yappi.start()

    #import line_profiler
    #profile = line_profiler.LineProfiler( cpppo.server.enip.enip_srv )

    #logix_performance()
    test_logix_remote()

    print('\n\nSORTED BY TOT TIME')
    yappi.print_stats( sys.stdout, sort_type=yappi.SORTTYPE_TTOT, limit=100 )
    
    print('\n\nSORTED BY SUB TIME')
    yappi.print_stats( sys.stdout, sort_type=yappi.SORTTYPE_TSUB, limit=100 )
    '''
    count			= repetitions
    start			= cpppo.timer()
    logix_performance( repeat=count )
    duration			= cpppo.timer() - start
    log.warning( "Local  ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    test_logix_remote( count=100 )
