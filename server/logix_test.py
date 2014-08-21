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
    #logging.getLogger().setLevel( logging.INFO )

import cpppo
from   cpppo.server import network, enip
from   cpppo.server.enip import logix, client, device

log				= logging.getLogger( "lgx.prof" )


def test_logix_multiple():
    """Test the Multiple Request Service.  Ensure multiple requests can be successfully handled, and
    invalid tags are correctly rejected.

    """
    size			= 1000
    Obj				= logix.Logix()
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'parts',       enip.parser.DINT, default=[n for n in range( size )])
    Obj_a2 = Obj.attribute['2']	= enip.device.Attribute( 'ControlWord', enip.parser.DINT, default=[n for n in range( size )])
    Obj_a3 = Obj.attribute['3']	= enip.device.Attribute( 'SCADA_40001', enip.parser.INT,  default=[n for n in range( size )])

    assert len( Obj_a1 ) == size
    assert len( Obj_a2 ) == size
    Obj_a1[0]			= 42
    Obj_a2[0]			= 476

    # Set up a symbolic tag referencing the Logix Object's Attribute
    enip.device.symbol['parts']	= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':1 }
    enip.device.symbol['ControlWord'] \
				= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':2 }
    enip.device.symbol['SCADA_40001'] \
				= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':3 }

    # Test that we correctly compute beg,end,endactual for various Read Tag Fragmented scenarios,
    # with 2-byte and 4-byte types.  For the purposes of this test, we only look at path...elements.
    data			= cpppo.dotdict()
    data.service		= Obj.RD_FRG_RPY
    data.path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [
                                                         {'element': 0 },
                                                       ]] }
    data.read_frag		= {}
    data.read_frag.elements	= 1000
    data.read_frag.offset	= 0
    
    # Request maximum size limited
    beg,end,endactual		= Obj.read_limit( Obj_a1, data, 'read_frag' )
    assert beg == 0 and end == 125 and endactual == 1000 # DINT == 4 bytes
    beg,end,endactual		= Obj.read_limit( Obj_a3, data, 'read_frag' )
    assert beg == 0 and end == 250 and endactual == 1000 # INT == 2 bytes

    data.read_frag.offset	= 125*4 # OK, second request; begin after byte offset of first
    beg,end,endactual		= Obj.read_limit( Obj_a1, data, 'read_frag' )
    assert beg == 125 and end == 250 and endactual == 1000 # DINT == 4 bytes

    # Request elements limited; 0 offset
    data.read_frag.elements	= 30
    data.read_frag.offset	= 0
    beg,end,endactual		= Obj.read_limit( Obj_a3, data, 'read_frag' )
    assert beg == 0 and end == 30 and endactual == 30 # INT == 2 bytes

    # Request elements limited; +'ve offset
    data.read_frag.elements	= 70
    data.read_frag.offset	= 80
    beg,end,endactual		= Obj.read_limit( Obj_a3, data, 'read_frag' )
    assert beg == 40 and end == 70 and endactual == 70 # INT == 2 bytes

    # Request limited by size of data provided (Write Tag Fragmented)
    data			= cpppo.dotdict()
    data.service		= Obj.WR_FRG_RPY
    data.path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [
                                                         {'element': 0 },
                                                       ]] }
    data.write_frag		= {}
    data.write_frag.data	= [0] * 100 # 100 elements provided in this request
    data.write_frag.elements	= 200       # Total request is to write 200 elements
    data.write_frag.offset	= 16        # request starts 16 bytes in (8 INTs)
    beg,end,endactual		= Obj.read_limit( Obj_a3, data, 'write_frag' )
    assert beg == 8 and end == 108 and endactual == 200 # INT == 2 bytes

    # ... same, but lets say request started somewhere in the middle of the array
    data.path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [
                                                         {'element': 222 },
                                                       ]] }
    beg,end,endactual		= Obj.read_limit( Obj_a3, data, 'write_frag' )
    assert beg == 8+222 and end == 108+222 and endactual == 200+222 # INT == 2 bytes


    # Test an example valid multiple request
    data			= cpppo.dotdict()
    data.multiple		= {}
    data.multiple.request	= [ cpppo.dotdict(), cpppo.dotdict() ]
    req				= data.multiple.request

    req[0].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'parts'}]] }
    req[0].read_tag		= {}
    req[0].read_tag.elements	= 1
    
    req[1].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'ControlWord'}]] }
    req[1].read_tag		= {}
    req[1].read_tag.elements	= 1

    request			= Obj.produce( data )

    req_1			= bytes(bytearray([
        0x0A,
        0x02,
        0x20, 0x02, 0x24, 0x01,
        
        0x02, 0x00,
        
        0x06, 0x00,
        0x12, 0x00,
        
        0x4C,
        0x04, 0x91, 0x05, 0x70, 0x61,
        0x72, 0x74, 0x73, 0x00,
        0x01, 0x00,
        
        0x4C,
        0x07, 0x91, 0x0B, 0x43, 0x6F,
        0x6E, 0x74, 0x72, 0x6F, 0x6C,
        0x57, 0x6F, 0x72, 0x64, 0x00,
        0x01, 0x00,
    ]))
                       
    assert request == req_1, \
        "Unexpected result from Multiple Request Service; got: \n%r\nvs.\n%r " % ( request, req_1 )

    # Now, use the Message_Router's parser
    source			= cpppo.rememberable( request )
    data			= cpppo.dotdict()
    with Obj.parser as machine:
        for i,(m,s) in enumerate( machine.run( source=source, data=data )):
            pass
    log.normal( "Multiple Request: %s", enip.enip_format( data ))
    assert 'multiple' in data, \
        "No parsed multiple found in data: %s" % enip.enip_format( data )
    assert data.service == device.Message_Router.MULTIPLE_REQ, \
        "Expected a Multiple Request Service request: %s" % enip.enip_format( data )
    assert data.multiple.number == 2, \
        "Expected 2 requests in request.multiple: %s" % enip.enip_format( data )

    # And ensure if we re-encode the parsed result, we get the original encoded request back
    assert Obj.produce( data ) == req_1

    # Process the request into a reply.
    Obj.request( data )
    log.normal( "Multiple Response: %s", enip.enip_format( data ))
    assert data.service == device.Message_Router.MULTIPLE_RPY, \
        "Expected a Multiple Request Service reply: %s" % enip.enip_format( data )

    rpy_1			= bytearray([
        0x8A,
        0x00,
        0x00,
        0x00,

        0x02, 0x00,

        0x06, 0x00,
        0x10, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC4, 0x00,
        0x2A, 0x00, 0x00, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC4, 0x00,
        0xDC, 0x01, 0x00, 0x00,
    ])

    assert data.input == rpy_1, \
        "Unexpected reply from Multiple Request Service request; got: \n%r\nvs.\n%r " % ( data.input, rpy_1 )

    # Now lets try some valid and invalid requests
    data			= cpppo.dotdict()
    data.multiple		= {}
    data.multiple.request = req	= [ cpppo.dotdict() ]
    req[0].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'SCADA_40001'}]] }
    req[0].read_tag		= {}
    req[0].read_tag.elements	= 1
    data.multiple.number	= len( data.multiple.request )

    request			= Obj.produce( data )

    req_good			= bytearray([
        0x0A,
        0x02,
        0x20, 0x02, ord('$'), 0x01,
        
        0x01, 0x00,
        
        0x04, 0x00,
        
        0x4C,
        0x07, 0x91, 0x0b, ord('S'), ord('C'),
        ord('A'), ord('D'), ord('A'), ord('_'), ord('4'),
        ord('0'), ord('0'), ord('0'), ord('1'), 0x00,
        0x01, 0x00,
    ])
    assert request == req_good, \
        "Unexpected result from Multiple Request Service request for SCADA_40001; got: \n%r\nvs.\n%r " % ( request, req_good )

    Obj.request( data )
    rpy_good			= bytearray([
        0x8A,
        0x00,
        0x00,
        0x00,

        0x01, 0x00,

        0x04, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC3, 0x00,
        0x00, 0x00,
    ])

    assert data.input == rpy_good, \
        "Unexpected reply from Multiple Request Service request for SCADA_40001; got: \n%r\nvs.\n%r " % ( data.input, rpy_good )

    # Add an invalid request
    data			= cpppo.dotdict()
    data.multiple		= {}
    data.multiple.request = req	= [ cpppo.dotdict(), cpppo.dotdict() ]
    req[0].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'SCADA_40001'}]] }
    req[0].read_tag		= {}
    req[0].read_tag.elements	= 1
    req[1].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'SCADA_40002'}]] }
    req[1].read_tag		= {}
    req[1].read_tag.elements	= 1
    data.multiple.number	= len( data.multiple.request )

    request			= Obj.produce( data )

    req_bad			= bytearray([
        0x0A,
        0x02,
        0x20, 0x02, ord('$'), 0x01,
        
        0x02, 0x00,
        
        0x06, 0x00,
        0x18, 0x00,
        
        0x4C,
        0x07, 0x91, 0x0b, ord('S'), ord('C'),
        ord('A'), ord('D'), ord('A'), ord('_'), ord('4'),
        ord('0'), ord('0'), ord('0'), ord('1'), 0x00,
        0x01, 0x00,

        0x4C,
        0x07, 0x91, 0x0b, ord('S'), ord('C'),
        ord('A'), ord('D'), ord('A'), ord('_'), ord('4'),
        ord('0'), ord('0'), ord('0'), ord('2'), 0x00,
        0x01, 0x00,
    ])
    assert request == req_bad, \
        "Unexpected result from Multiple Request Service request for SCADA_40001/2; got: \n%r\nvs.\n%r " % ( request, req_bad )

    Obj.request( data )
    rpy_bad			= bytearray([
        0x8A,
        0x00,
        0x00,
        0x00,

        0x02, 0x00,

        0x06, 0x00,
        0x0e, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC3, 0x00,
        0x00, 0x00,

        0xCC, 0x00, 0x05, 0x01, # Status code 0x05 (invalid path)
        0x00, 0x00,
    ])
    assert data.input == rpy_bad, \
        "Unexpected reply from Multiple Request Service request for SCADA_40001/2; got: \n%r\nvs.\n%r " % ( data.input, rpy_bad )


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
    assert len( data.read_frag.data ) == 19
    assert data.read_frag.data[ 0] == 1
    assert data.read_frag.data[-1] == 19


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
