from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import logging
import os
import pytest
import sys
import threading
import time

has_pylogix			= False
try:
    import pylogix
    has_pylogix			= True
except Exception:
    pass

# for @profile, kernprof.py -v -l enip_test.py
#from line_profiler import LineProfiler

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    #logging.getLogger().setLevel( logging.INFO )

import cpppo
from   cpppo.server import enip
from   cpppo.server.enip import logix, client

log				= logging.getLogger( "enip.lgx" )

# Get Attribute[s] All/Single tests: description, original, produced, parsed, processed, response.
# Ensure we can produce the encoded version from the original, and then check what we can parse from
# the encoded, and finally what the result is.
GA_tests			= [
            (
                "Get Attribute Single 0x02/1/4",
                {
                    'get_attribute_single': True,
                    'path': {
                        'segment': [ cpppo.dotdict( s ) for s in [
                                { 'class': 0x02 },
                                { 'instance': 1},
                                { 'attribute': 4 }]]},
                },
                b'\x0e\x03 \x02$\x010\x04',
                {
                    "service": 0x0e,
                },
                {
                    "service": 0x8e,
                    "get_attribute_single.data": [
                        0,
                        0,
                        128,
                        63
                    ],
                },
                b'\x8e\x00\x00\x00\x00\x00\x80?',
            ), (
                "Get Attributes All 0x02/1",
                {
                    'get_attributes_all': True,
                    'path': {
                        'segment': [ cpppo.dotdict( s ) for s in [
                            { 'class': 0x02 },
                            { 'instance': 1 }]]},
                },
                b'\x01\x02 \x02$\x01',
                {
                    "service": 0x01,
                },
                {
                    "service": 0x81,
                    "get_attributes_all.data": [
                        220,
                        1,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        128,
                        63
                    ],
                },
                b'\x81\x00\x00\x00\xdc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80?',
            ), (
                "Set Attribute Single 0x02/1/4",
                {
                    'set_attribute_single': {
                        'data': [ 0, 0, 128, 63 ]
                    },
                    'path': {
                        'segment': [ cpppo.dotdict( s ) for s in [
                            { 'class': 0x02 },
                            { 'instance': 1 },
                            { 'attribute': 4 }]]},
                },
                b'\x10\x03 \x02$\x010\x04\x00\x00\x80?',
                {
                    "service": 0x10,
                    "set_attribute_single.data": [
                        0,
                        0,
                        128,
                        63
                    ],
                },
                {
                    "service": 0x90,
                    "status": 0,
                },
                b'\x90\x00\x00\x00',
            )
]

def test_logix_multiple():
    """Test the Multiple Request Service.  Ensure multiple requests can be successfully handled, and
    invalid tags are correctly rejected.

    The Logix is a Message_Router instance, and is expected to be at Class 2, Instance 1.  Eject any
    non-Logix Message_Router that presently exist.

    """
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    Obj				= logix.Logix( instance_id=1 )

    # Create some Attributes to test, but mask the big ones from Get Attributes All.
    size			= 1000
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'parts',       enip.parser.DINT, default=[n for n in range( size )],
                                                         mask=enip.device.Attribute.MASK_GA_ALL )
    Obj_a2 = Obj.attribute['2']	= enip.device.Attribute( 'ControlWord', enip.parser.DINT, default=[0,0])
    Obj_a3 = Obj.attribute['3']	= enip.device.Attribute( 'SCADA_40001', enip.parser.INT,  default=[n for n in range( size )],
                                                         mask=enip.device.Attribute.MASK_GA_ALL )
    Obj_a4 = Obj.attribute['4']	= enip.device.Attribute( 'number',      enip.parser.REAL, default=0.0)

    # Set up a symbolic tag referencing the Logix Object's Attribute
    enip.device.symbol['parts']	= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':1 }
    enip.device.symbol['ControlWord'] \
				= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':2 }
    enip.device.symbol['SCADA_40001'] \
				= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':3 }
    enip.device.symbol['number'] \
				= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':4 }


    assert len( Obj_a1 ) == size
    assert len( Obj_a3 ) == size
    assert len( Obj_a4 ) == 1
    Obj_a1[0]			= 42
    Obj_a2[0]			= 476
    Obj_a4[0]			= 1.0
    # Ensure that the basic CIP Object requests work on a derived Class.
    for description,original,produced,parsed,result,response in GA_tests:
        request			= cpppo.dotdict( original )

        log.warning( "%s; request: %s", description, enip.enip_format( request ))
        encoded			= Obj.produce( request )
        assert encoded == produced, "%s: Didn't produce correct encoded request: %r != %r" % (
            description, encoded, produced )

        # Now, use the Message_Router's parser to decode the encoded bytes
        source			= cpppo.rememberable( encoded )
        decoded			= cpppo.dotdict()
        with Obj.parser as machine:
            for m,s in enumerate( machine.run( source=source, data=decoded )):
                pass
        for k,v in cpppo.dotdict( parsed ).items():
            assert decoded[k] == v, "%s: Didn't parse expected value: %s != %r in %s" % (
                description, k, v, enip.enip_format( decoded ))

        # Process the request into a reply, and ensure we get the expected result (some Attributes
        # are filtered from Get Attributes All; only a 2-element DINT array and a single REAL should
        # be produced)
        Obj.request( request )
        logging.warning("%s: reply:   %s", description, enip.enip_format( request ))
        for k,v in cpppo.dotdict( result ).items():
            assert k in request and request[k] == v, \
                "%s: Didn't result in expected response: %s != %r; got %r" % (
                    description, k, v, request[k] if k in request else "(not found)" )

        # Finally, produce the encoded response
        encoded			= Obj.produce( request )
        assert encoded == response, "%s: Didn't produce correct encoded response: %r != %r" % (
            description, encoded, response )


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
    
    # Reply maximum size limited
    beg,end,endactual		= Obj.reply_elements( Obj_a1, data, 'read_frag' )
    assert beg == 0 and end == 125 and endactual == 1000 # DINT == 4 bytes
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 0 and end == 250 and endactual == 1000 # INT == 2 bytes

    data.read_frag.offset	= 125*4 # OK, second request; begin after byte offset of first
    beg,end,endactual		= Obj.reply_elements( Obj_a1, data, 'read_frag' )
    assert beg == 125 and end == 250 and endactual == 1000 # DINT == 4 bytes

    # Request elements limited; 0 offset
    data.read_frag.elements	= 30
    data.read_frag.offset	= 0
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 0 and end == 30 and endactual == 30 # INT == 2 bytes

    # Request elements limited; +'ve offset
    data.read_frag.elements	= 70
    data.read_frag.offset	= 80
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 40 and end == 70 and endactual == 70 # INT == 2 bytes

    # Request limited by size of data provided (Write Tag [Fragmented])
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
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'write_frag' )
    assert beg == 8 and end == 108 and endactual == 200 # INT == 2 bytes

    # ... same, but lets say request started somewhere in the middle of the array
    data.path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [
                                                         {'element': 222 },
                                                       ]] }
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'write_frag' )
    assert beg == 8+222 and end == 108+222 and endactual == 200+222 # INT == 2 bytes

    # Ensure correct computation of (beg,end] that are byte-offset and data/size limited
    data			= cpppo.dotdict()
    data.service		= Obj.WR_FRG_RPY
    data.path			= { 'segment': [] }

    data.write_frag		= {}
    data.write_frag.data	= [3,4,5,6]
    data.write_frag.offset	= 6
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'write_frag' )
    assert beg == 3 and end == 7 and endactual == 1000 # INT == 2 bytes

    # Trigger the error cases only accessible via write

    # Too many elements provided for attribute capacity
    data.write_frag.offset	= ( 1000 - 3 ) * 2
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'write_frag' )
        assert False, "Should have raised Exception due to capacity"
    except Exception as exc:
        assert "capacity exceeded" in str( exc )

    data			= cpppo.dotdict()
    data.service		= Obj.RD_FRG_RPY
    data.path			= { 'segment': [] }

    data.read_frag		= {}
    data.read_frag.offset	= 6
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 3 and end == 253 and endactual == 1000 # INT == 2 bytes

    # And we should be able to read with an offset right up to the last element
    data.read_frag.offset	= 1998
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 999 and end == 1000 and endactual == 1000 # INT == 2 bytes


    # Trigger all the remaining error cases

    # Unknown service
    data.service		= Obj.RD_FRG_REQ
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'read_frag' )
        assert False, "Should have raised Exception due to service"
    except Exception as exc:
        assert "unknown service" in str( exc )

    # Offset indivisible by element size
    data.service		= Obj.RD_FRG_RPY
    data.read_frag.offset	= 7
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'read_frag' )
        assert False, "Should have raised Exception due to odd byte offset"
    except Exception as exc:
        assert "element boundary" in str( exc )

    # Initial element outside bounds
    data.read_frag.offset	= 2000
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'read_frag' )
        assert False, "Should have raised Exception due to initial element"
    except Exception as exc:
        assert "initial element invalid" in str( exc )

    # Ending element outside bounds
    data.read_frag.offset	= 0
    data.read_frag.elements	= 1001
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'read_frag' )
        assert False, "Should have raised Exception due to ending element"
    except Exception as exc:
        assert "ending element invalid" in str( exc )

    # Beginning element after ending (should be no way to trigger).  This request doesn't specify an
    # element in the path, hence defaults to element 0, and asks for a number of elements == 2.
    # Thus, there is no 6-byte offset possible (a 2-byte offset is, though).
    data.read_frag.offset	= 6
    data.read_frag.elements	= 2
    try:
        beg,end,endactual	= Obj.reply_elements( Obj_a3, data, 'read_frag' )
        assert False, "Should have raised Exception due to ending element order"
    except Exception as exc:
        assert "ending element before beginning" in str( exc )
    data.read_frag.offset	= 2
    data.read_frag.elements	= 2
    beg,end,endactual		= Obj.reply_elements( Obj_a3, data, 'read_frag' )
    assert beg == 1 and end == 2 and endactual == 2 # INT == 2 bytes


    # Test an example valid multiple request
    data			= cpppo.dotdict()
    data.multiple		= {}
    data.multiple.request	= [
        cpppo.dotdict(), cpppo.dotdict(), cpppo.dotdict(), cpppo.dotdict(), cpppo.dotdict() ] 
    req				= data.multiple.request

    req[0].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'parts'}]] }
    req[0].read_tag		= {}
    req[0].read_tag.elements	= 1
    
    req[1].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'ControlWord'}]] }
    req[1].read_tag		= {}
    req[1].read_tag.elements	= 1

    req[2].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'number'}]] }
    req[2].read_tag		= {}
    req[2].read_tag.elements	= 1

    req[3].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'number'}]] }
    req[3].write_tag		= {}
    req[3].write_tag.elements	= 1
    req[3].write_tag.type	= 0x00ca
    req[3].write_tag.data	= [1.25]

    req[4].path			= { 'segment': [ cpppo.dotdict( d )
                                                 for d in [{'symbolic': 'number'}]] }
    req[4].read_tag		= {}
    req[4].read_tag.elements	= 1


    request			= Obj.produce( data )

    req_1			= bytes(bytearray([
        0x0A,
        0x02,
        0x20, 0x02, 0x24, 0x01,
        
        0x05, 0x00,
        
        0x0c, 0x00,
        0x18, 0x00,
        0x2a, 0x00,
        0x36, 0x00,
        0x48, 0x00,
        
        0x4C,
        0x04, 0x91, 0x05, 0x70, 0x61,
        0x72, 0x74, 0x73, 0x00,
        0x01, 0x00,
        
        0x4C,
        0x07, 0x91, 0x0B, 0x43, 0x6F,
        0x6E, 0x74, 0x72, 0x6F, 0x6C,
        0x57, 0x6F, 0x72, 0x64, 0x00,
        0x01, 0x00,

        b'L'[0],
        0x04, 0x91, 0x06, b'n'[0], b'u'[0], b'm'[0], b'b'[0], b'e'[0], b'r'[0],
        0x01, 0x00,

        b'M'[0],
        0x04, 0x91, 0x06, b'n'[0], b'u'[0], b'm'[0], b'b'[0], b'e'[0], b'r'[0],
        0xca, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x3f,

        b'L'[0],
        0x04, 0x91, 0x06, b'n'[0], b'u'[0], b'm'[0], b'b'[0], b'e'[0], b'r'[0],
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
    assert data.service == enip.device.Message_Router.MULTIPLE_REQ, \
        "Expected a Multiple Request Service request: %s" % enip.enip_format( data )
    assert data.multiple.number == 5, \
        "Expected 5 requests in request.multiple: %s" % enip.enip_format( data )

    # And ensure if we re-encode the parsed result, we get the original encoded request back
    assert Obj.produce( data ) == req_1

    # Process the request into a reply.
    Obj.request( data )
    log.normal( "Multiple Response: %s", enip.enip_format( data ))
    assert data.service == enip.device.Message_Router.MULTIPLE_RPY, \
        "Expected a Multiple Request Service reply: %s" % enip.enip_format( data )

    rpy_1			= bytearray([
        0x8A,
        0x00,
        0x00,
        0x00,

        0x05, 0x00,

        0x0c, 0x00,
        0x16, 0x00,
        0x20, 0x00,
        0x2a, 0x00,
        0x2e, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC4, 0x00,
        0x2A, 0x00, 0x00, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xC4, 0x00,
        0xDC, 0x01, 0x00, 0x00,

        0xCC, 0x00, 0x00, 0x00,
        0xCA, 0x00, 0x00, 0x00, 0x80, 0x3F,

        0xcd, 0x00, 0x00, 0x00,

        0xcc, 0x00, 0x00, 0x00,
        0xca, 0x00, 0x00, 0x00, 0xa0, 0x3f,
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

#@profile
def logix_test_once( obj, req ):
    req_source			= cpppo.peekable( req )
    req_data 			= cpppo.dotdict()
    with obj.parser as machine:
        for m,s in machine.run( source=req_source, data=req_data ):
            pass
    if log.isEnabledFor( logging.NORMAL ):
        log.normal( "Logix Request parsed: %s", enip.enip_format( req_data ))
    
    # If we ask a Logix Object to process the request, it should respond.
    processed			= obj.request( req_data )
    if log.isEnabledFor( logging.NORMAL ):
        log.normal( "Logix Request processed: %s", enip.enip_format( req_data ))

    # And, the same object should be able to parse the request's generated reply
    rpy_source			= cpppo.peekable( bytes( req_data.input ))
    rpy_data			= cpppo.dotdict()
    with obj.parser as machine:
        for i,(m,s) in enumerate( machine.run( source=rpy_source, data=rpy_data )):
            if log.isEnabledFor( logging.INFO ):
                log.info( "%s #%3d -> %10.10s; next byte %3d: %-10.10r: %r", m.name_centered(),
                          i, s, rpy_source.sent, rpy_source.peek(), rpy_data )

    if log.isEnabledFor( logging.NORMAL ):
        log.normal( "Logix Reply   processed: %s", enip.enip_format( rpy_data ))

    return processed,req_data,rpy_data


def logix_performance( repeat=1000 ):
    """Characterize the performance of the logix module, parsing and processing a large request, and
    then parsing the reply.  No network I/O is involved.

    """
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    Obj				= logix.Logix( instance_id=1 )

    size			= 1000
    Obj_a1 = Obj.attribute['1']	= enip.device.Attribute( 'Something', enip.parser.INT, default=[n for n in range( size )])

    assert len( Obj_a1 ) == size

    # Set up a symbolic tag referencing the Logix Object's Attribute
    enip.device.symbol['SCADA']	= {'class': Obj.class_id, 'instance': Obj.instance_id, 'attribute':1 }

    # Lets get it to parse a request, resulting in a 200 element response:
    #     'service': 			0x52,
    #     'path.segment': 		[{'symbolic': 'SCADA', 'length': 5}],
    #     'read_frag.elements':		201,
    #     'read_frag.offset':		2,

    req_1	 		= bytes(bytearray([
        0x52, 0x04, 0x91, 0x05, 0x53, 0x43, 0x41, 0x44, #/* R...SCAD */
        0x41, 0x00, 0xC9, 0x00, 0x02, 0x00, 0x00, 0x00, #/* A....... */
    ]))

    proc,req_data,rpy_data	= False,None,None
    while repeat > 0:
        proc,req_data,rpy_data	= logix_test_once( Obj, req_1 )
        repeat		       -= 1

    assert rpy_data.status == 0
    assert len( rpy_data.read_frag.data ) == 200
    assert rpy_data.read_frag.data[ 0] == 1
    assert rpy_data.read_frag.data[-1] == 200


# This number of repetitions is the point where the performance of pypy 2.1
# intersects with cpython 2.7/3.3 on my platform (OS-X 10.8 on a 2.3GHz i7:
# ~380TPS on a single thread.  Set thresholds low, for tests on slow hosts.
repetitions=250

@cpppo.assert_tps( 10, scale=repetitions )
def test_logix_performance():
    """Performance of parsing and executing an operation a number of times on an
    existing Logix object.

    """
    logix_performance( repeat=repetitions )

@cpppo.assert_tps( 10, repeat=repetitions )
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

def test_logix_remote_cpppo( count=100 ):
    """Performance of executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).

    """
    #logging.getLogger().setLevel( logging.NORMAL )
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    svraddr		        = ('localhost', 12345)
    kwargs			= {
        'argv': [
            #'-v',
            #'--log',		'/tmp/logix.log',
            #'--profile',	'/tmp/logix.prof',
            '--address',	'%s:%d' % svraddr,
            'SCADA=INT[1000]'
        ],
        'server': {
            'control': cpppo.apidict( enip.timeout, { 
                'done': False
            } ),
        },
    }
    logixthread_kwargs		= {
        'count':		count,
        'svraddr':		svraddr,
        'kwargs':		kwargs
    }

    log.normal( "test_logix_remote_cpppo w/ server.control in object %s", id( kwargs['server']['control'] ))
    # This is sort of "inside-out".  This thread will run logix_remote_cpppo, which will signal the
    # enip.main (via the kwargs.server...) to shut down.  However, to do line-based performance
    # measurement, we need to be running enip.main in the "Main" thread...
    logixthread			= threading.Thread( target=logix_remote_cpppo, kwargs=logixthread_kwargs )
    logixthread.daemon		= True
    logixthread.start()

    enip.main( **kwargs )

    logixthread.join()


def logix_remote_cpppo( count, svraddr, kwargs ):
  try:
    time.sleep(.25) # Wait for server to be established
    # Confirm that a known Register encodes as expected
    data			= cpppo.dotdict()
    data.enip			= {}
    data.enip.options		= 0
    data.enip.session_handle	= 0
    data.enip.status		= 0
    data.enip.sender_context	= {}
    data.enip.sender_context.input = bytearray( [0x00] * 8 )
    data.enip.CIP		= {}
    data.enip.CIP.register 	= {}
    data.enip.CIP.register.options 		= 0
    data.enip.CIP.register.protocol_version	= 1

    data.enip.input		= bytearray( enip.CIP.produce( data.enip ))
    data.input			= bytearray( enip.enip_encode( data.enip ))
    log.normal( "Register Request: %r" % data )
    
    assert bytes( data.input ) == rss_004_request

    # Try to Register a real session, followed by commands
    timeout			= 5

    begun			= cpppo.timer()
    cli				= client.client( host=svraddr[0], port=svraddr[1] )
    assert cli.writable( timeout=timeout )
    elapsed			= cpppo.timer() - begun
    log.normal( "Client Connected in  %7.3f/%7.3fs" % ( elapsed, timeout ))

    begun			= cpppo.timer()
    with cli:
        cli.register( timeout=timeout )
        data,elapsed		= client.await_response( cli, timeout=timeout )
    log.normal( "Client Register Rcvd %7.3f/%7.3fs: %r", elapsed, timeout, data )
    assert data is not None and 'enip.CIP.register' in data, "Failed to receive Register response"
    assert data.enip.status == 0, "Register response indicates failure: %s" % data.enip.status

    # Establish the EtherNet/IP "session handle" used by all further requests
    cli.session			= data.enip.session_handle

    start			= cpppo.timer()
    with cli:
        for _ in range( count ):
            begun		= cpppo.timer()
            cli.read( path=[{'symbolic': 'SCADA'}, {'element': 12}],
                      elements=201, offset=2, timeout=timeout )
            data,elapsed	= client.await_response( cli, timeout=timeout )
            log.detail( "Client ReadFrg. Rcvd %7.3f/%7.3fs: %r", elapsed, timeout, data )

    duration			= cpppo.timer() - start
    log.warning( "Client ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    log.normal( "Signal shutdown w/ server.control in object %s", id( kwargs['server']['control'] ))
  finally:
    kwargs['server']['control'].done= True # Signal the server to terminate


@pytest.mark.skipif( not has_pylogix, reason="Needs pylogix" )
def test_logix_remote_pylogix( count=100 ):
    """Performance of pylogix executing an operation a number of times on a socket connected
    Logix simulator, within the same Python interpreter (ie. all on a single CPU
    thread).  Only connects on the standard port.

    """
    #logging.getLogger().setLevel( logging.NORMAL )
    enip.lookup_reset() # Flush out any existing CIP Objects for a fresh start
    svraddr		        = ('localhost', 44818)
    kwargs			= {
        'argv': [
            #'-v',
            #'--log',		'/tmp/pylogix.log',
            #'--profile',	'/tmp/plogix.prof',
            '--address',	'%s:%d' % svraddr,
            'SCADA=INT[1000]'
        ],
        'server': {
            'control': cpppo.apidict( enip.timeout, { 
                'done': False
            } ),
        },
    }
    logixthread_kwargs		= {
        'count':		count,
        'svraddr':		svraddr,
        'kwargs':		kwargs
    }

    log.normal( "test_logix_remote_pylogix w/ server.control in object %s", id( kwargs['server']['control'] ))
    # This is sort of "inside-out".  This thread will run logix_remote, which will signal the
    # enip.main (via the kwargs.server...) to shut down.  However, to do line-based performance
    # measurement, we need to be running enip.main in the "Main" thread...
    logixthread			= threading.Thread( target=logix_remote_pylogix, kwargs=logixthread_kwargs )
    logixthread.daemon		= True
    logixthread.start()

    enip.main( **kwargs )

    logixthread.join()


def logix_remote_pylogix( count, svraddr, kwargs ):
  try:
    time.sleep(.25) # Wait for server to be established

    # Try to Register a real session, followed by commands
    timeout			= 5

    with pylogix.PLC() as comm:
        comm.SocketTimeout	= timeout
        comm.IPAddress		= enip.address[0]
        comm.ConnectionSize	= 4000

        # CIP Register, Forward Open
        start			= cpppo.timer()
        conn			= comm.conn.connect()
        #assert not conn[0], "Failed to connect via pylogix"
        elapsed			= cpppo.timer() - start
        log.normal( "Client Register Rcvd %7.3f/%7.3fs: %r", elapsed, timeout, conn )

        # count x Logix Read Tag [Fragmented] 201-element reads, starting at element 12
        start			= cpppo.timer()
        for _ in range( count ):
            reply		= comm.Read( 'SCADA[12]', 201 )
            elapsed		= cpppo.timer() - start
            data		= reply.Value
            log.detail( "Client ReadFrg. Rcvd %7.3f/%7.3fs: %r", elapsed, timeout, data )

        duration		= cpppo.timer() - start
        log.warning( "Client ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    log.normal( "Signal shutdown w/ server.control in object %s", id( kwargs['server']['control'] ))
  finally:
    kwargs['server']['control'].done= True # Signal the server to terminate


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

    # To profile using line_profiler: kernprof.py -v -l logix_test.py
    repetitions=250
    count			= repetitions

    start			= cpppo.timer()
    logix_performance( repeat=count )
    duration			= cpppo.timer() - start
    log.warning( "Local  ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    '''

    # Profile the main thread
    import cProfile
    import pstats
    prof_file			= "logix_test.profile"

    start			= cpppo.timer()
    cProfile.run( "logix_performance( repeat=%d )" % repetitions, prof_file )
    duration			= cpppo.timer() - start
    log.warning( "Local  ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))

    prof			= pstats.Stats( prof_file )
    print( "\n\nTIME:")
    prof.sort_stats(  'time' ).print_stats( 100 )
    print( "\n\nCUMULATIVE:")
    prof.sort_stats(  'cumulative' ).print_stats( 100 )
    '''

#    test_logix_remote( count=100 )

