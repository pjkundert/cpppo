from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import contextlib
import copy
import json
import logging
import os
import pytest
import sys
import threading
import time

from ...automata import log_cfg, peekable
from ...dotdict import dotdict, apidict
from ... import misc
from .main import main as enip_main
from . import defaults, udt, parser, device, logix, ucmm

# Set up logging to use our log format (instead of default Pytest format), while
# retaining any logging level eg. python -m pytest --log-cli-level=25 ...
logging.getLogger().handlers[0].setFormatter( logging.Formatter( log_cfg['format'] ))

try:
    import reprlib
except ImportError:
    import repr as reprlib

has_pylogix			= False
try:
    import pylogix
    has_pylogix			= True
except Exception:
    pass

log				= logging.getLogger( 'udt_test' )

example_tagname			= "ExampleSensor"
example_tags_json		= os.path.join( os.path.dirname( __file__ ), 'udt_test', example_tagname + "-tags.json" )
example_vals_json		= os.path.join( os.path.dirname( __file__ ), 'udt_test', example_tagname + "-vals.json" )
example_data_dump		= os.path.join( os.path.dirname( __file__ ), 'udt_test', example_tagname + ".hexdump" )


# The CIP address uses by the pycomm3 I/O is actually CIP Class 0x6B, Instance 0x0008, NO Attribute
# specified, Element/Member 0.  This must imply a (default) Instance number of 1 (since instance 0
# specifies the "meta-Class" Instance.)  TODO: Cpppo doesn't currently support this "assumption" of
# Instance number in a numeric CIP-addressed request; use a Tag name, or a fully specified (to the
# Instance level) CIP address.
example_enip_addr		= (0x6B, 0x0008, 1)

def load_data_from_pcap():
    with open( example_data_dump, 'r' ) as f:
        return b''.join( data for addr,data in misc.hexloader( f ))


def tagtype_from_tags_json( tagname ):
    tagtype			= None
    with open( example_tags_json ) as f:
        tags			= json.loads( f.read() )
    for k in tags.keys():
        if k.endswith( tagname ):
            tagtype		= tags[k]
    assert tagtype, \
        "Didn't find {tagname} in {keys}".format(
            tagname=tagname, keys=list( tags.keys() ))
    return tagtype


def parse_check_tag_records( tagdata, tagname, tagtype ):
    """Encode the tag according to its UDT type, returning the decoded Tag records, plus the re-encoded
    binary tag value.

    """
    with open( example_vals_json ) as f:
        original		= json.loads( f.read() )

    elmcoder			= udt.tag_struct()
    elmtype			= tagtype["data_type"] 
    rec_cnt			= tagtype["dimensions"][0]
    rec_siz			= tagtype["data_type"]["template"]["structure_size"]

    tagrecords			= []
    tagencoding			= b''
    for i in range( rec_cnt ):
        rec			= tagdata[i*rec_siz:(i+1)*rec_siz]
        log.info( "{i:>5}:\n{dump}\n".format( i=i, dump=misc.hexdump( rec )))

        # Extract the record's Tag struct details, and compare against known decoded records in
        # original.  Parse/produce using STRUCT_typed, one UDT instance at a time.  Collect decoded
        # records into tagrecords list (eg. for an enip.Attribute simulator's default data).  This
        # uses the same APIs as enip.Attribute to de/encode between raw data and the UDT's dict
        # structures.
        parser			= udt.STRUCT_typed( name=tagname, data_type=tagtype )
        
        record			= dotdict()
        with parser as machine:
            with contextlib.closing( machine.run( source=peekable( rec ), data=record )) as engine:
                for m,s in engine:
                    pass
        log.info( "Parsed w/ STRUCT_typed: {record!r}".format( record=record ))
        for itn,val in original[i].items():
            new			= record.get( itn )
            if new == val:
                log.detail( "{itn:<32} == {new!r}".format( itn=itn, new=new ))
            else:
                log.warning( "{itn:<32} == {new!r} != {val}".format( itn=itn, new=new, val=val ))

        # Reproduce the record's data.input, ensuring it matches the original rec data.  We expect
        # differences, here, but they should be limited to not reproducing junk data after the end
        # of STRINGs' LEN in their DATA (ie. junk left over from previous, longer STRING values).
        out			= parser.produce( record )
        encoded			= out == rec
        if encoded:
            log.detail( "{tagname}[{i}] ENCODING MATCHES (STRUCT_typed)".format( tagname=tagname, i=i ))
        else:
            out_dump		= misc.hexdump( out, length=8 )
            rec_dump		= misc.hexdump( rec, length=8 )
            rec_vs_out		= misc.hexdump_differs(
                rec_dump, out_dump, inclusive=log.isEnabledFor( logging.DETAIL ) )
            log.normal( "{tagname}[{i}] ENCODING DIFFERS (STRUCT_typed):\n{rec_vs_out}\n".format(
                tagname=tagname, i=i, rec_vs_out=rec_vs_out ))

        tagrecords.append( record )
        tagencoding	       += out

    return tagrecords,tagencoding


@pytest.mark.skipif( not has_pylogix, reason="Needs pylogix" )
def test_logix_remote_udt( count=1 ):
    """Performance of a client executing an operations on a CIP UDT.

    """

    # Flush out any existing CIP Objects for a fresh start, including UCMM
    device.lookup_reset()
    logix.setup_reset()

    svraddr		        = ('localhost', 44838)

    tagname			= example_tagname
    tagaddr			= example_enip_addr
    # 
    # Load ExampleSensor attribute raw data into tagdata from the PCAP dump
    # 
    tagdata			= load_data_from_pcap()

    # 
    # Load the Tag structure data, and discover the tagdata record size, count etc., and confirm size
    #
    tagtype			= tagtype_from_tags_json( tagname )

    rec_cnt			= tagtype["dimensions"][0]
    rec_siz			= tagtype["data_type"]["template"]["structure_size"]
    rec_name			= tagtype["data_type"]["name"]
    log.normal( "Loaded {tagdata_len} bytes of {rec_name} record data, in {rec_cnt} x {rec_siz} bytes/UDT".format(
        tagdata_len=len( tagdata ), rec_name=rec_name, rec_cnt=rec_cnt, rec_siz=rec_siz ))
    assert rec_siz * rec_cnt == len( tagdata ), \
        "Incorrect record count {rec_cnt} x size {rec_siz} != {tagdata_len}".format(
            tagdata_len=len( tagdata ), rec_cnt=rec_cnt, rec_siz=rec_siz )

    # 
    # Parse each ExampleSensor UDT from the raw bytes in tagdata, test against known vals
    #
    tagrecords,tagencoding	= parse_check_tag_records( tagdata, tagname, tagtype )

    # 
    # Intercept all server requests, and collect requests/replies locally
    #
    server_txs			= []

    class UCMM_collector( ucmm.UCMM ):
        """Collect the data (request), and its modified response.  Returns the "proceed" flag (or
        re-raises Exception)

        """
        def request( self, data, addr=None ):
            #log.info( "UCMM collector: {addr!r:24} {req:s}".format( addr=addr, req=reprlib.repr( data )))
            req			= None
            try:
                req		= copy.deepcopy( data )
                proceed		= super( UCMM_collector, self ).request( data=data, addr=addr )
                rpy		= copy.deepcopy( data )
                server_txs.append( (addr,req,rpy) )
            except Exception as exc:
                server_txs.append( (addr,req,exc) )
                raise
            else:
                return proceed

    # 
    # Package the device.Attribute **kwds to support STRUCT_typed backed elements, including initial
    # default tag data.
    # 
    type_cls			= lambda: udt.STRUCT_typed(
        data_type	= tagtype
    )
    attribute_kwds		= dict(
        name		= tagname,
        type_cls	= type_cls,
        default		= tagrecords
    )
    latency		= 1.0
    timeout		=10.0
    
    kwargs			= dict(
        argv		= [
            #'-v',
            #'--log',		'/tmp/pylogix.log',
            #'--profile',	'/tmp/plogix.prof',
            '--address',	'%s:%d' % svraddr,
            "{tagname}{tagaddr}".format(
                tagname	= tagname,
                tagaddr	= '@'+'/'.join( map( hex, tagaddr )) if tagaddr else '',
            ),
        ],
        server		= dict(
            control	= apidict( timeout, dict(
                done		= False,
                latency		= latency,
                timeout		= timeout,
            )),
            server_txs	= server_txs,		# Allow the client to see server's requests/responses
        ),
        client		= dict(),
        UCMM_class	= UCMM_collector,
        attribute_kwds	= attribute_kwds,
        enip_process	= logix.process,	# The default, but be explicit
    )
    targetthread_kwargs		= dict(
        count		= count,
        svraddr		= svraddr,
        kwargs		= kwargs,		# Allow client thread to shut enip_main server down
    )

    try:
        for target in [
                logix_remote_udt_pylogix
        ]:
            # This is sort of "inside-out".  This thread will run logix_remote..., which will signal
            # the enip_main (via the kwargs.server...) to shut down.  However, to do line-based
            # performance measurement, we need to be running enip.main:main in the "Main" thread...
            kwargs['server']['control'].done = False
            kwargs['client'] = {}
            log.normal( "test_logix_remote_udt w/ controls in object server: %s (txs %s, %d txs), client: %s",
                        id( kwargs['server'] ),
                        id( kwargs['server']['server_txs'] ), len( kwargs['server']['server_txs'] ),
                        id( kwargs['client'] ))
            targetthread= threading.Thread(
                target	= target,
                kwargs	= targetthread_kwargs,
            )
            targetthread.daemon	= True
            targetthread.start()
            log.normal( "Startup  of C*Logix client {client_name} complete".format( client_name=target.__name__ ))

            # Run the server; each client will signal it to shut down when finished transacting with it.
            enip_main( **kwargs )

            targetthread.join()
            log.normal( "Shutdown of C*Logix client complete" )

            # Now that the targetthread (the C*Logix client) is complete, we can check what it got.
            # We expect that it should have received the full STRUCT tag encoding, and successfully
            # completed its tests.
            client_got		= kwargs['client'].get( 'received', None )
            client_ok		= kwargs['client'].get( 'successful', None )
            log.normal( "Client received {length}-byte: {got}".format(
                length=len(client_got) if client_got else "(Unknown)", got=reprlib.repr( client_got )))
            assert client_got == tagencoding
            assert client_ok == True
    finally:
        # In case of Exception, ensure we've shut down the server...
        kwargs['server']['control'].done = True
    log.normal( "Shutdown of server complete" )


def logix_remote_udt_pylogix( count, svraddr, kwargs ):
    """Pylogix access of UDT STRUCT. """
    tagname			= example_tagname

    time.sleep( 1 ) # Wait for server to be established

    # We'll check our server transactions (that they're sensible), and also send back what we got...
    server_txs			= kwargs['server']['server_txs']
    server_txs_beg		= len( server_txs ) # in case the same server is used for many clients
    log.normal( "logix_remote_udt_pylogix w/ controls in object server: %s (txs %s, %d txs), client: %s",
                        id( kwargs['server'] ),
                        id( kwargs['server']['server_txs'] ), len( kwargs['server']['server_txs'] ),
                        id( kwargs['client'] ))
    try:
        # Try to Register a real session, followed by commands
        timeout			= kwargs['server']['control'].timeout
        client_got		= None
        with pylogix.PLC() as comm:
            comm.SocketTimeout	= timeout
            comm.IPAddress	= svraddr[0]

            comm.conn.Port	= int( svraddr[1] )

            # CIP Register, Forward Open
            start		= misc.timer()
            conn		= comm.conn.connect()
            #assert not conn[0], "Failed to connect via pylogix"
            elapsed		= misc.timer() - start
            log.normal( "Client Register Rcvd %7.3f/%7.3fs: %r", elapsed, timeout, conn )

            # count x Logix Read Tag [Fragmented] 360-element reads, starting at element 0
            start		= misc.timer()
            for _ in range( count ):
                reply		= comm.Read( "{tagname}[0]".format( tagname=tagname ), 360 )
                client_got	= reply.Value
            duration		= misc.timer() - start
            log.warning( "Client ReadFrg. Average %7.3f TPS (%7.3fs ea)." % ( count / duration, duration / count ))
            log.normal( "Client ReadFrg. Rcvd: %s", reprlib.repr( client_got ))

        kwargs['client']['received'] = client_got

        # Check that server processed correct commands (first and last few), return what the client
        # got...  We'll see the EtherNet/IP register, Forward Open, Read Tag Fragmented w/ offset 0
        # status 6, and high offset, status 0, forward close, EtherNet/IP unregister.
        kwargs['server']['control'].done = True

        cases			= [
            {
                "enip.CIP.register.options": 0,
            }, {
                # The default forward_open connection size should be ~4002, but should be Large
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_open.O_T.large": True,
            }, {
                # Initial Pylogix Read Tag Fragmented is of a single element (to test Tag type)
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.offset": 0,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.elements": 1,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.type": 672,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.structure_tag": 36345,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.status": 6, 
            }, {
                # Then, starts with a Read Tag
                "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[1].element": 0,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_tag.elements": 360,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_tag.type": 672,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_tag.structure_tag": 36345,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.status": 6,
            }, {
                # Continuing with Read Tag Fragmented, if necessary
                "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[0].symbolic": "ExampleSensor",
                "enip.CIP.send_data.CPF.item[1].connection_data.request.path.segment[1].element": 0,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.elements": 360,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.offset": 215696, # w/ 488 byte MAX_BYTES
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.type": 672,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.read_frag.structure_tag": 36345,
                "enip.CIP.send_data.CPF.item[1].connection_data.request.status": 0,
            }, {
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.forward_close.application.size": 0,
                "enip.CIP.send_data.CPF.item[1].unconnected_send.request.status": 0,
            }, {
                "enip.CIP.unregister": True,
            }
        ]
        log.normal( "Testing {server_txs_cnt} Server txs vs. {cases_cnt} test cases".format(
            server_txs_cnt=len( server_txs ) - server_txs_beg, cases_cnt=len( cases )))
        for num,(addr,req,rpy) in enumerate( server_txs ):
            if num < server_txs_beg or server_txs_beg + 5 <= num <= len( server_txs ) - 5:
                continue
            # See if this reply matches one of our cases; delete if so
            for i,c in enumerate( cases ):
                if all( rpy.get( k ) == v for k,v in c.items() ):
                    del cases[i]
                    break
        if cases:
            log.warning( "Failed to find cases {cases!r}".format( cases=cases ))
            for num,(addr,req,rpy) in enumerate( server_txs ):
                if num < server_txs_beg or server_txs_beg + 5 <= num <= len( server_txs ) - 5:
                    continue
                log.detail( "UDT req {num:3d}: {addr!r:24}: {req}".format( num=num, addr=addr, req=parser.enip_format( req )))
                log.normal( "UDT rpy {num:3d}: {addr!r:24}: {rpy}".format( num=num, addr=addr, rpy=parser.enip_format( rpy )))

        assert cases == []
        kwargs['client']['successful'] = True

    finally:
        kwargs['server']['control'].done = True
