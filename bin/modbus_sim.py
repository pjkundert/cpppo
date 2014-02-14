#!/usr/bin/env python

from __future__ import print_function

'''
modbus-sim.py -- A Modbus PLC Simulator, with various simulated failure modes

    A simple Modbus/TCP PLC simulator.  Based on the pymodbus Synchronous APIs.
    Requires the Python "pymodbus" library:

        http://github.com/bashwork/pymodbus


OPTIONS

  --address <addr>[:port]	Address to bind to (default all, port 502)

  --range N			Try binding to up to N ports if not successful

    If you are running multiple tests, automatically tries binding to other
    ports.  Primarily useful if you are automating bulk unit tests against
    multiple simulated PLCs.

  --evil ...    		Various evil PLC antics (timeouts, corruptions, ...)

    Implements various PLC failure modes, for testing Modbus client error handling.

    truncate         -- return only part of the response
    delay[:#.#]      -- delay response by #.# seconds (default == 5)
    corrupt[:<shat>] -- corrupt Modbus/TCP protocol response (default == "transaction")
       :transaction    -- Transaction ID
       :protocol       -- Protocol ID
       :unit           -- Unit number
       :function       -- Function code
       :registers      -- Amount of response data

  <begin>-<end>[=<val>[,<val>]] Ranges of registers to serve, and their initial value(s)

    If a range of registers is specified, the provided <val>[,<val>] provided is
    duplicated to fill the range.  Alternatively, if just a <begin> is provided,
    the <end> is deduced from the number of values provided (a default value of
    0 is assumed).

EXAMPLE

  modbus-sim.py --address localhost:7502 --evil delay:2.5  40001-40100

    Starts a simulated PLC serving Holding registers 40001-40100 == 0, on port 7502
    on interface 'localhost', which delays all responses for 2.5 seconds.

'''
import os
import sys
import traceback
import random
import time
import socket
import struct
import logging
import repr
import argparse

#---------------------------------------------------------------------------# 
# import the various server implementations
#---------------------------------------------------------------------------# 
from pymodbus.server.sync import StartTcpServer
from pymodbus.server.sync import StartUdpServer
from pymodbus.server.sync import ModbusTcpServer

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSparseDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.constants import Defaults
from pymodbus.register_read_message import ReadRegistersResponseBase
from pymodbus.register_write_message import WriteSingleRegisterResponse, WriteMultipleRegistersResponse

from pymodbus.transaction import *
from pymodbus import constants

#---------------------------------------------------------------------------# 
# configure the service logging
#---------------------------------------------------------------------------# 

log 			= logging.getLogger( 'modbus_sim' )

def registers_context( registers ):
    """
    --------------------------------------------------------------------------
    initialize your data store, returning an initialized ModbusServerConext
    --------------------------------------------------------------------------
    The datastores only respond to the addresses that they are initialized to.
    Therefore, if you initialize a DataBlock to addresses of 0x00 to 0xFF, a
    request to 0x100 will respond with an invalid address exception. This is
    because many devices exhibit this kind of behavior (but not all)::
    
        block = ModbusSequentialDataBlock(0x00, [0]*0xff)
    
    Continuting, you can choose to use a sequential or a sparse DataBlock in
    your data context.  The difference is that the sequential has no gaps in
    the data while the sparse can. Once again, there are devices that exhibit
    both forms of behavior::
    
        block = ModbusSparseDataBlock({0x00: 0, 0x05: 1})
        block = ModbusSequentialDataBlock(0x00, [0]*5)
    
    Alternately, you can use the factory methods to initialize the DataBlocks
    or simply do not pass them to have them initialized to 0x00 on the full
    address range::
    
        store = ModbusSlaveContext(di = ModbusSequentialDataBlock.create())
        store = ModbusSlaveContext()
    
    Finally, you are allowed to use the same DataBlock reference for every
    table or you you may use a seperate DataBlock for each table. This depends
    if you would like functions to be able to access and modify the same data
    or not::
    
        block = ModbusSequentialDataBlock(0x00, [0]*0xff)
        store = ModbusSlaveContext(di=block, co=block, hr=block, ir=block)
    --------------------------------------------------------------------------
    eg.:
    
    store = ModbusSlaveContext(
        di = ModbusSequentialDataBlock(0, [0]*1000),
        co = ModbusSequentialDataBlock(0, [0]*1000),
        hr = ModbusSequentialDataBlock(0, [0]*10000),
        ir = ModbusSequentialDataBlock(0, [0]*1000))
    context = ModbusServerContext(slaves=store, single=True)
    
    
    Parse the register ranges, as: registers[, registers ...], and produce a
    keywords dictionary suitable for passing to ModbusSlaveContext, containing
    ModbusSparseDataBlock instances, for 'hr' (Holding Registers), 'co' (Coils),
    etc.:
    
        40001=999
    
    produces:
    
         hr = ModbusSparseDataBlock({ 0: 999 }),
    
        1-10000		Coils
    10001-30000		Input  Coils
    30001-40000		Input   Registers
    40001-		Holding Registers
    
    Allow:
        <begin>[-<end>][=<val>[,<val>]] ...
    """
    def registers_parse( txt ):
        """ Tokenizer yields integers; any other character, one at a time. """
        b, i, e 			= 0, 0, len( txt )
        while i <= e:
            if i == e or not( '0' <= txt[i] <= '9' ):
                if i > b:
                    yield int( txt[b:i] )  		# "123..."   Parsed 1+ digits
                    b, i 		= i, i-1
                elif i < e:
                    yield txt[b]           		# "?..."     Something else
                    b, i 		= i+1, i
            i 		       += 1                           
    
    # Parse register ranges
    # 0  10001 30001 40001
    cod,   did,  ird,  hrd 		= {}, {}, {}, {}
    for txt in registers:
        prs 			= registers_parse( txt )
        beg = end 			= None
        val 			= []
        try:
            beg 			= prs.next()
            end 			= beg
            end 			= prs.next()
            if end == '-':
                end 		= prs.next()		# <beg>-<end>=
                equ 		= prs.next()
            elif end == '=':
                equ 		= end			# <beg>=
                end 		= beg
            else:
                assert end == '-'			# Unknown range operator
            assert equ == '='
            while True:
                val 	       += [prs.next()]
                assert type( val[-1] ) == int
                assert prs.next() == ','
        except StopIteration:
            assert type( beg ) is int
            if end is None:
                end 		= beg
            assert type( end ) is int
            # Extend <beg>-<end> out to the number of values, or extend val to the
            # range length; duplicate entries and/or truncates to range length
            if not val:
                val 		= [0]
            if end == beg:
                end 		= beg + len( val ) - 1
            if len( val ) < end - beg + 1:
                val 	       *= (( end - beg + 1 ) / len( val ) + 1 )
            val 			= val[:end - beg + 1]
            log.info( "%05d-%05d = %s" % ( beg, end, repr.repr( val )))
            for reg in xrange( beg, end + 1 ):
                dct, off 	= (     ( hrd, 40001 ) if reg >= 40001
                                   else ( ird, 30001 ) if reg >= 30001
                                   else ( did, 10001 ) if reg >= 10001
                                   else ( cod,     1 ))
                dct[reg - off] 	= val[reg - beg]
        except Exception as exc:
            log.error( "Unrecognized registers '%s': %s" % ( txt, str( exc )))
            raise
        log.info( "Holding Registers: %s" % ( repr.repr( hrd )))
        log.info( "Input   Registers: %s" % ( repr.repr( ird )))
        log.info( "Output  Coils:     %s" % ( repr.repr( cod )))
        log.info( "Discrete Inputs:   %s" % ( repr.repr( did )))
    store = ModbusSlaveContext(
        di = ModbusSparseDataBlock( did ) if did else None,
        co = ModbusSparseDataBlock( cod ) if cod else None,
        hr = ModbusSparseDataBlock( hrd ) if hrd else None,
        ir = ModbusSparseDataBlock( ird ) if ird else None )
    return ModbusServerContext( slaves=store, single=True )
    

#---------------------------------------------------------------------------#
# Evil Framers
#---------------------------------------------------------------------------#
class ModbusSocketFramerTruncateResponse(ModbusSocketFramer):
    def buildPacket(self, message):
        ''' Creates a *truncated* ready to send modbus packet.  Truncates from 1
        to all of the bytes, before returning response.

        :param message: The populated request/response to send
        '''
        packet 			= ModbusSocketFramer.buildPacket( self, message )
        datalen			= len( packet )
        corrlen			= datalen - random.randint( 1, datalen )

        log.info("Corrupting response; truncating from %d to %d bytes" % ( datalen, corrlen ))

        return packet[:corrlen]

class ModbusSocketFramerDelayResponse(ModbusSocketFramer):
    delay			= 5

    def buildPacket(self, message):
        ''' Creates a ready to send modbus packet but delays the return.

        :param message: The populated request/response to send
        '''
        packet 			= ModbusSocketFramer.buildPacket( self, message )

        log.info("Delaying response for %s seconds" % ( self.delay ))
        time.sleep( self.delay )

        return packet

class ModbusSocketFramerCorruptResponse(ModbusSocketFramer):
    what			= "transaction"

    def buildPacket(self, message):
        ''' Creates a *corrupted* ready to send modbus packet.  Truncates from 1
        to all of the bytes, before returning response.

        :param message: The populated request/response to send

        WARNING: pymodbus seems to swallow any exceptions thrown by these
        methods.  This seems like a defect; it should log them, at least.
        '''
        try:
            log.info("Encoding package")
            data		= message.encode()
            tran_id		= message.transaction_id
            prot_id		= message.protocol_id
            unit_id		= message.unit_id
            func_code		= message.function_code

            if self.what == "transaction":
                tran_id	       ^= 0xFFFF
            elif self.what == "registers":
                if isinstance( message, ReadRegistersResponseBase ):
                    # These have '.registers' attribute, which is a list.
                    # Add/remove some
                    saveregs	= message.registers
                    if len( message.registers ) == 0 or random.randint( 0, 1 ):
                        message.registers += [999]
                    else:
                        message.registers = message.registers[:-1]
                    data	= message.encode()
                    message.registers = saveregs
                elif isinstance( message, WriteSingleRegisterResponse ):
                    # Flip the responses address bits and then flip them back.
                    message.address    ^= 0xFFFF
                    data	= message.encode()
                    message.address    ^= 0xFFFF
                elif isinstance( message, WriteMultipleRegisterResponse ):
                    # Flip the responses address bits and then flip them back.
                    message.address    ^= 0xFFFF
                    data	= message.encode()
                    message.address    ^= 0xFFFF
                else:
                    raise NotImplementedException(
                        "Unhandled class for register corruption; not implemented" )
            elif self.what == "protocol":
                prot_id	       ^= 0xFFFF
            elif self.what == "unit":
                unit_id	       ^= 0xFF
            elif self.what == "function":
                func_code      ^= 0xFF
            else:
                raise NotImplementedException(
                    "Unknown corruption specified; not implemented" )

            log.info("Create corrupted package")

            # original build packet code
            packet = struct.pack('>HHHBB',
                tran_id,
                prot_id,
                len(data) + 2,
                unit_id,
                func_code ) + data
            
            log.info("Returning corrupted package")
        except Exception as exc:
            log.info("Could not build corrupt packet: %s" % ( traceback.format_exc() ))
        return packet


#---------------------------------------------------------------------------#
# Creation Factories
#---------------------------------------------------------------------------#
def StartTcpServerLogging( context=None, identity=None, framer=ModbusSocketFramer, address=None ):
    ''' A factory to start and run a tcp modbus server

    :param context: The ModbusServerContext datastore
    :param identity: An optional identify structure
    :param address: An optional (interface, port) to bind to.
    '''
    server = ModbusTcpServer(context, framer, identity, address)
    # Print the address successfully bound; this is useful, if attempts are made
    # to bind over a range of ports.
    print( "Success; Started Modbus/TCP Simulator; PID = %d; address = %s:%s" % (
        os.getpid(), address[0] if address else "", address[1] if address else Defaults.Port ))
    sys.stdout.flush()
    server.serve_forever()


def main():
    parser			= argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = """\
    The --evil option takes the following :
      truncate         -- return only part of the response
      delay[:#.#]      -- delay response by #.# seconds (default == 5)
      corrupt[:<shat>] -- corrupt Modbus/TCP protocol response (default == "transaction")
         :transaction    -- Transaction ID
         :protocol       -- Protocol ID
         :unit           -- Unit number
         :function       -- Function code
         :registers      -- Amount of response data
    
    Register range(s) and value(s) must be supplied:
    
      <begin>[-<end>][=<val>[,<val>]]
    
    EXAMPLE
    
      modbus-sim.py --address localhost:7502 --evil delay:2.5 40001-40100
    
        Starts a simulated PLC serving Holding registers 40001-40100 == 0, on port 7502
        on interface 'localhost', which delays all responses for 2.5 seconds.
    
    """ )
    parser.add_argument( '-v', '--verbose',
                         default=1, action="count", help="Display logging information." )
    parser.add_argument('-l', '--log', 
                        type=str, default=None, help="Direct log output to the specified file" )
    parser.add_argument( '-a', '--address', default="0.0.0.0:502",
                         help="Default [interface][:port] to bind to (default: any, port 502)" )
    parser.add_argument( '-r', '--range',	default=1,
                         help="Number of ports to try, if busy       (default: 1)" )
    parser.add_argument( '-e', '--evil',	default=None,
                         help="Evil Modbus/TCP protocol framer       (default: None)" )
    parser.add_argument( 'registers', nargs="+" )
    args			= parser.parse_args()
    
    # Deduce logging level and target file (if any)
    levelmap 			= {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    level			= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )
    
    logging.basicConfig( level=level, filename=args.log,
        format='%(asctime)s.%(msecs).03d %(threadName)10.10s %(name)-15.15s %(funcName)-15.15s %(levelname)-8.8s %(message)s' )
    
    #---------------------------------------------------------------------------# 
    # run the server you want
    #---------------------------------------------------------------------------# 
    
    # Deduce interface:port to bind, and correct types.  Interface defaults to ''
    # (INADDR_ANY) if only :port is supplied.  Port defaults to 502 if only
    # interface is supplied.  After this block, 'address' is always a tuple
    # like ("interface",502)
    address			= None
    if args.address:
        address			= args.address.split(':')
        assert 1 <= len( address ) <= 2
        address			= (
            str( address[0] ),
            int( address[1] ) if len( address ) > 1 else Defaults.Port )
        log.info( "--server '%s' produces address=%r" % (args.address, address ))

    framer			= None
    if args.evil == "truncate":
        framer			= ModbusSocketFramerTruncateResponse
        log.info( "--evil '%s' uses ModbusSocketFramerTruncateResponse" % ( args.evil ))
    elif args.evil and args.evil.startswith('delay'):
        framer			= ModbusSocketFramerDelayResponse
        # If a "--evil delay:1.5" is provided, pull out the number and change
        # the ModbusSockerFramerDelayResponse class' .delay value to the specified
        # number of seconds
        req			= args.evil.split(":", 1)
        assert 1 <= len( req ) <= 2
        if len( req ) == 2:
            ModbusSocketFramerDelayResponse.delay = float( req[1] )
        log.info( "--evil '%s' uses ModbusSocketFramerDelayResponse, which delays responses for %s seconds" % (
                args.evil, ModbusSocketFramerDelayResponse.delay ))
    elif args.evil and args.evil.startswith('corrupt'):
        framer			= ModbusSocketFramerCorruptResponse
        # If a "--evil corrupt:<what>" is provided, corrupt the specified entry.
        req			= args.evil.split(":", 1)
        assert 1 <= len( req ) <= 2
        if len( req ) == 2:
            ModbusSocketFramerCorruptResponse.what = req[1]
        log.info( "--evil '%s' uses ModbusSocketFramerCorruptResponse, which corrupts the responses %s entry" % (
                args.evil, ModbusSocketFramerCorruptResponse.what ))
    elif args.evil:
        log.error("Unrecognized --evil argument: %s" % args.evil )
        return 1

    #---------------------------------------------------------------------------#
    # Start the PLC simulation engine on a port in the range; will serve forever
    #---------------------------------------------------------------------------#
    for port in xrange( address[1], address[1] + int( args.range )):
        address			= (address[0], port)
        try:
            StartTcpServerLogging( registers_context( args.registers ), framer=framer, address=address )
        except KeyboardInterrupt:
            return 1
        except Exception as exc:
            log.info( "Couldn't start PLC simulator on %s:%s: %s" % (
                    address[0], address[1], traceback.format_exc()))
    
    log.error( "Failed to start PLC simulator on %s, over a range of %s ports" % (
            args.address, args.range ))
    return 1

if __name__ == "__main__":
    sys.exit( main() )
