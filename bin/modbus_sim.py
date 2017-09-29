#!/usr/bin/env python

# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

'''
modbus_sim.py -- A Modbus PLC Simulator, with various simulated failure modes

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

  modbus_sim.py --address localhost:7502 --evil delay:2.5  40001-40100

    Starts a simulated PLC serving Holding registers 40001-40100 == 0, on port 7502
    on interface 'localhost', which delays all responses for 2.5 seconds.

'''
import argparse
import json
import logging
import os
import random
import sys
import time
import traceback

#---------------------------------------------------------------------------#
# import the various server implementations
#---------------------------------------------------------------------------#
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.constants import Defaults
from pymodbus.register_read_message import ReadRegistersResponseBase
from pymodbus.register_write_message import WriteSingleRegisterResponse, WriteMultipleRegistersResponse
from pymodbus.transaction import ModbusSocketFramer
from pymodbus.exceptions import NotImplementedException

if __name__ == "__main__" and __package__ is None:
    # Ensure that importing works (whether cpppo installed or not) with:
    #   python -m cpppo.bin.modbus_sim ...
    #   ./cpppo/bin/modbus_sim.py ...
    #   ./bin/modbus_sim.py ...
    __package__			= "cpppo.bin"

try:
    import cpppo
except ImportError:
    # Couldn't import; include our cpppo-containing directory path in sys.path
    sys.path.insert( 0, os.path.dirname( os.path.dirname( os.path.dirname( os.path.abspath( __file__ )))))
    import cpppo

from cpppo.remote.pymodbus_fixes import (
    modbus_sparse_data_block, modbus_server_rtu, modbus_rtu_framer_collecting, modbus_server_tcp )


#---------------------------------------------------------------------------#
# configure the service logging
#---------------------------------------------------------------------------#

log 			= logging.getLogger( 'modbus_sim' )

def register_parse( txt ):
    """Tokenizer yields integers; any other character (except space), one at a time. """
    b, i, e			= 0, 0, len( txt )
    while i <= e:
        if i == e or not( '0' <= txt[i] <= '9' ):
            if i > b:
                yield int( txt[b:i] )			# "123..."   Parsed 1+ digits
                b, i		= i, i-1
            elif i < e:
                if txt[b] != ' ':
                    yield txt[b]			# "?..."     Something else (not whitespace)
                b, i		= i+1, i
        i		       += 1


def register_decode( txt, default=None ):
    """Parse the supplied <beg>[-<end>][=<val>[,...]] and return beg,end,val.  If no ...=<val> portion
    is found, the returned 'val' is empty unless a non-None 'default' is provided.

    """
    prs				= register_parse( txt )
    beg = end			= None
    val				= []
    try:
        beg			= prs.next()
        end			= beg
        end			= prs.next()
        if end == '-':
            end			= prs.next()		# <beg>-<end>=
            equ			= prs.next()		#    ... raises StopIteration if no '='
        elif end == '=':
            equ			= end			# <beg>=
            end			= beg
        else:
            assert end == '-'			# Unknown range operator
        assert equ == '='
        while True: # Consumes values forever, 'til StopIteration
            val.append( prs.next() )
            assert type( val[-1] ) == int
            assert prs.next() == ','
    except StopIteration:
        pass
    except Exception as exc:
        log.error( "Unrecognized registers '%s': %s", txt, str( exc ))
        raise

    assert type( beg ) is int
    if end is None:
        end			= beg
    assert type( end ) is int

    if val or default is not None:
        # We're supposed to ensure some default values (or were provided 1 or more values).  Try
        # hard; Extend <beg>-<end> out to the number of values, or extend val to the range length;
        # duplicate entries and/or truncates to range length
        if not val:
            val			= [0 if default is None else default]
        if end == beg:
            end			= beg + len( val ) - 1
        if len( val ) < end - beg + 1:
            val		       *= (( end - beg + 1 ) // len( val ) + 1 )
        val			= val[:end - beg + 1]

    log.info( "%05d-%05d = %s", beg, end, cpppo.reprlib.repr( val ))
    return beg,end,val


def register_definitions( registers, default=None ):
    """Parse the register ranges, as: registers[, registers ...], and produce a keywords dictionary
    suitable for construction of modbus_sparse_data_block instances for a ModbusSlaveContext, for
    'hr' (Holding Registers), 'co' (Coils), etc.:

        40001=999

    produces:

         { ..., hr: { 0: 999 }, ... }

    Incoming registers are standard one-based Modbus address ranges, output register: value
    dictionaries are zero-based.

           1-1[0]0000		Coils
    1[0]0001-3[0]0000		Input  Coils
    3[0]0001-4[0]0000		Input   Registers
    4[0]0001-			Holding Registers

    Allow:
        <begin>[-<end>][=<val>[,<val>]] ...

    """
    # Parse register ranges
    # 0  10001 30001 40001
    cod,   did,  ird,  hrd 	= {}, {}, {}, {}
    for txt in registers:
        beg,end,val		= register_decode( txt, default=0 )

        for reg in range( beg, end + 1 ):
            dct, off		= (     ( hrd,  40001 ) if  40001 <= reg <=  99999
                                   else ( hrd, 400001 ) if 400001 <= reg <= 465536
                                   else ( ird,  30001 ) if  30001 <= reg <=  39999
                                   else ( ird, 300001 ) if 300001 <= reg <= 365536
                                   else ( did,  10001 ) if  10001 <= reg <=  19999
                                   else ( did, 100001 ) if 100001 <= reg <= 165536
                                   else ( cod,      1 ) if      1 <= reg <=   9999
                                   else ( None, None ))
            assert dct is not None, "Invalid Modbus register: %d" % ( reg )
            dct[reg - off]	= val[reg - beg]
    log.info( "Holding Registers: %5d, %6d-%6d; %s", len( hrd ),
              400001 + min( hrd ) if hrd else 0, 400001 + max( hrd ) if hrd else 0, cpppo.reprlib.repr( hrd ))
    log.info( "Input   Registers: %5d, %6d-%6d; %s", len( ird ),
              300001 + min( ird ) if ird else 0, 300001 + max( ird ) if ird else 0, cpppo.reprlib.repr( ird ))
    log.info( "Output  Coils:     %5d, %6d-%6d; %s", len( cod ),
                   1 + min( cod ) if cod else 0,      1 + max( cod ) if cod else 0, cpppo.reprlib.repr( cod ))
    log.info( "Discrete Inputs:   %5d, %6d-%6d; %s", len( did ),
              100001 + min( did ) if did else 0, 100001 + max( did ) if did else 0, cpppo.reprlib.repr( did ))

    return dict( co=cod, di=did, ir=ird, hr=hrd )


def register_context( registers, slaves=None ):
    """Parse a series of register ranges (and optional values), create a data
    store, and assign it to the given single (or sequence of) Slave IDs (if
    None, then it reports to any ID.)  The same data store is used to back all
    provided Slave IDs.

    --------------------------------------------------------------------------
    initialize your data store, returning an initialized ModbusServerContext
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
    """

    definitions			= register_definitions( registers )
    did				= definitions.get( 'di' )
    cod				= definitions.get( 'co' )
    hrd				= definitions.get( 'hr' )
    ird				= definitions.get( 'ir' )
    store = ModbusSlaveContext(
        di = modbus_sparse_data_block( did ) if did else None,
        co = modbus_sparse_data_block( cod ) if cod else None,
        hr = modbus_sparse_data_block( hrd ) if hrd else None,
        ir = modbus_sparse_data_block( ird ) if ird else None )

    # If slaves is None, then just pass the store with single=True; it will be
    # used for every slave.  Otherwise, map all the specified slave IDs to the
    # same store and pass single=False.  This would be used for Serial Modbus
    # protocols, and you should probably also specify ignore_missing_slaves=True
    # so that the simulator acts like a multi-drop serial PLC arrangement.
    try:
        if slaves is None:
            return ModbusServerContext( slaves=store, single=True )
        else:
            if not hasattr( slaves, '__iter__' ):
                slaves		= [ slaves ] # Convert a single value to an iterable
            return ModbusServerContext( slaves=dict( (uid,store) for uid in slaves ), single=False )
    finally:
        log.info( "Modbus Slave IDs:  %s", slaves or "(all)" )


# Global 'context'; The caller of 'main' may want a separate Thread to be able
# to access/modify the data store...
context				= None

#---------------------------------------------------------------------------#
# Creation Factories
#   - always take 'address'; underlying Modbus...Server may differ
#   - passes any remaining keywords to underlying Modbus...Server (eg.
#     serial port parameters)
#---------------------------------------------------------------------------#
def StartTcpServerLogging( registers, identity=None, framer=ModbusSocketFramer, address=None,
                           slaves=None, **kwds ):
    ''' A factory to start and run a Modbus/TCP server

    :param registers: The register ranges (and optional values) to serve
    :param identity: An optional identify structure
    :param address: An optional (interface, port) to bind to.
    :param slaves: An optional single (or list of) Slave IDs to serve
    '''
    global context
    context			= register_context( registers, slaves=slaves )
    server			= modbus_server_tcp( context, framer, identity, address,
                                                   **kwds )
    # Print the address successfully bound; this is useful, if attempts are made
    # to bind over a range of ports.
    print( "Success; Started Modbus/TCP Simulator; PID = %d; address = %s:%s" % (
        os.getpid(), address[0] if address else "", address[1] if address else Defaults.Port ))
    sys.stdout.flush()
    server.serve_forever()


def StartRtuServerLogging( registers, identity=None, framer=modbus_rtu_framer_collecting,
                           address=None, slaves=None, **kwds ):
    '''A factory to start and run a Modbus/RTU server

    :param registers: The register ranges (and optional values) to serve
    :param identity: An optional identify structure
    :param address: An optional serial port device to bind to (passes 'address' as 'port').
    :param slaves: An optional single (or list of) Slave IDs to serve


    '''
    global context
    context			= register_context( registers, slaves=slaves )
    server			= modbus_server_rtu( context, framer, identity, port=address,
                                                      **kwds )

    # Print the address successfully bound; this is useful, if attempts are made
    # to bind over a range of ports.
    print( "Success; Started Modbus/RTU Simulator; PID = %d; address = %s" % (
        os.getpid(), address ))
    sys.stdout.flush()
    server.serve_forever()


def main( argv=None ):
    parser			= argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = """\
    If an address starting with '/' is provided (eg. --address /dev/ttyS1), then
    a Modbus/RTU serial framer is assumed.  Otherwise, a Modbus/TCP framer is used.

    The --evil option takes the following :
      truncate         -- return only part of the response
      delay[:#.#[-#.#]]-- delay response by #.#[-#.#] seconds (default == 5)
      corrupt[:<shat>] -- corrupt Modbus/TCP protocol response (default == "transaction")
         :transaction    -- Transaction ID (only relevant to Modbus/TCP servers)
         :protocol       -- Protocol ID
         :unit           -- Unit number
         :function       -- Function code
         :registers      -- Amount of response data

    Register range(s) and value(s) must be supplied:

      <begin>[-<end>][=<val>[,<val>]]

    EXAMPLE

      modbus_sim.py --address localhost:7502 --evil delay:2.5 40001-40100

        Starts a simulated Modbus/TCP PLC serving Holding registers 40001-40100
        == 0, on port 7502 on interface 'localhost', which delays all responses
        for 2.5 seconds.

      modbus_sim.py --address /dev/ttyS0 --evil delay:.01-.1 40001-40100

        Starts a simulated Modbus/RTU PLC serving Holding registers 40001-40100
        == 0, on serial port /dev/ttyS0, which delays all responses for between
        .01-.1 seconds.

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
    parser.add_argument( '-c', '--config',	default=None,
                         help="""JSON config data for Modbus framer (eg. {"baudrate":19200}) (default: None)""" )
    parser.add_argument( 'registers', nargs="+" )
    args			= parser.parse_args( argv )

    # Deduce logging level and target file (if any)
    levelmap			= {
        0: logging.CRITICAL,
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose]
                                    if args.verbose in levelmap
                                    else logging.DEBUG )
    if args.log:
        cpppo.log_cfg['filename']= args.log # log rotation not supported

    logging.basicConfig( **cpppo.log_cfg )

    #---------------------------------------------------------------------------#
    # run the server you want
    #---------------------------------------------------------------------------#

    # Deduce interface:port to bind, and correct types.  Interface defaults to
    # '' (INADDR_ANY) if only :port is supplied.  Port defaults to 502 if only
    # interface is supplied.  After this block, 'address' is always a tuple like
    # ("interface",502).  If '/', then start a Modbus/RTU serial server,
    # otherwise a Modbus/TCP network server.  Create an address_sequence
    # yielding all the relevant target addresses we might need to try.

    # We must initialize 'framer' here (even if its the same as the 'starter'
    # default), because we may make an Evil...() derived class below...
    starter_kwds		= {}
    if args.address.startswith( '/' ):
        starter			= StartRtuServerLogging
        framer			= modbus_rtu_framer_collecting
        try:
            import serial
        except ImportError:
            logging.error( "Modbus/RTU not supported; ensure PySerial is available" )
            raise
        starter_kwds		= {
            # Default serial configs; may be overridden, eg:
            #     --config '{"baudrate":19200, "slaves":[1,2,3]}'
            'stopbits':			1,
            'bytesize':			8,
            'parity':			serial.PARITY_NONE,
            'baudrate':			4800,
            'timeout':			0.5,
            'slaves':			None,
            'ignore_missing_slaves':	True,
        }
        address_sequence	= [ args.address ]
        assert args.range == 1, \
            "A range of serial ports is unsupported"
    else:
        starter			= StartTcpServerLogging
        framer			= ModbusSocketFramer
        address			= args.address.split(':')
        assert 1 <= len( address ) <= 2
        address			= (
            str( address[0] ),
            int( address[1] ) if len( address ) > 1 else Defaults.Port )
        log.info( "--server '%s' produces address=%r", args.address, address )
        address_sequence	= (
            (address[0],port)
            for port in range( address[1], address[1] + int( args.range ))
        )

    #---------------------------------------------------------------------------#
    # Evil Framers, manipulate packets resulting from underlying Framers
    #---------------------------------------------------------------------------#
    if args.evil == "truncate":

        class EvilFramerTruncateResponse( framer ):
            def buildPacket(self, message):
                ''' Creates a *truncated* ready to send modbus packet.  Truncates from 1
                to all of the bytes, before returning response.

                :param message: The populated request/response to send
                '''
                packet		= super( EvilFramerTruncateResponse, self ).buildPacket( message )
                datalen		= len( packet )
                corrlen		= datalen - random.randint( 1, datalen )

                log.info( "Corrupting response; truncating from %d to %d bytes", datalen, corrlen )

                return packet[:corrlen]

        framer			= EvilFramerTruncateResponse
        log.info( "--evil '%s' uses EvilFramerTruncateResponse", args.evil )

    elif args.evil and args.evil.startswith( 'delay' ):

        class EvilFramerDelayResponse( framer ):
            delay		= 5

            def buildPacket(self, message):
                ''' Creates a ready to send modbus packet but delays the return.

                :param message: The populated request/response to send
                '''
                packet		= super( EvilFramerDelayResponse, self ).buildPacket( message )

                log.info( "Delaying response for %s seconds", self.delay )
                delay		= self.delay
                if isinstance( delay, (list,tuple) ):
                    delay	= random.uniform( *delay )
                time.sleep( delay )

                return packet

        framer			= EvilFramerDelayResponse
        # If a "--evil delay:1.5" is provided, pull out the number and change
        # the ModbusSockerFramerDelayResponse class' .delay value to the specified
        # number of seconds
        req			= args.evil.split( ':', 1 )
        assert 1 <= len( req ) <= 2
        if len( req ) == 2:
            # Specified delay value or range
            delay		= tuple( map( float, req[1].split( '-' )))
            assert 1 <= len( delay ) <= 2
            EvilFramerDelayResponse.delay = delay if len( delay ) > 1 else delay[0]
        log.info( "--evil '%s' uses EvilFramerDelayResponse, which delays responses for %s seconds",
                args.evil, EvilFramerDelayResponse.delay )

    elif args.evil and args.evil.startswith( 'corrupt' ):

        class EvilFramerCorruptResponse( framer ):
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
                    message.encode()

                    if self.what == "transaction":
                        message.transaction_id ^= 0xFFFF
                        packet	= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                        message.transaction_id ^= 0xFFFF
                    elif self.what == "registers":
                        if isinstance( message, ReadRegistersResponseBase ):
                            # These have '.registers' attribute, which is a list.
                            # Add/remove some
                            saveregs		= message.registers
                            if len( message.registers ) == 0 or random.randint( 0, 1 ):
                                message.registers += [999]
                            else:
                                message.registers = message.registers[:-1]
                            packet		= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                            message.registers	= saveregs
                        elif isinstance( message, WriteSingleRegisterResponse ):
                            # Flip the responses address bits and then flip them back.
                            message.address    ^= 0xFFFF
                            packet		= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                            message.address    ^= 0xFFFF
                        elif isinstance( message, WriteMultipleRegistersResponse ):
                            # Flip the responses address bits and then flip them back.
                            message.address    ^= 0xFFFF
                            packet		= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                            message.address    ^= 0xFFFF
                        else:
                            raise NotImplementedException(
                                "Unhandled class for register corruption; not implemented" )
                    elif self.what == "protocol":
                        message.protocol_id    ^= 0xFFFF
                        packet			= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                        message.protocol_id    ^= 0xFFFF
                    elif self.what == "unit":
                        message.unit_id	       ^= 0xFF
                        packet			= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                        message.unit_id	       ^= 0xFF
                    elif self.what == "function":
                        message.function_code  ^= 0xFF
                        packet			= super( EvilFramerCorruptResponse, self ).buildPacket( message )
                        message.function_code  ^= 0xFF
                    else:
                        raise NotImplementedException(
                            "Unknown corruption specified; not implemented" )
                except Exception:
                    log.info( "Could not build corrupt packet: %s", traceback.format_exc() )
                return packet

        framer			= EvilFramerCorruptResponse
        # If a "--evil corrupt:<what>" is provided, corrupt the specified entry.
        req			= args.evil.split(":", 1)
        assert 1 <= len( req ) <= 2
        if len( req ) == 2:
            EvilFramerCorruptResponse.what = req[1]
        log.info( "--evil '%s' uses EvilFramerCorruptResponse, which corrupts the responses %s entry",
                args.evil, EvilFramerCorruptResponse.what )

    elif args.evil:

        log.error( "Unrecognized --evil argument: %s", args.evil )
        return 1

    if args.config:
        try:
            starter_kwds.update( **json.loads( args.config ))
        except Exception as exc:
            log.error( "Failed to parse JSON --config Modbus Framer config: %s; %s", args.config, exc )
            raise

    #---------------------------------------------------------------------------#
    # Start the PLC simulation engine on a port in the range; will serve forever
    #---------------------------------------------------------------------------#
    for address in address_sequence:
        try:
            for k in sorted( starter_kwds.keys() ):
                log.info( "config: %24s: %s", k, starter_kwds[k] )
            starter( registers=args.registers, framer=framer, address=address, **starter_kwds )
        except KeyboardInterrupt:
            return 1
        except Exception as exc:
            log.info( "Couldn't start PLC simulator on %s: %s",
                    address, traceback.format_exc() )

    log.error( "Failed to start PLC simulator on %s, over a range of %s ports",
               args.address, args.range )
    return 1

if __name__ == "__main__":
    sys.exit( main() )
