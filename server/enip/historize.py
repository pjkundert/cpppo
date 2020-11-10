
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

# 
# cpppo.server.enip.historize
# 
#     Example of how to run an EtherNet/IP simulator, and intercept all Attribute I/O.  In this
# instance, we'll arrange to output a copy of all I/O to the file specified in the first
# command-line argument to the module.  Invoke using:
# 
#     python -m cpppo.server.enip.historize some_file.hst Tag_Name=DINT[1000]
# 
#     You may use a cpppo.history.reader to retrieve the previously historized records and replay
# them in real-time.  Alternatively, since they are stored in JSON format records, you can write
# your own processor.  Processing time stamps is non-trivial, especially in the presence of timezone
# information, and you may want to use the cpppo.history.timestamp class to correctly handle the
# timestamp information in the file.
# 
# 
#     Use this as a template for intercepting and processing EtherNet/IP Attribute I/O for your own
# project; Replace the code between vvvv and ^^^^ with your own code, which maps EtherNet/IP
# Attribute indices to data values.  In this case, we're using the default implementation (which
# just remembers any values written, and returns them to future read requests).  You will probably
# map certain Tag names to certain aspects of your application, and provide read and/or write access
# to pre-existing data from within your application instead.
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

import sys

from cpppo import history
from cpppo.server.enip import device
from cpppo.server.enip.main import main as enip_main

# 
# Attribute_historize -- intercept all EtherNet/IP Attribute I/O, and output to a file
# 
class Attribute_historize( device.Attribute ):
    """Capture sys.argv[1] (the first command-line argument) as a filename, and arrange to output a
    copy of all Attribute I/O (and exceptions) to that file.  However, trapping exceptions should be
    rare, as most PLC I/O issues are detected before processing the I/O request to the Attribute.

    The 'key' arguments to __{get,set}item__ are of type slice or int, and 'value' is a list (for
    multi-element Attributes). 

    WARNING

    An instance of this class is created for each EtherNet/IP CIP Tag, and multiple client request
    service Threads may access it simultaneously.  Ensure that your arrange to protect any code
    subject to race conditions with a threading.[R]Lock mutex.  In this contrived example, we are
    opening a single file at module load time, and separate Threads are writing complete records of
    text out to a shared file object in 'a' (append) mode, so the risks are minimal.

    In a real (production) example derived from this code, you should be aware of the fact that each
    EtherNet/IP CIP client is serviced asynchronously in a separate Thread, and that these
    __getitem__ and __setitem__ invocations may (appear) to occur simultaneously; lock your mutex
    around any critical sections!

    """
    
    __filename			= sys.argv.pop( 1 ) # Capture and remove first command-line argument
    __logger			= history.logger( __filename, bufsize=history.logger.LINE_BUF )

    def __init__( self, *args, **kwds ):
        super( Attribute_historize, self ).__init__( *args, **kwds )
        self.__logger.comment( "%s: Started recording Tag: %s" % ( history.timestamp(), self.name ))
        
    def __getitem__( self, key ):
        try:
            # vvvv -- Process an EtherNet/IP CIP Read [Tag [Fragmented]].
            # 
            # We'll just access the (previously written) saved data here, and output the read
            # request (and the value returned) to our time-series history file.
            # 
            value		= super( Attribute_historize, self ).__getitem__( key )
            self.__logger.write( { 'read': value }, serial=(self.name, (
                key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
            )))
            # ^^^^
            return value
        except Exception as exc:
            # vvvv -- Process an EtherNet/IP CIP Read [Tag [Fragmented]] Exception.
            # 
            # Something went wrong with the Read request processing.  Log something intelligent and
            # re-raise the exception, to return a failure to the EtherNet/IP client.
            # 
            self.__logger.comment(
                "%s: PLC I/O Read  Tag %20s[%5s-%-5s] Exception: %s" % (
                    history.timestamp(), self.name,
                    key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                    key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
                    exc ))
            # ^^^^
            raise

    def __setitem__( self, key, value ):
        try:
            # vvvv -- Process an EtherNet/IP CIP Write [Tag [Fragmented]].
            # 
            # We'll just store the value, and output the write request (and the value written) to
            # our time-series history file.
            # 
            super( Attribute_historize, self ).__setitem__( key, value )
            self.__logger.write( { 'write': value }, serial=(self.name, (
                key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
            )))
            # ^^^^
        except Exception as exc:
            # vvvv -- Process an EtherNet/IP CIP Write [Tag [Fragmented]] Exception.
            # 
            # Something went wrong with the Write request processing.  Log something intelligent and
            # re-raise the exception, to return a failure to the EtherNet/IP client.
            # 
            self.__logger.comment(
                "%s: PLC I/O Write Tag %20s[%5s-%-5s] Exception: %s" % (
                    history.timestamp(), self.name,
                    key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                    key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
                    exc ))
            # ^^^^
            raise

sys.exit( enip_main( attribute_class=Attribute_historize ))
