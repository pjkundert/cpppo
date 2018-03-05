#! /usr/bin/env python3

# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2018, Hard Consulting Corporation.
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
__copyright__                   = "Copyright (c) 2018 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

"""
enip.pccc -- Parse/produce DF1 requests


"""
__all__				= ['PCCC']

import sys
import logging

import cpppo
from .. import enip
from .parser import ( USINT, UINT, octets_noop, typed_data, move_if )
log				= logging.getLogger( "enip.pccc" )



class ANC_120e_DF1( cpppo.dfa ):
    """Parse a DF1 request/reply, in ANC-120e Class 0xA6 form.  This differs from classical (and
    C*Logix PCCC), as described in:

    http://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1770-rm516_-en-p.pdf, 6-5

    The DST/SRC seem to be 4-byte values, w/ an enumerated DH+ DST/SRC in byte 3.

    CMD byte's bit:
       7:   0 always
       6:   1 iff reply, 0 command
       5:   1 iff priority, 0 normal
       4:   0 always
       0-3: Command code

    Almost all Commands are formatted (not all commands have additional data):

        +---+---+---+---+---+---+---+---+...+---+
        |DST|SRC|CMD|STS|  TNS  |FNC| ...DATA...|
        +---+---+---+---+---+---+---+---+...+---+

    Some have no FNC:
                 =04 
        +---+---+---+---+---+---+---+---+---+
        |DST|SRC|CMD|STS|  TNS  | ADDR  |SIZ| PLC-2 Physical Read
        +---+---+---+---+---+---+---+---+---+
                 =02 
        +---+---+---+---+---+---+---+---+---+...+---+
        |DST|SRC|CMD|STS|  TNS  | ADDR  | SET/RESET | PLC-2/3/4 Protected Bit Write
        +---+---+---+---+---+---+---+---+---+...+---+ 60 x 4-byte blocks, 2x16-bit set/reset masks

    Replies are formatted:

                     =F0
        +---+---+---+---+---+---+EXT+
        |DST|SRC|CMD|STS|  TNS  |STS|		Remote error w/ EXT STS
        +---+---+---+---+---+---+---+

                     !00
        +---+---+---+---+---+---+
        |DST|SRC|CMD|STS|  TNS  |		Remote/local error w/o EXT STS
        +---+---+---+!00+---+---+

                     =00
        +---+---+---+---+---+---+---+...+---+
        |DST|SRC|CMD|STS|  TNS  | ...DATA...|	Success (STS == 00) w/ optional data payload
        +---+---+---+!00+---+---+---+...+---+

    """
    def __init__( self, name=None, **kwds ):
        name 			= name or kwds.setdefault( 'context', self.__class__.__name__ )
        # All command request/reply share the first 12 bytes:
        init			= USINT(	 	  	context='byt0' )
        init[True]		= byt1	= USINT(	 	  	context='byt1' )
        byt1[True]		= dst	= USINT(	 	  	context='dst' )
        dst[True]		= byt3	= USINT(	 	  	context='byt3' )
        byt3[True]		= byt4	= USINT(	 	  	context='byt4' )
        byt4[True]		= byt5	= USINT(	 	  	context='byt5' )
        byt5[True]		= src	= USINT(	 	  	context='src' )
        src[True]		= byt7	= USINT(	 	  	context='byt7' )
        byt7[True]		= cmd	= USINT(	 	  	context='cmd' )
        cmd[True]		= sts	= USINT(	  		context='sts' )
        sts[True]		= tns	= UINT(	 	  		context='tns' )
    
        # Reply has STS == 0xF0, then EXT STS is parsed
        rpy_extsts		= USINT(			context='extsts',	terminal=True )
        # Reply has STS != 0x00, then reply is done
        rpy_sts			= octets_noop(						terminal=True )
        # Reply has STS == 0; collect remaining USINTs into .data (cannot parse, b/c replies not self-describing)
        rpy			= typed_data( tag_type=USINT.tag_type,			terminal=True )
    
        # Split the replies off
        # For a Reply (CMD & 0xb01000000 set); If sts was !0, then the byte following TNS is EXT STS.
        tns[None]		= cpppo.decide(	'RPY EXT STS?',	state=rpy_extsts,
                                            predicate=lambda path=None, data=None, **kwds: \
                                                        bool( data[path].cmd & 0b01000000 ) and data[path].sts == 0xf0 )
        tns[None]		= cpppo.decide(	'RPY',		state=rpy_sts,
                                            predicate=lambda path=None, data=None, **kwds: \
                                                bool( data[path].cmd & 0b01000000 ) and data[path].sts != 0x00 )
        tns[None]		= cpppo.decide(	'RPY',		state=rpy,
                                            predicate=lambda path=None, data=None, **kwds: \
                                                bool( data[path].cmd & 0b01000000 ) and data[path].sts == 0x00 )
    
        # Request follows TNS. May be a request w/o a FNC.  See:
        # http://literature.rockwellautomation.com/idc/groups/literature/documents/rm/1770-rm516_-en-p.pdf
        # 7-2 for a table of all CMD/FNC codes. Just collect the rest into .data.
        req_nonfnc		= typed_data( tag_type=USINT.tag_type,			terminal=True )
        tns[None]		= cpppo.decide(	'REQ NON FNC',	state=req_nonfnc,
                                        predicate=lambda path=None, data=None, **kwds: \
                                            data[path].cmd in (
                                                0x00, #   protected write
                                                        0x01, # unprotected read
                                                        0x02, #   protected bit write
                                                        0x05, #    physical read
                                                        0x05, # unprotected bit write
                                                        0x08, # Unprotected write
                                                    ))
    
        # ... 7-17: .read...: Protected Typed Logical Read w/ 3 Address Fields has (sub-)element w/ 1 or 2-byte values
        tlr3		= tlr3b	= USINT(			context='read', extension='.bytes' )
        tlr3b[True]	= tlr3fn= USINT(			context='read', extension='.file' ) # 0-254
        tr3fn16			= UINT(				context='read', extension='.file' )
        tlr3fn[None]		= cpppo.decide(	'FLN 16?',	state=tlr3fn16,
                                                predicate=lambda path=None, data=None, **kwds: \
                                                    data[path].read.file == 0xFF )
        tlr3fn16[True] = tlr3fn[True] = tlr3ft= USINT(		context='read', extension='.type' ) # 0x80-8F; 89 = integer, 8A = float, ...
        tlr3ft[True]	= tlr3el= USINT(			context='read', extension='.element' ) # 0xFF ==> 16-bit element # follows
        tlr3el16		= UINT(				context='read', extension='.element' )
        tlr3el[None]		= cpppo.decide(	'ELE 16?',	state=tlr3el16,
                                                predicate=lambda path=None, data=None, **kwds: \
                                                    data[path].read.element == 0xFF )
        tlr3el16[True] = tlr3el[True] = tlr3se = USINT(		context='read', extension='.subelement', terminal=True )
        tlr3se16		= UINT(				context='read', extension='.subelement', terminal=True )
        tlr3se[None]		= cpppo.decide(	'SEL 16?',	state=tlr3se16,
                                                predicate=lambda path=None, data=None, **kwds: \
                                                    data[path].read.subelement == 0xFF )

        # 7-28: .read...: Typed Read PLC5
        # 13-11:   Uses PLC-5 Logical Binary Addressing. Too complex to implement right now.
        #trp5		= trp5o	= UINT(				context='read', extension='.offset' )# Offset to 1st item in range to return
        #trp5o[True]	= trp5t	= UINT(				context='read', extension='.total' ) # Total number of data items in range

        # ... 7-6: .status: Diagnostic Status has no additional data; create (empty) .status
        diag		= diagm	= octets_noop(			context='status', terminal=True )
        diagm.initial[None]	= move_if(	'mark',		initializer=True )
    
        # A Request CMD w/ a FNC code. See if we recognize it.
        tns[True]		= fnc	= USINT(			context='fnc' )
        #fnc[None]		= cpppo.decide(	'Typed Read?',		state=tlr3,  # Typed Read (read block) w/ PLC-5 sys. addressing
        #                                        predicate=lambda path=None, data=None, **kwds: \
        #                                            data[path].cmd == 0x0F and data[path].fnc == 0x68 )
        fnc[None]		= cpppo.decide(	'Typed Read 3?',	state=tlr3,  # Protected Typed Logical Read w/ 3 Address Fields
                                                predicate=lambda path=None, data=None, **kwds: \
                                                    data[path].cmd == 0x0F and data[path].fnc == 0xA2 )
        fnc[None]		= cpppo.decide(	'Diagnostic Status? ',	state=diag,  # Diagnostic Status
                                                predicate=lambda path=None, data=None, **kwds: \
                                                    data[path].cmd == 0x06 and data[path].fnc == 0x03 )

        # Unknown CMD/FNC; just harvest the rest of the request into .data (often no further command data)
        fnc[None]			= typed_data( tag_type=USINT.tag_type, context="",	terminal=True )
        
        super( ANC_120e_DF1, self ).__init__( name=name, initial=init, **kwds )

    @classmethod
    def produce( cls, data ):
        result			= b''
        df1			= data.get( 'DF1' )
        return result

        
class PCCC_ANC_120e( enip.Object ):
    """Understands PCCC DF1 I/O requests.  However, does not use the C*Logix PCCC Object's 0x4b
    "Execute PCCC" service code; uses a simple encapsulation:

    +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
    |  00 |  00 | DST |  00 |  00 |  00 | SRC |  00 | CMD |  TNS      | FNC | ...
    +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+

    The ANC-120e DH+ "host" is identifed as ID 0, and each DH+ host on the network is enumerated 1,
    2, ...

    """
    class_id			= 0xA6

    parser			= ANC_120e_DF1( context="DF1" )

    # Data tables shared by all instance of PCCC Object
    tables			= {
        'N7':	[0]	* 100,
        'F8':	[0.0]	* 100,
    }

    def request( self, data, addr=None ):
        """Any exception should result in a reply being generated with a non-zero status."""
        if log.isEnabledFor( logging.DETAIL ):
            log.detail( "%s Request: %s", self, enip.enip_format( data ))
        
        # Pick out our services added at this level.  If not recognized, let superclass try; it'll
        # return an appropriate error code if not recognized.
        df1			= data.get( 'DF1' )
        if   df1 and df1.get( 'cmd' ) == 0x06 and df1.get( 'fnc' ) == 0x03:
            log.warning( "DF1: Diagnostic Status: %s", enip.enip_format( data ))
        elif df1 and df1.get( 'cmd' ) == 0x0f and df1.get( 'fnc' ) == 0xA2:
            log.warning( "DF1: Protected typed Logical Read w/ 3 Address Fields: %s", enip.enip_format( data ))
        else:
            log.warning( "DF1: Unrecognized: %s", enip.enip_format( data ))


# 
# Simulate a simple ANC-120e DF1 device, w/ an instance of class 0xA6
# 
class UCMM_no_route_path( enip.UCMM ):
    """The PowerFlex/20-COMM-E UnConnected Messages Manager allows no route_path"""
    route_path			= False

def main( **kwds ):
    """Set up PowerFlex/20-COMM-E objects (enip.main will set up other Logix-like objects)"""

    enip.config_files 	       += [ __file__.replace( '.py', '.cfg' ) ]

    PCCC_ANC_120e( name="PCCC", instance_id=0 ) # Class Object
    PCCC_ANC_120e( name="PCCC", instance_id=1 ) # 0xA6/1 -- target Object for CIP requests w/ DF1 payload

    # Establish Identity and TCPIP objects w/ some custom data for the test, from a config file
    return enip.main( argv=sys.argv[1:], UCMM_class=UCMM_no_route_path )


if __name__ == "__main__":
    sys.exit( main() )
