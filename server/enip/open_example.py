#! /usr/bin/env python

# 
# Open a "Connected" Class-1 session to a C*Logix PLC
# 
#     python -m cpppo.server.enip.open_example <hostname> [<tag> ...]
# 
# To start a simulator on localhost suitable for polling:
# 
#     python -m cpppo.server.enip.poll_test
# 

import logging
import sys
import time
import threading

import cpppo

from cpppo.server.enip import client, defaults

log				= logging.getLogger( 'open ex.' )

cpppo.log_cfg['level']		= logging.DETAIL
logging.basicConfig( **cpppo.log_cfg )

# Device IP in 1st arg, or 'localhost' (run: python -m cpppo.server.enip.poll_test)
hostname			= sys.argv[1] if len( sys.argv ) > 1 else 'localhost'

# Parameters valid for device; for *Logix, others, try:
#params				= [('@1/1/1','INT'),('@1/1/7','SSTRING')] # not supported
params_default			= [ "A63FGRDT", "T455ADT" ]
params				= sys.argv[2:] if len( sys.argv ) > 2 else params_default

# See Vol1_3.15, Section 3-4 Transport Class Bits
FO_TRANSPORT_DIR_CLIENT		= 0b0    << 7
FO_TRANSPORT_DIR_SERVER		= 0b1    << 7
FO_TRANSPORT_TRG_CYCLIC		= 0b000  << 4
FO_TRANSPORT_TRG_COS		= 0b001  << 4
FO_TRANSPORT_TRG_APPOBJ		= 0b010  << 4
FO_TRANSPORT_CLS_0		= 0b0000 << 0
FO_TRANSPORT_CLS_1		= 0b0001 << 0
FO_TRANSPORT_CLS_2		= 0b0010 << 0
FO_TRANSPORT_CLS_3		= 0b0011 << 0

#transport_class_triggers = FO_TRANSPORT_DIR_SERVER | FO_TRANSPORT_TRG_APPOBJ | FO_TRANSPORT_CLS_3, # 163
# The endpoint is a Client (initiates), cyclicly
transport_class_triggers	= FO_TRANSPORT_DIR_CLIENT | FO_TRANSPORT_TRG_CYCLIC | FO_TRANSPORT_CLS_3
priority_time_ticks		= 7
timeout_ticks			= 155
connection_timeout_multiplier	= 1


sender_context			= b'open_ex.'
multiple			= 500
depth				= 2
fragment			= True
printing			= True
timeout				= .5

connected			= True


if connected:
    route_path, send_path	= [], ''	# Simple (eg. Powerflex, Micrologix)
    connection			= client.implicit(
        host			= hostname,
        timeout			= timeout,        
        sender_context		= sender_context,
        transport_class_triggers= transport_class_triggers,
        priority_time_tick	= priority_time_ticks,
        timeout_ticks		= timeout_ticks,
        connection_timeout_multiplier = connection_timeout_multiplier,
        T_O_NCP			= 0x4302,
        O_T_NCP			= 0x4302,
        T_O_RPI			= 4000000,
        O_T_RPI			= 4000000,
        # connection_path		= [
        #     {'port':1, 'link': 0},
        #     {'class':2}, {'instance':1},
        #     #{'class':1}, {'instance':1},# {'attribute':7},
        #     #{'symbolic': 'A63FGRDT'}
        # ],
        # path			= [
        #     # {'symbolic': 'A63FGRDT'},
        #     {'class':1}, {'instance':1},# {'attribute':7},
        # ]
    )
else:
    route_path, send_path		= None, None	# Routed (eg. C*Logix)
    #route_path, send_path		= defaults.route_path_default, defaults.send_path_default
    connection			= client.connector(
        host			= hostname,
        timeout			= timeout,
        sender_context		= sender_context,
    )

    
with connection as conn:
    data			= True
    while True:
        # Perform some I/O on the Connected channel
        begun			= cpppo.timer()
        operations		= client.parse_operations( params, route_path=route_path, send_path=send_path )
        failed,txs		= conn.process(
            operations=operations, depth=depth, multiple=multiple,
            fragment=fragment, printing=printing, timeout=timeout )
        elapsed			= cpppo.timer() - begun

        # Now, wait for spontaneous data
        data,elapsed		= client.await_response( conn, timeout=1 )
        if data: log.normal( "Received: {data!r}".format( data=data ))

