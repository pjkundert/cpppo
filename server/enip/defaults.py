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

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


"""
enip.defaults -- System-wide default (global) values

"""
__all__				= [ 'latency', 'timeout', 'address',
                                    'route_path_default', 'send_path_default',
                                    'config_name', 'config_files' ]

import os

import cpppo

latency				=  0.1 	# network I/O polling (should allow several round-trips)
timeout				= 20.0	# Await completion of all I/O, thread activity (on many threads)
address				= ('', 44818)	# The default cpppo.enip.address
route_path_default		= [{'port': 1, 'link': 0}] # default controller address: backplane, slot 0 
send_path_default		= [{'class': 6}, {'instance': 1}]
config_name			= 'cpppo.cfg'
config_files			= [
    os.path.join( os.path.dirname( cpppo.__file__ ), config_name ),	# cpppo install dir
    os.path.join( os.getenv( 'APPDATA', os.sep + 'etc' ), config_name ),# global app data
    os.path.join( os.path.expanduser( '~' ), '.' + config_name ),	# user home dir
    config_name,							# current dir
]
