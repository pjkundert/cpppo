from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import logging
import os
import sys
import threading
import time
import traceback

if __name__ == "__main__":
    # Allow relative imports when executing within package directory, for
    # running tests directly
    sys.path.insert(0, os.paht.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    #logging.getLogger().setLevel( logging.INFO )

import cpppo
from   cpppo.server.enip import playback

log				= logging.getLogger( "playback" )

def test_playback_command():
    stdin_save			= sys.stdin
    try:
        with open( os.path.join( os.path.dirname( __file__ ),
                   "playback_test.input" ), "r" ) as sys.stdin:
            command		= playback.daemon_command( )
            command.start()

            time.sleep( .5 )
            assert len( command ) == 2
            assert command[0] == "Something"
            assert command[1] == "Another"
            assert not command # should be dead by now
    finally:
        sys.stdin		= stdin_save

def test_playback_reader():
    reader			= playback.daemon_playback(
        os.path.join( "/tmp", ""))
