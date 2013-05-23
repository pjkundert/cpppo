#!/usr/bin/env python
# 
# readme.py: A demo of plain and composite cpppo state machinery; works under python 2 or 3 
# 
from __future__ import print_function

import os, sys

# Allow import of 'cpppo' when executing within 'cpppo' package directory
sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cpppo

def main():
    """The basic examples in the README"""

    # Basic DFA that accepts ab+
    E			= cpppo.state( "E" )
    A			= cpppo.state_input( "A" )
    B			= cpppo.state_input( "B", terminal=True )
    E['a']		= A
    A['b']		= B
    B['b']		= B

    # Composite state machine accepting ab+, ignoring ,[ ]* separators
    CSV			= cpppo.dfa( "CSV", initial=E )
    SEP			= cpppo.state_discard( "SEP" )
    CSV[',']		= SEP
    SEP[' ']		= SEP
    SEP[None]		= CSV

    for initial in (E, CSV):
        data		= cpppo.dotdict()
        source		= cpppo.peekable( str( 'abbbb, ab' ))
        with cpppo.dfa( initial=initial ) as machine:
            for i,(m,s) in enumerate( machine.run( source=source, path="DFA", data=data )):
                print( "%s #%3d; next byte %3d: %-10.10r: %r" % (
                       m.name_centered(), i, source.sent, source.peek(), data ))
        print( "Accepted: %r; remaining: %r\n" % ( data, ''.join( source )))

if __name__ == "__main__":
    sys.exit( main() )
