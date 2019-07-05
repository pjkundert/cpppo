#!/usr/bin/env python
#
# readme.py: A demo of plain and composite cpppo state machinery; works under python 2 or 3 
#
from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import os, sys

try:
    import cpppo
except ImportError:
    # Allow import of 'cpppo' when executing within 'cpppo' package directory
    sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import cpppo

# To enable logging, uncomment:
# import logging
# logging.basicConfig( **cpppo.log_cfg )
# #logging.getLogger().setLevel( logging.DEBUG )


def main():
    """The basic examples in the README"""

    # Basic DFA that accepts ab+
    E			= cpppo.state( 'E' )
    A			= cpppo.state_input( 'A' )
    B			= cpppo.state_input( 'B', terminal=True )
    E['a']		= A
    A['b']		= B
    B['b']		= B

    BASIC		= cpppo.dfa( 'ab+', initial=E, context='basic' )

    # Composite state machine accepting ab+, ignoring ,[ ]* separators
    ABP			= cpppo.dfa( 'ab+', initial=E, terminal=True )
    SEP			= cpppo.state_drop( 'SEP' )
    ABP[',']		= SEP
    SEP[' ']		= SEP
    SEP[None]		= ABP

    CSV			= cpppo.dfa( 'CSV', initial=ABP, context='csv' )

    # A regular expression; he default dfa name is the regular expression itself.
    REGEX		= cpppo.regex( initial='(ab+)((,[ ]*)(ab+))*', context='regex' )

    data		= cpppo.dotdict()
    for machine in [ BASIC, CSV, REGEX ]:
        path		= machine.context() + '.input'  # default for state_input data
        source		= cpppo.peekable( str( 'abbbb, ab' ))
        with machine:
            for i,(m,s) in enumerate( machine.run( source=source, data=data )):
                print( "%s #%3d; next byte %3d: %-10.10r: %r" % (
                       m.name_centered(), i, source.sent, source.peek(), data.get(path) ))
        print( "Accepted: %r; remaining: %r\n" % ( data.get(path), ''.join( source )))
    print( "Final: %r" % ( data ))

if __name__ == "__main__":
    sys.exit( main() )
