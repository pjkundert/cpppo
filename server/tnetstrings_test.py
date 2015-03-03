# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals
from __future__ import division

import logging

from   cpppo.server import tnetstrings # reference implementation


def test_tnetstrings():
    tests      			= [
        (  8, 'abcπ' ),
        ( 38, { "pi": 'π', "abc": b'abc', "def": str("def")  } ),
        (  3, [] ),
        ( 26, [1, 2.3, str("4"), b'5', '6'] ),
        ( 3,  None ),
        ( 7,  True ),
    ]
    
    composite 			= b''
    for l, t in tests:
        data			= tnetstrings.dump( t, encoding="utf-8" )
        logging.info( "%32.32r == %r" % ( t, data ))
        assert type( data ) is bytes
        assert len( data ) == l
        composite	       += data

    ti				= iter( tests )
    extra			= composite
    while extra:
        payload, extra		= tnetstrings.parse( extra, encoding="utf-8" )
        l, t			= next( ti )
        assert payload == t


