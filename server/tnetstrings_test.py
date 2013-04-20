# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import logging
import sys

import tnetstrings


def test_tnetstrings():
    tests      			= [
        (  8, u'abcπ' ),
        ( 38, { "pi": u'π', "abc": b'abc', "def": "def"  } ),
        (  3, [] ),
        ( 26, [1, 2.3, "4", b'5', u'6'] ),
        ( 3,  None ),
        ( 7,  True ),
    ]
    
    print()
    composite 			= b''
    for l, t in tests:
        data			= tnetstrings.dump( t, encoding="utf-8" )
        print("%32.32r == %r" % ( t, data ))
        assert type( data ) is bytes
        assert len( data ) == l
        composite	       += data

    ti				= iter( tests )
    extra			= composite
    while extra:
        payload, extra		= tnetstrings.parse( extra, encoding="utf-8" )
        l, t			= next( ti )
        assert payload == t


