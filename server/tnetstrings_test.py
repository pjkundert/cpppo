# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import print_function

import sys

import tnetstrings

def test_tnetstrings():
    data			= tnetstrings.dump( u"abcπ", encoding="utf-8" )
    assert type( data ) is bytes
    assert len( data ) == 8

    payload			= tnetstrings.parse( data, encoding="utf-8" )
    assert payload == (u'abcπ', b'')
