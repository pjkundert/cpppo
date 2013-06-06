from __future__ import absolute_import
from __future__ import print_function

import logging
import os
import sys

from .misc import *

def test_centeraxis():
    string='abc.123.xyz'
    assert centeraxis( string, 20 ) \
        == '   abc.123.xyz      '
    assert centeraxis( string, 20, reverse=True ) \
        == '       abc.123.xyz  '
    assert centeraxis( string, 20, reverse=True, fillchar='x' ) \
        == 'xxxxxxxabc.123.xyzxx'

    string='----------abc.123.xyz++++++++++'
    assert centeraxis( string, 20, reverse=True ) \
        == '----------abc.123.xyz++++++++++'
    assert centeraxis( string, 20, reverse=True, clip=True ) \
        == '-------abc.123.xyz++'
    assert centeraxis( string, 20,               clip=True ) \
        == '---abc.123.xyz++++++'
    assert centeraxis( string, 20,               clip=True ) \
        == '---abc.123.xyz++++++'

    # If no axis char, center around a fill char
    string='abc'
    assert centeraxis( string, 20, reverse=True ) \
        == '       abc          '
    assert centeraxis( string, 20               ) \
        == '           abc      '

def test_natural():
    assert natural('10th')	== ('       10', 't', 'h')
    for itm in [ None, [1], {'a':1} ]:
        assert natural(itm)	== ('', itm.__class__.__name__,
                                    "%9d" % ( hash( itm )
                                              if hasattr( itm, '__hash__' ) and itm.__hash__ is not None
                                              else id( itm )))

    l = ['10th', '1st', '9', 9, 'Z', 'a', 9.0, "9.1", None ]
    ls1 = ['None', "'1st'", "'9'", "9", "9.0", "'9.1'", "'10th'", "'a'", "'Z'"]
    ls2 = ['None', "'1st'", "9", "'9'", "9.0", "'9.1'", "'10th'", "'a'", "'Z'"]

    s = sorted( l, key=natural )
    rs = [ repr(i) for i in s ]
    assert rs == ls1 or rs == ls2
