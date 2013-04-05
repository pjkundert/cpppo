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
