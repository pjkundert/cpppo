from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import logging
import os
import sys
import types
import threading

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

def test_function_creation():
    """Creating functions with code containing a defined co_filename is required in
    order to extend the logging module.  Unfortunately, this module seeks up the
    stack frame until it finds a function whose co_filename is not the logging
    module...  """

    def func( boo ):
        pass

    assert func.__code__.co_filename == __file__
    filename			= "something/else.py"
    change_function( func, co_filename=filename )
    assert func.__code__.co_filename == filename


def test_mutexmethod():

    class C( object ):
        _cls_lock		= threading.Lock()
        def __init__( self ):
            self._ins_lock	= threading.Lock()

        @classmethod
        @mutexmethod( '_cls_lock', blocking=False )
        def clsmethod_lock_cls( cls, f=None ):
            if f:
                return f()

        @mutexmethod( '_cls_lock', blocking=False )
        def insmethod_lock_cls( self, f=None ):
            if f:
                return f()

        @mutexmethod( '_ins_lock', blocking=False )
        def insmethod_lock_ins( self, f=None ):
            if f:
                return f()

    c				= C()

    # Same lock; should raise Exception (since blocking=False used above)
    assert c.insmethod_lock_cls() is None
    try:
        c.insmethod_lock_cls( c.insmethod_lock_cls )
        assert False, "Should have raised recursive lock exception"
    except Exception as exc:
        assert "Lock is held" in str( exc )

    assert c.clsmethod_lock_cls() is None
    try:
        c.clsmethod_lock_cls( c.clsmethod_lock_cls )
        assert False, "Should have raised recursive lock exception"
    except Exception as exc:
        assert "Lock is held" in str( exc )

    try:
        c.clsmethod_lock_cls( c.insmethod_lock_cls )
        assert False, "Should have raised recursive lock exception"
    except Exception as exc:
        assert "Lock is held" in str( exc )

    # Two different locks; should not interfere
    c.clsmethod_lock_cls( c.insmethod_lock_ins )

