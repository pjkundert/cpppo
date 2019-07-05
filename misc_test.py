from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import threading

from .misc import ( near, scale, magnitude, centeraxis, natural, change_function, mutexmethod )

def test_scale():
    assert near( scale(   0., ( 0., 100. ), ( 32., 212. )),  32. )
    assert near( scale( -40., ( 0., 100. ), ( 32., 212. )), -40. )
    assert near( scale(  20., ( 0., 100. ), ( 32., 212. )),  68. )

    # Try an inverted mapping (a reverse-ordered range)
    assert near( scale(   0., ( 0., 100. ), ( 1., -1.   )),   1. )
    assert near( scale( -40., ( 0., 100. ), ( 1., -1.   )),   1.80 )
    assert near( scale(  20., ( 0., 100. ), ( 1., -1.   )),   0.60 )
    assert near( scale( 120., ( 0., 100. ), ( 1., -1.   )),  -1.40 )

    # Try a reverse-ordered domain
    assert near( scale(   0., ( 100., 0. ), ( 32., 212. )), 212. )
    assert near( scale( -40., ( 100., 0. ), ( 32., 212. )), 284. )
    assert near( scale(  20., ( 100., 0. ), ( 32., 212. )), 176. )

    # An exponential mapping
    assert near( scale(  40,       ( 25  , 40 ), ( 0, 1 )),              1 )
    assert near( scale(  40,       ( 25  , 40 ), ( 0, 1 ), exponent=2),  1 )
    assert near( scale(  25,       ( 25  , 40 ), ( 0, 1 )),              0 )
    assert near( scale(  25,       ( 25  , 40 ), ( 0, 1 ), exponent=2),  0 )
    assert near( scale(  25+15/2 , ( 25  , 40 ), ( 0, 1 )),               .5 )
    assert near( scale(  25+15/2 , ( 25  , 40 ), ( 0, 1 ), exponent=2),   .25 )
    assert near( scale(  39      , ( 25  , 40 ), ( 0, 1 )),               .9333 )
    assert near( scale(  39      , ( 25  , 40 ), ( 0, 1 ), exponent=2),   .8711 )
    assert near( scale(  26      , ( 25  , 40 ), ( 0, 1 )),               .066667 )
    assert near( scale(  26      , ( 25  , 40 ), ( 0, 1 ), exponent=2),   .004444 )

    # Ensure non-linear scaling ensures negatives may be handled by clamping domain
    assert near( scale(  24      , ( 25  , 40 ), ( 0, 1 ), exponent=2, clamped=True ),  0 )

def test_magnitude():
    # base 10 (the default)
    assert near( magnitude( 23.   ),  1.   )
    assert near( magnitude(   .23 ),  .01  )

    assert near( magnitude( 75.   ), 10.   )
    assert near( magnitude(   .03 ),  .001 )

    # base 2
    assert near( magnitude( 33., 2 ),  16. )
    assert near( magnitude( 50., 2 ),  32. )

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

