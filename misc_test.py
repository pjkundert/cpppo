from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import threading

from .misc import (
    near, scale, magnitude, centeraxis, natural, change_function, mutexmethod,
    parse_ip_port, ip, network,
    hexdump, hexload,
)

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


def test_parse_ip_port():

    for t,(a,p) in {
        "127.0.0.1":			( ip("127.0.0.1"),			None ),
        "127.0.0.1:80":			( ip("127.0.0.1"),			80 ),
        "::1":				( ip("::1"),				None ),
        "[::1]:80":			( ip("::1"),				80 ),
        "::192.168.0.1":		( ip("::c0a8:1"), 			None ),
        "2605:2700:0:3::4713:93e3":	( ip("2605:2700:0:3::4713:93e3"),	None ),
        "[2605:2700:0:3::4713:93e3]:80":( ip("2605:2700:0:3::4713:93e3"),	80),
        "boogaloo.cash:443":		( "boogaloo.cash",			443 ),
    }.items():
        assert parse_ip_port( t ) == (a,p)

    for t,(a,p) in {
        "127.0.0.1":			( ip("127.0.0.1"),			123 ),
        "127.0.0.1:80":			( ip("127.0.0.1"),			80 ),
        "::1":				( ip("::1"),				123 ),
        "[::1]:80":			( ip("::1"),				80 ),
        "::192.168.0.1":		( ip("::c0a8:1"), 			123 ),
        "2605:2700:0:3::4713:93e3":	( ip("2605:2700:0:3::4713:93e3"),	123 ),
        "[2605:2700:0:3::4713:93e3]:80":( ip("2605:2700:0:3::4713:93e3"),	80),
        "boogaloo.cash:443":		( "boogaloo.cash",			443 ),
    }.items():
        assert parse_ip_port( t, default=(None,123) ) == (a,p)

    assert parse_ip_port( ":11", default=('',456)) == ('',11)
    assert parse_ip_port( ":11", default=('boo',456)) == ('boo',11)
    assert parse_ip_port( "", default=('',456)) == ('',456)

    assert str( network( "192.168.1.0/24" ).broadcast_address ) == "192.168.1.255"

def test_hexdump():
    vals		= b'\x01\x02\x03'

    dump		= hexdump( vals )
    assert dump == '00000000:  01 02 03                                           |...|'
    load		= hexload( dump )
    print( repr( load ))
    assert load == vals

    dump		= hexdump( vals, quote='' )
    assert dump == '00000000:  01 02 03                                           ...'
    load		= hexload( dump )
    print( repr( load ))
    assert load == vals

    dump		= hexdump( vals, quote='' )
    assert dump == '00000000:  01 02 03                                           ...'
    load		= hexload( dump, offset=1 )
    print( repr( load ))
    assert load == vals[1:]

    # fill gaps in addresses, start at an offset
    gaps		= r"""
        00003FD0:  3F D0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |................|
        ... something unparsable ...
        00003FF0:  3F F0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |................|
        00004000:  40 00 30 31 20 53 45 34  20 45 20 32 33 2e 35 63   |@.01 SE4 E 23.5c|
    """
    load		= hexload( gaps, offset=0x3fc0, fill=b'\xFF', skip=True )
    dump		= hexdump( load, offset=0x3fc0 )
    print( dump )
    assert dump == """\
00003FC0:  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff   |................|
00003FD0:  3f d0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |?...............|
00003FE0:  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff   |................|
00003FF0:  3f f0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |?...............|
00004000:  40 00 30 31 20 53 45 34  20 45 20 32 33 2e 35 63   |@.01 SE4 E 23.5c|"""

    # Don't fill, skip unparsable rows
    load		= hexload( gaps, skip=True )
    dump		= hexdump( load )
    print( dump )
    assert dump == """\
00000000:  3f d0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |?...............|
00000010:  3f f0 00 00 00 00 00 00  00 00 00 00 12 00 00 00   |?...............|
00000020:  40 00 30 31 20 53 45 34  20 45 20 32 33 2e 35 63   |@.01 SE4 E 23.5c|"""
    try:
        load		= hexload( gaps )
    except Exception as exc:
        assert str(exc) == "Failed to match a hex dump on row: '        ... something unparsable ...'"
    else:
        raise AssertionError( "Failed to raise Exception, got: {load!r}".format( load=load ))

    # simpler formats that are accepted
    simp		= """\
        0001:01020304
        0005:05
        9:09
    """
    load		= hexload( simp )
    print( repr( load ) )
    dump		= hexdump( load )
    print( dump )
    assert dump == """\
00000000:  01 02 03 04 05 09                                  |......|"""

    load		= hexload( simp, fill=b'\x99' )
    print( repr( load ) )
    dump		= hexdump( load )
    print( dump )
    assert dump == """\
00000000:  99 01 02 03 04 05 99 99  99 09                     |..........|"""
