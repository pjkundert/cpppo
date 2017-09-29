from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import logging
import sys
import threading
import time

from . import misc
from .dotdict import dotdict, apidict


def test_dotdict():
    # Like dict, construct from mapping, iterable and/or keywords
    assert "a" in dotdict({"a":1})
    assert dotdict({"a":1})["a"] == 1

    assert "b" in dotdict({"a":1}, b=2)
    assert dotdict({"a":1}, b=2)["b"] == 2

    assert "c" in dotdict([("c",3)], d=4)
    assert dotdict([("c",3)], d=4)["c"] == 3

    assert "e" in dotdict(e=5)
    assert dotdict(e=5)["e"] == 5

    # Create hierarchies by assignment
    d = dotdict()
    d["a.b"] = 1
    assert d["a.b"] == 1
    assert d.a.b == 1		# attribute access =~= indexing
    d.a.b = 2
    assert d["a.b"] == 2
    assert d.a.b == 2

    # but only one layer at a time by attribute access
    try:
        d.x.y = 99
        assert False, "Shouldn't be able to create y in non-existent x!"
    except AttributeError as e:
        assert "'x'" in str( e )

    # dicts already containing dotted keys are converted when assigned
    d2 = {"c.d": 2}
    d.a.b = d2
    assert d.a.b.c.d == 2

    assert "b.c.d" in d.a
    assert "b.c.x" not in d.a
    assert "e.f" not in d.a
    assert "a.b" in d     # Not a value, but is another layer of dotdict
    assert "a.b.x...b.c.d" in d
    assert "a.b.x....a.b.c.d" in d
    assert "a.b.x" not in d
    assert "a.b.c" in d

    assert isinstance( d.a.b.setdefault( 'c', "boo" ), dotdict )

    # Now, test paths containing back-tracking "a.b..c" ==> "a.c".  Of course,
    # this only works with indexing, not attribute access.  Leading '.' are OK
    # in indexes, consistent with 
    d.a.x = 3
    assert d["a.x"] == 3
    assert d[".a.x"] == 3
    assert d["a.b..x"] == 3
    assert d["a.b.c.d....x"] == 3
    # and back-tracking past root is OK (just like in filesystems)
    d["a...a.x"]
    d["a.b.c...x"]
    assert "a.....a.x" in d
    try:
        d["a.b.c...y"]
        assert False, "Should have failed trying to find y in root"
    except KeyError as e:
        assert "'y'" in str( e ) 

    # back-tracking doesn't confirm the validity of the ignored key elements:
    assert d["a.b.c.d.e.f....d"] == 2

    # key iteration
    assert list( sorted( k for k in d )) == ['a.b.c.d', 'a.x']

    # Make sure keys/items returns a list/iterator appropriate to Python version
    import types
    assert isinstance( d.keys(), list if sys.version_info[0] < 3 else types.GeneratorType )
    assert isinstance( d.items(), list if sys.version_info[0] < 3 else types.GeneratorType )


    # Test deletion, including refusing partial keys (unless empty)
    try:
        del d["a.b.c"]
    except KeyError as e:
        assert "(partial key)" in str( e ) 
    del d["a.b.c.d"]
    # key iteration (does not ignore empty key layers)
    assert list( sorted( k for k in d )) == ['a.b.c', 'a.x']
    del d["a.b.c"]
    assert list( sorted( k for k in d )) == ['a.b', 'a.x']
    # We can dig down using attribute access
    assert d.a.x == 3
    try:
        del d.a.x
    except AttributeError as e:
        assert "x" in str( e )
    del d.a["x"]
    assert list( sorted( k for k in d )) == ['a.b']
    assert "a" in d
    assert "b" in d.a
    assert "c" not in d.a.b
    del d["a.b"]
    del d["a"]
    assert list( sorted( k for k in d )) == []

    # pop has no such restrictions; it will happily pop and return a value or non-empty dotdict
    d["a.b.c.d"] = 2
    d["a.x"] = 3
    assert d.a.b.c.d == 2
    assert d.pop("a.b.c") == {'d':2}
    assert "a.b" in d
    assert "a.b.c" not in d
    assert "x" in d.a
    assert d.pop("a.b.c...x") == 3
    assert "x" not in d.a


def test_indexes():
    """Indexing presently only works for __getitem__, get; not implemented/tested for __setitem__,
    setdefault, del, pop, etc."""
    d = dotdict()

    d['a.b'] = 1
    d['c'] = 2
    d['l'] = [1,2,3,dotdict({'d':3})]

    assert d._resolve( 'a' ) == ( 'a', None )
    assert d._resolve( 'l[a.b+c].d' ) == ( 'l[a.b+c]', 'd' )

    assert d['l[a.b+c].d'] == 3

    try:
        assert d['l[a.b+c-1].d'] == 3
        assert False, "Indexing int, then trying to resolve another level should fail"
    except KeyError as exc:
        assert "not subscriptable" in str(exc)
        pass

    assert d.get( 'l[a.b+c-1].d' ) == None
    assert d.get( 'l[a.b+c].d' ) == 3

    # Also allow indexes in __setattr__/__setitem__, while finding path down to
    # dotdict item to change:
    d['l[3].d'] = 4
    assert d.get( 'l[a.b+c].d' ) == 4
    d['l[a.b+c].d'] = 5
    assert d.get( 'l[a.b+c].d' ) == 5

    # Also allow (valid) indexes (even using local dotdict names) in the final level
    assert d['l[c-1]'] == 2
    d['l[c-1]'] = 99
    assert d['l[c-1]'] == 99

    try:
        d['l[c+3]'] = 3
        assert False, "Indexing with a bad index should fail"
    except IndexError as exc:
        assert "index out of range" in str(exc)
        pass
    

def test_hasattr():
    """Indexing failures returns KeyError, attribute access failures return AttributeError for hasattr
    etc. work.  Also, the concept of attributes is roughly equivalent to our top-level dict keys."""
    d = dotdict()

    d['.a.b'] = 1
    d['.c'] = 2

    assert hasattr( d, 'a' )
    assert hasattr( d, 'a.b' )
    assert not hasattr( d, 'b' )
    assert hasattr( d, 'c' )

    attrs = [ a for a in dir( d ) if not a.startswith('__') ]
    assert 'c' in attrs
    assert 'a' in attrs
    assert 'b' not in attrs
    assert len( attrs ) == 2
    #print( dir( d ))


repeat = 1000
@misc.assert_tps( scale=repeat )
def test_dotdict_performance():
    count = repeat
    while count:
        count -= 1
        test_dotdict()
        test_indexes()


def test_apidict():
    # Ensure that latency doesn't apply to initial import of values by constructor, or to setting
    # items by indexing; only setting by attribute assignment.

    latency = 0.5
    significance = .2 # w/in 20%, for leeway on slow testing hosts
    beg = misc.timer()
    ad = apidict( latency, something='a', another='b' )
    dif = misc.timer() - beg
    assert dif < latency*significance # should be nowhere near latency (close to zero)
    assert ad.something == 'a'

    beg = misc.timer()
    ad.boo = 1
    dif = misc.timer() - beg
    assert dif >= latency
    #assert misc.near( dif, latency, significance=significance ) # rare failures on some Pythons

    beg = misc.timer()
    ad['boo'] = 2
    dif = misc.timer() - beg
    assert dif < latency * significance # but setting items by indexing does not delay!

    # Now, start a thread with a shorter delay; it should invoke __get{attr,item}__, shortening the
    # wait.  Under python 3.3, threading.Condition's wait is implemented using non-polling
    # intrinsic; under prior versions, they poll (max .05s; see threading.py, _Condition.wait) -- so
    # the resolution of the timeout test is reduced to be greater than that margin of error.  The
    # 'significance' of the error is expressed as a multiplication factor of the tested values;
    # eg. .1 --> 10% error allowed vs. the greatest absolute value.  For version of python < 3.3, 
    # allow for a factor at least 0.05 vs. the shorter latency, increased by 10%.  
    
    shorter = latency/2.0
    if (sys.version_info[0], sys.version_info[1]) < (3,3):
        significance = max( significance, 0.05 / shorter * 1.1 )

    def release( base, delay, dd, attr=None, item=None ):
        now = misc.timer()
        logging.debug( "started after %7.3fs", now - base )
        when = base + delay
        if when > now:
            time.sleep( when - now )
        if attr:
            val = getattr( ad, attr )	# Will release apidict
        else:
            val = ad[item]		# Won't release apidict
        logging.debug( "got: %s", val )

    for kwargs in [ {'attr': 'boo'}, {'item': 'boo'}, {'attr': 'noo'}, {'item': 'noo'} ]:
        beg = misc.timer()
        t = threading.Thread( target=release, args=(beg, shorter, ad), kwargs=kwargs )
        t.start()
        #print( "set; significance: ", significance )
        ad.noo = 3 # blocks 'til Thread releases apidict
        dif = misc.timer() - beg
        err = abs( shorter - dif )
        logging.debug( "end; dif: %s, err: %s ==> %s", dif, err, err/shorter )
        # There are unexplained issues with some version of Python (ie. 3.4), with occasional
        # larger than expected delays...  So, just test </>= against full latency 
        assert dif < latency if 'attr' in kwargs else dif >= latency
        #assert misc.near( dif, shorter if 'attr' in kwargs else latency, significance=significance )
        assert ad.noo == 3
        t.join()
