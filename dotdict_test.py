from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import logging
import os
import sys

# Allow relative imports when executing within package directory, for running tests
sys.path.insert( 0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cpppo


def test_dotdict():
    d = cpppo.dotdict()
    d["a.b"] = 1
    assert d["a.b"] == 1
    assert d.a.b == 1		# attribute access =~= indexing
    d.a.b = 2
    assert d["a.b"] == 2
    assert d.a.b == 2

    # dicts already containing dotted keys are converted when assigned
    d2 = {"c.d": 2}
    d.a.b = d2
    assert d.a.b.c.d == 2

    assert "b.c.d" in d.a

    # Now, test paths containing back-tracking "a.b..c" ==> "a.c".  Of course,
    # this only works with indexing, not attribute access
    d.a.x = 3
    assert d["a.x"] == 3
    assert d["a.b..x"] == 3
    assert d["a.b.c.d....x"] == 3
    # ... but back-tracking past root doesn't work
    try:
        d["..a"]
        assert False, "Should have failed trying to back-track too many levels"
    except KeyError as e:
        assert 'cannot index using key "..a"' in str( e ) 
    try:
        d["a.b...x"]
        assert False, "Should have failed trying to back-track too many levels"
    except KeyError as e:
        assert 'cannot index using key "a.b...x"' in str( e ) 

    # back-tracking doesn't confirm the validity of the ignored key elements:
    assert d["a.b.c.d.e.f....d"] == 2

    # key iteration
    assert list( sorted( k for k in d )) == ['a.b.c.d', 'a.x']

    # Make sure keys/items returns a list/iterator appropriate to Python version
    import types
    assert isinstance( d.keys(), list if sys.version_info.major < 3 else types.GeneratorType )
    assert isinstance( d.items(), list if sys.version_info.major < 3 else types.GeneratorType )
