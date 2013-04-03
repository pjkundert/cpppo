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
    assert d.a.b == 1
    d.a.b = 2
    assert d["a.b"] == 2
    assert d.a.b == 2

    # dicts already containing dotted keys are converted when assigned
    d2 = {"c.d": 2}
    d.a.b = d2
    assert d.a.b.c.d == 2

    assert "b.c.d" in d.a
