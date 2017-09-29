from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import os

from ..misc import timer, near
from . import waits

def test_waits():
    assert all( waits.existence()( "/etc/hosts" ))
    assert all( waits.existence()( __file__ + "%^def test_waits" ))

    assert not all( waits.existence()( .1, __file__ + ".boo" )) # timeout on filename
    assert not all( waits.existence()( .1, __file__ + "%^boo" )) # timeout on regex

    # Ensure timeout delay is computed correctly (exponential back-off)

    # A bare .25-second timeout.  The timeout delay should implemented after
    # yielding last value, but before raising StopIteration.
    v			= .25
    a			= iter( waits.existence()( str( v )))
    beg			= timer()
    assert next( a ) == True
    assert 0.0 <= timer() - beg < v * 0.1
    try:
        next( a )
        assert False, "waits iterator shouldn't have yielded any more values"
    except StopIteration:
        pass
    assert v <= timer() - beg < v * 1.1

    # A 100 second timeout on an existing file (this one)
    v			= 100
    a			= iter( waits.existence()( str( v ), __file__ ))
    beg			= timer()
    assert next( a ) == True
    assert 0.0 <= timer() - beg < v * 0.1

    now			= a.started
    # full 100 seconds remaining; initial delay should be .delay_min, should max
    # out at delay_max
    assert near( a.delay( target=0, now=now ), a.delay_min )
    assert near( a.delay( target=v, now=now ), a.delay_max )

    # Before elapsed + target reaches 1/2 the timeout, we'll see durations of up
    # to the lesser of target or delay_max
    dur			= v*1/4
    now			= a.started + dur
    rem			= a.timeout - dur
    assert near( a.delay( target=0,     now=now ), a.delay_min )
    assert near( a.delay( target=dur/2, now=now ), dur/2 )
    assert near( a.delay( target=dur,   now=now ), dur )
    assert near( a.delay( target=dur*2, now=now ), min( dur*2, a.delay_max ))

    # After 1/2 the timeout passes, we'll begin to see durations of 1/2 the remainder.
    dur			= v*1/2
    now			= a.started + dur
    rem			= a.timeout - dur
    assert near( a.delay( target=v, now=now ), rem/2 )

    dur			= v*4/5
    now			= a.started + dur
    rem			= a.timeout - dur
    assert near( a.delay( target=v, now=now ), rem/2 )

def test_waits_presence():
    # Inaccessible files are "indeterminate", and thus require a timeout; they
    # are treated as if they don't yet exist.
    beg			= timer()
    iamroot		= os.geteuid() == 0
    assert all( waits.existence()( .1, "/etc/shadow" )) == iamroot
    if iamroot:
        assert timer() - beg < .1
    else:
        assert .1 <= timer() - beg < .2

    # We can reverse presence detection.  Check that we can fail due to a file that exists
    beg			= timer()
    assert all( waits.existence( terms=[ .1, __file__ ], presence=False )) == False
    assert .1 <= timer() - beg < .2
    # But a file that doesn't exist completes right away
    beg			= timer()
    assert all( waits.existence( terms=[ __file__+"asdfds" ], presence=False )) == True
    assert  timer() - beg < .1
    beg			= timer()
    assert all( waits.existence( terms=[ "+inf", __file__+"asdfds" ], presence=False )) == True
    assert  timer() - beg < .1
    beg			= timer()
    assert all( waits.existence( terms=[ ".1", __file__+"asdfds" ], presence=False )) == True
    assert  timer() - beg < .1
    # and a failing regex is the same as not existing
    beg			= timer()
    assert all( waits.existence( terms=[ .1, __file__+"%^asdfsdaf" ], presence=False )) == True
    assert  timer() - beg < .1
    # but a matching regex has to be timed out and fails
    beg			= timer()
    assert all( waits.existence( terms=[ .1, __file__+"%^def test_waits_presence" ], presence=False )) == False
    assert .1 <= timer() - beg < .2

def test_waits_duration():
    truth,timing	= next( waits.duration( waits.existence( [ lambda: True ], timeout=1.0 )))
    assert truth is True and timing <= .01
    truth,timing	= next( waits.duration( waits.existence( [ lambda: False ], timeout=.25 )))
    assert truth is False and .25 <= timing <= .25+.01
