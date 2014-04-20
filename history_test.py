from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import datetime
import logging
import string
import sys

try:
    import reprlib
except ImportError:
    import repr as reprlib

import cpppo
from . import misc
has_pytz			= False
try:
    import pytz
    has_pytz			= True
except ImportError:
    logging.warning( "Failed to import pytz module; skipping history related tests; run 'pip install pytz'" )

got_localzone			= False
if has_pytz:
    try:
        from .history import *
        got_localzone		= True
    except pytz.UnknownTimeZoneError as exc:
        logging.warning( "Failed to determine local timezone; platform requires tzlocal; run 'pip install tzlocal'" )


logging.basicConfig( **cpppo.log_cfg )

    
trtab				= ( string 
                                    if sys.version_info.major < 3
                                    else str ).maketrans( ":-.", "   " )

def utc_strp( loctime ):
    if '.' in loctime:
        unaware			= datetime.datetime.strptime( loctime, timestamp._fmt + ".%f" )
    else:
        unaware			= datetime.datetime.strptime( loctime, timestamp._fmt )
    return pytz.utc.localize( unaware )

def utc_trns( loctime ):
    terms			= loctime.translate( trtab ).split()
    if len( terms ) == 7:
        # convert .123 into 123000 microseconds
        terms[6]           += '0' * ( 6 - len( terms[6] ))
    return datetime.datetime( *map( int, terms ), tzinfo=pytz.utc )


def test_history_timestamp():
    """Ensure timestamp deals in UTC only"""
    if not has_pytz or not got_localzone:
        logging.warning( "Skipping cpppo.history.timestamp tests" )
        return

    timestamp.support_abbreviations( 'CA' )
    assert 'MDT' in timestamp._tzabbrev
    timestamp.support_abbreviations( 'America' )
    timestamp.support_abbreviations( 'Europe' )
    assert 'CEST' in timestamp._tzabbrev
    timestamp.support_abbreviations( 'Asia' )
    timestamp.support_abbreviations( 'Australia' )

    # $ TZ=UTC date --date=@1388559600
    # Wed Jan  1 07:00:00 UTC 2014
    # 1396531199
    # Thu Apr  3 07:19:59 MDT 2014
    assert '2014-01-02 03:04:55.123'.translate( trtab ) == '2014 01 02 03 04 55 123'

    cnt				= 10000
    beg				= misc.timer()
    for _ in range( cnt ):
        utc1			= utc_strp( '2014-01-02 03:04:55.123' )
    dur1			= misc.timer() - beg
    beg				= misc.timer()
    for _ in range( cnt ):
        utc2			= utc_trns( '2014-01-02 03:04:55.123' )
    dur2			= misc.timer() - beg
    beg				= misc.timer()
    for _ in range( cnt ):
        utc3			= timestamp.datetime_from_string( '2014-01-02 03:04:55.123' )
    dur3			= misc.timer() - beg
    assert utc1.strftime( timestamp._fmt ) \
        == utc2.strftime( timestamp._fmt ) \
        == utc3.strftime( timestamp._fmt ) == '2014-01-02 03:04:55'
    logging.detail( "strptime: %d/s, translate: %d/s, timestamp: %d/s", cnt/dur1, cnt/dur2, cnt/dur3 )

    now				= misc.timer()
    assert timestamp( now ) < timestamp( now + 1 )

    # From a numeric timestamp
    ts				= timestamp( 1396531199 )
    assert ts.utc	== '2014-04-03 13:19:59.000' == str( ts )

    assert ts.local	in ( '2014-04-03 07:19:59 MDT',
                             '2014-04-03 13:19:59 UTC' )

    # From a string UTC time
    dt				= timestamp.datetime_from_string( '2014-01-01 07:00:00.0' )
    assert str( dt )	== '2014-01-01 07:00:00+00:00'
    assert repr( dt )	== 'datetime.datetime(2014, 1, 1, 7, 0, tzinfo=<UTC>)'
    #assert dt.strftime( '%s' ) != '1388559600' # !? (will fail if machine is in UTC timezone )
    #assert pytz.utc.normalize( dt ).strftime( '%s' ) != '1388559600' # !?
    assert 1388559559.999999 < timestamp.number_from_datetime( dt ) < 1388559600.000001 # ok
    ts				= timestamp( '2014-01-01 07:00:00.0' )
    assert  1388559559.999999 < ts.value < 1388559600.000001
    assert ts.utc	== '2014-01-01 07:00:00.000' == str( ts )
    assert ts.local	in ( '2014-01-01 00:00:00 MST',
                             '2014-01-01 07:00:00 UTC' )

    # OK, now try a UTC time where the local timezone is in MDT
    ts.utc			= '2014-04-01 07:00:00.000'
    assert ts.local	in ( '2014-04-01 01:00:00 MDT',
                             '2014-04-01 07:00:00 UTC' )

    # Make sure that local times are unambiguous over daylight savings time
    # Mar 9 02:00 -> 03:00    1394355540 == Mar 9 2014 01:59
    # Nov 2 02:00 -> 01:00    1414915140 == Nov 2 2014 01:59
    ts				= timestamp( 1394355540 )
    assert ts.local	in ( '2014-03-09 01:59:00 MST',
                             '2014-03-09 08:59:00 UTC' )
    ts			       += 61
    assert ts.local	in ( '2014-03-09 03:00:01 MDT',
                             '2014-03-09 09:00:01 UTC' )

    ts				= timestamp( 1414915140 )
    assert ts.local	in ( '2014-11-02 01:59:00 MDT',
                             '2014-11-02 07:59:00 UTC' )
    ts			       += 61
    assert ts.local	in ( '2014-11-02 01:00:01 MST',
                             '2014-11-02 08:00:01 UTC' )

    # Now try converting a few strings that have a specific timezone.  We can use either .utc =
    # ... or .local = ...; they just default to the UTC or (local) timezone, respectively.  Using a
    # DST-specific timezone such as MST/MDT, we can unambiguously specify whether a time is inside
    # or outside DST.
    try:
        ts.local		= '2014-03-09 02:00:01 America/Edmonton' # Just inside MDT 2014
        assert False, """Should have failed -- time doesn't exist during "spring ahead" """
    except Exception as exc:
        assert "NonExistentTimeError" in str( exc )
    ts.local			= '2014-03-09 03:00:01 MDT' # Just inside MDT 2014
    assert 1394355600.999999 < ts.value < 1394355601.000001
    assert ts.utc 	==   '2014-03-09 09:00:01.000' # MDT == UCT-6:00
    assert ts.local	in ( '2014-03-09 03:00:01 MDT',
                             '2014-03-09 09:00:01 UTC' )
    # However, we CAN use a specifically non-DST timezone to specify times non-existent in DST
    ts.local			= '2014-03-09 02:00:01 MST' # No such time in MDT!!
    assert 1394355600.999999 < ts.value < 1394355601.000001
    assert ts.utc	==   '2014-03-09 09:00:01.000'
    assert ts.local	in ( '2014-03-09 03:00:01 MDT',
                             '2014-03-09 09:00:01 UTC' )

    ts.local			= '2014-11-02 01:00:01 MST' # 1 second after the end of DST
    assert 1414915200.999999 < ts.value < 1414915201.000001
    assert ts.utc	==   '2014-11-02 08:00:01.000'
    assert ts.local	in ( '2014-11-02 01:00:01 MST',
                             '2014-11-02 08:00:01 UTC' )

    ts			       -= 2 # Go back 2 seconds, into DST
    assert ts.utc	==   '2014-11-02 07:59:59.000'
    assert ts.local	in ( '2014-11-02 01:59:59 MDT',
                             '2014-11-02 07:59:59 UTC' )

    ts.local			= '2014-11-02 01:59:58 MDT' # 2 seconds before end of DST
    assert 1414915197.999999 < ts.value < 1414915198.000001
    assert ts.utc	==   '2014-11-02 07:59:58.000'
    assert ts.local	in ( '2014-11-02 01:59:58 MDT',
                             '2014-11-02 07:59:58 UTC' )

    # Using a canonical timezone such as 'America/Edmonton', an "ambiguous" time (eg. during the
    # overlap in the fall) cannot be specified.  Using a DST-specific timezone, we can.
    try:
        ts.local		= '2014-11-02 01:00:01 America/Edmonton' # Inside DST?
    except Exception as exc:
        assert "AmbiguousTimeError" in str( exc )

    ts.local			= '2014-11-02 00:59:59 America/Edmonton' # 2 seconds before end of DST
    assert 1414911598.999999 < ts.value < 1414911599.000001
    assert ts.utc	==   '2014-11-02 06:59:59.000'
    assert ts.local	in ( '2014-11-02 00:59:59 MDT',
                             '2014-11-02 06:59:59 UTC' )

    after			= timestamp( '2014-11-02 01:02:03.123 MST' ) # (Nov 2 2014 -- 1:02 *after* DST ended)
    before			= timestamp( '2014-11-02 01:02:03.456 MDT' ) # (Nov 2 2014 --  :58 *before* DST ends)
    assert before < after
    assert before.utc	==   '2014-11-02 07:02:03.456'
    assert before.local	in ( '2014-11-02 01:02:03 MDT',
                             '2014-11-02 07:02:03 UTC' )
    assert after.utc	==   '2014-11-02 08:02:03.123'
    assert after.local	in ( '2014-11-02 01:02:03 MST',
                             '2014-11-02 08:02:03 UTC' )

    after			= timestamp( '2014-10-26 02:01:00.123 CET' )  # (Nov 26 2014 -- 1:02 *after* DST ended)
    before			= timestamp( '2014-10-26 02:01:00.456 CEST' ) # (Nov 26 2014 --  :58 *before* DST ends)
    assert before < after
    assert before.utc	==   '2014-10-26 00:01:00.456'
    assert before.local	in ( '2014-10-25 18:01:00 MDT',
                             '2014-10-26 00:01:00 UTC' )
    assert after.utc	==   '2014-10-26 01:01:00.123'
    assert after.local	in ( '2014-10-25 19:01:00 MDT',
                             '2014-10-26 01:01:00 UTC' )

