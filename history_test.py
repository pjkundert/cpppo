from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

import datetime
import json
import logging
import os
import pytest
import random
import string
import sys
import time

# For the purposes of this history_test, we assume the Canada/Mountain timezone 
os.environ['TZ']		= "Canada/Mountain"

if __name__ == "__main__":
    # If you run tests in-place (instead of using py.test), ensure local version is tested!
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from cpppo.automata import log_cfg
    logging.basicConfig( **log_cfg )
    logging.getLogger().setLevel( logging.NORMAL )

from cpppo import timer, near, reprlib


has_pytz			= False
try:
    import pytz
    has_pytz			= True
except ImportError:
    logging.warning( "Failed to import pytz module; skipping history related tests; run 'pip install pytz'" )

got_localzone			= False
if has_pytz:
    try:
        from cpppo.history import (
            timestamp, parse_offset, format_offset, timedelta_total_seconds,
            AmbiguousTimeZoneError, HistoryExhausted, IframeError, DataError, 
            opener, loader, reader, logger )
        got_localzone		= True
    except pytz.UnknownTimeZoneError as exc:
        logging.warning( "Failed to determine local timezone; platform requires tzlocal; run 'pip install tzlocal'" )


@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_timestamp_abbreviations():
    """Test timezone abbreviation support. """
    abbrev			= timestamp.support_abbreviations( 'CA', reset=True )
    assert sorted( abbrev ) == ['ADT', 'AST', 'CDT', 'CST', 'EDT', 'EST', 'MDT', 'MST', 'NDT', 'NST', 'PDT', 'PST']

    # Perform all the remaining timezone abbreviation tests relative to a known range of times, to
    # avoid differences in the future due to timezone changes.
    ts				= timestamp( "2014-04-24 08:00:00 MDT" )
    assert near( ts.value, 1398348000.0 )

    # Try to add all of the Americas to the CA abbreviations already supported; can't be done (too
    # many inconsistencies)
    try:
        abbrev			= timestamp.support_abbreviations( 'America' )
        assert False, "Many zones should have been ambiguously abbreviated"
    except AmbiguousTimeZoneError as exc:
        assert "America/Mazatlan" in str( exc )

    exclude			= [
        'America/Mazatlan', 'America/Merida', 'America/Mexico_City', 'America/Monterrey',
        'America/Bahia_Banderas', 'America/Cancun', 'America/Chihuahua', 'America/Havana',
        'America/Santa_Isabel', 'America/Grand_Turk', 'America/Cayman', 'America/Port-au-Prince',
        'America/Metlakatla',
    ]
    #print()
    #print( "America, w/o %r" % ( exclude ))
    abbrev			= timestamp.support_abbreviations( 'America', exclude=exclude )
    #print( sorted( abbrev ))
    #print( reprlib.repr( timestamp._tzabbrev ))
    pytz_version		= tuple( map( int, pytz.__version__.split( '.' )))
    if pytz_version < (2015,4):
        logging.warning( "pytz < 2015.4; HADT/HAST vs. HDT/HST" )
        assert sorted( abbrev ) == ['ACT', 'AKDT', 'AKST', 'AMST', 'AMT', 'ART', 'BOT', 'BRST', 'BRT', 'CLST', 'CLT',
                                    'COT', 'ECT', 'EGST', 'EGT', 'FNT', 'GFT', 'GMT', 'GYT', 'HADT', 'HAST',
                                    'PET', 'PMDT', 'PMST', 'PYST', 'PYT', 'SRT', 'UYST', 'UYT', 'VET', 'WGST', 'WGT']
    elif pytz_version < (2015,7):
        logging.warning( "pytz < 2015.7; had UYST" )
        assert sorted( abbrev ) == ['ACT', 'AKDT', 'AKST', 'AMST', 'AMT', 'ART', 'BOT', 'BRST', 'BRT', 'CLST', 'CLT',
                                    'COT', 'ECT', 'EGST', 'EGT', 'FNT', 'GFT', 'GMT', 'GYT', 'HDT', 'HST',
                                    'PET', 'PMDT', 'PMST', 'PYST', 'PYT', 'SRT', 'UYST', 'UYT', 'VET', 'WGST', 'WGT']
    elif pytz_version < (2017,2):
        assert sorted( abbrev ) == ['ACT', 'AKDT', 'AKST', 'AMST', 'AMT', 'ART', 'BOT', 'BRST', 'BRT', 'CLST', 'CLT',
                                    'COT', 'ECT', 'EGST', 'EGT', 'FNT', 'GFT', 'GMT', 'GYT', 'HDT', 'HST',
                                    'PET', 'PMDT', 'PMST', 'PYST', 'PYT', 'SRT', 'UYT', 'VET', 'WGST', 'WGT']
    else:
        # As of pytz 2017.2, alot of these zones are now using time zones consistent with CA; only a few added.
        assert sorted( abbrev ) == ['AKDT', 'AKST', 'GMT', 'HDT', 'HST']

    # We *can* add Europe/Berlin
    abbrev			= timestamp.support_abbreviations( 'Europe/Berlin' )
    assert sorted( abbrev ) == ['CEST', 'CET']
    assert 'CEST' in timestamp._tzabbrev
    assert 'EEST' not in timestamp._tzabbrev

    # And all of Europe, w/o some troublesome time zones
    exclude			= [ 'Europe/Simferopol', 'Europe/Istanbul', 'Europe/Minsk', 'Europe/Chisinau', 'Europe/Dublin' ]
    #print()
    #print( "Europe, w/o %r" % ( exclude ))
    abbrev			= timestamp.support_abbreviations( 'Europe', exclude=exclude )
    #print( sorted( abbrev ))
    if pytz_version < (2015,2):
        assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'MSK', 'SAMT', 'WEST', 'WET']
    elif pytz_version < (2016,3):
        assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'IST', 'MSK', 'SAMT', 'WEST', 'WET']
    elif pytz_version < (2016,7):
        assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'IST', 'MSK', 'SAMT', 'WEST', 'WET']
    elif pytz_version < (2018,5):
        assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'IST', 'MSK', 'WEST', 'WET']
    else:
        assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'MSK', 'WEST', 'WET']
        
    assert 'EEST' in timestamp._tzabbrev
    try:
        timestamp.support_abbreviations( 'Asia' )
        assert False, "Asia/Jerusalem IST should have mismatched Europe/Dublin IST"
    except AmbiguousTimeZoneError as exc:
        assert "Asia/Jerusalem" in str( exc )

    assert near( parse_offset( '< 1:00:00.001' ),	-3600.001 )
    assert near( parse_offset( '<:1.001' ), 		   -1.001 )
    assert near( parse_offset( '>1:0.001' ),		   60.001 )
    assert near( parse_offset( '>1' ), 			    1 )

    # While Asia is internally very inconsistent (eg. EEST), countries should be internally consisent
    abbrev			= timestamp.support_abbreviations( 'JO', reset=True ) # Jordan
    #print( sorted( abbrev ))
    assert sorted( abbrev ) == [ 'EEST', 'EET']
    z,dst,off			= timestamp._tzabbrev['EEST']
    assert str(z) == 'Asia/Amman'	and dst == True  and format_offset( timedelta_total_seconds( off ), ms=None ) == "> 3:00:00"
    abbrev			= timestamp.support_abbreviations( 'IE', reset=True ) # Israel
    #print( sorted( abbrev ))
    assert sorted( abbrev ) == [ 'GMT', 'IST' ]
    # Jordan, Israel and Lebanon only work if we pick a region to exclude, for one EEST definition
    abbrev			= timestamp.support_abbreviations( ['JO', 'IE', 'LB'],
                                                                   exclude=[ 'Asia/Amman' ], reset=True )
    #print( sorted( abbrev ))
    assert sorted( abbrev ) == [ 'EEST', 'EET', 'GMT', 'IST' ]
    z,dst,off			= timestamp._tzabbrev['EEST']
    assert str(z) == 'Asia/Beirut'	and dst == True  and format_offset( timedelta_total_seconds( off ), ms=None ) == "> 3:00:00"

    # Australia zones incompatible with a bunch of other timezone abbreviations, eg. CST; reset
    abbrev			= timestamp.support_abbreviations( 'Australia', reset=True )
    #print( sorted( abbrev ))
    #print( repr( timestamp._tzabbrev ))
    if pytz_version < (2017,2):
        assert sorted( abbrev ) == ['ACDT', 'ACST', 'ACWST', 'AEDT', 'AEST', 'AWST', 'LHDT', 'LHST']
        z,dst,off		= timestamp._tzabbrev['LHST']
        assert str(z) == 'Australia/Lord_Howe'	and dst == False and format_offset( timedelta_total_seconds( off ), ms=None ) == ">10:30:00"
    else:
        assert sorted( abbrev ) ==  ['ACDT', 'ACST', 'AEDT', 'AEST', 'AWST']


    # Ensure that non-ambiguous (DST-specific) zone abbreviations override ambiguous (no longer
    # relevant, as pytz >= 2014.7 no longer contains dst == None for some of the Australian zones
    # without DST)
    abbrev			= timestamp.support_abbreviations( [ 'Australia/Adelaide' ], reset=True )
    assert sorted( abbrev ) == [ 'ACDT', 'ACST' ]
    z,dst,off			= timestamp._tzabbrev['ACST']
    assert str(z) == 'Australia/Adelaide'	and dst == False and format_offset( timedelta_total_seconds( off ), ms=None ) == "> 9:30:00"
    abbrev			= timestamp.support_abbreviations( [ 'Australia/Adelaide', 'Australia/Darwin' ], reset=True )
    #print( sorted( abbrev ))
    #print( repr( timestamp._tzabbrev ))
    z,dst,off			= timestamp._tzabbrev['ACST']
    assert str(z) in ( 'Australia/Darwin',
                       'Australia/Adelaide' ) and dst == False and format_offset( timedelta_total_seconds( off ), ms=None ) == "> 9:30:00"

    # Check that zones with complete, permanent offset changes (not just DST) are handled.  We know
    # that within a year of 2014-04-28, the America/Eirunepe (west Amazonas) zone had such a change
    # (pre pytz 2017.2, anyway...)
    if pytz_version < (2017,2):
        abbrev			= timestamp.support_abbreviations( [ 'America/Eirunepe' ], at=datetime.datetime( 2014, 4, 28 ), reset=True)
        #print( sorted( abbrev ))
        assert sorted( abbrev ) == [ 'ACT', 'AMT' ]
        z,dst,off			= timestamp._tzabbrev['ACT']
        assert str(z) == 'America/Eirunepe'		and dst == False and format_offset( timedelta_total_seconds( off ), ms=None ) == "< 5:00:00"
        z,dst,off			= timestamp._tzabbrev['AMT']
        assert str(z) == 'America/Eirunepe'		and dst == False and format_offset( timedelta_total_seconds( off ), ms=None ) == "< 4:00:00"


@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_timestamp():
    """Test timestamp, ensuring comparison deals in UTC only.  Supports testing in local timezones:
    
        Canada/Edmonton		-- A generic, ambiguous DST/non-DST timezone
        MST			-- A DST-specific non-DST timezone
        UTC			-- UTC

    """
    trtab			= ( string 
                                    if sys.version_info[0] < 3
                                    else str ).maketrans( ":-.", "   " )

    def utc_strp( loctime ):
        if '.' in loctime:
            unaware		= datetime.datetime.strptime( loctime, timestamp._fmt + ".%f" )
        else:
            unaware		= datetime.datetime.strptime( loctime, timestamp._fmt )
        return pytz.utc.localize( unaware )

    def utc_trns( loctime ):
        terms			= loctime.translate( trtab ).split()
        if len( terms ) == 7:
            # convert .123 into 123000 microseconds
            terms[6]               += '0' * ( 6 - len( terms[6] ))
        return datetime.datetime( *map( int, terms ), tzinfo=pytz.utc )

    # Basic millisecond hygiene.  Comparisons are by standard UTC format to 3 sub-second decimal
    # places of precision.  Unfortunately, the Python 2/3 strftime microsecond formatters are
    # different, so we don't use them.  If no precision, we do NOT round; we truncate, to avoid the
    # surprising effect of formatting a UNIX value manually using strftime produces a different
    # second than formatting it using render() with no sub-second precision.
    assert timestamp( 1399326141.999836 ) >= timestamp( 1399326141.374836 )
    assert timestamp( 1399326141.999836 ).render( ms=False ) == '2014-05-05 21:42:21'
    assert timestamp( 1399326141.999836 ).render( ms=5 ) == '2014-05-05 21:42:21.99984'
    assert timestamp( 1399326141.999836 ).render() == '2014-05-05 21:42:22.000'

    # Type caste support
    assert abs( float( timestamp( 1399326141.999836 )) - 1399326141.999836 ) < 1e-6
    assert int( timestamp( 1399326141.999836 )) == 1399326141

    # Adjust timestamp default precision and comparison epsilon.
    save			= timestamp._precision,timestamp._epsilon
    try:
        ts			= timestamp( 1399326141.999836 )
        for p in range( 0, 7 ):
            timestamp._precision= p
            timestamp._epsilon	= 10**-p if p else 0

            assert ts.render( ms=True ) == {
                0: '2014-05-05 21:42:21', # Truncates at 0 digits of sub-second precision
                1: '2014-05-05 21:42:22.0',
                2: '2014-05-05 21:42:22.00',
                3: '2014-05-05 21:42:22.000',
                4: '2014-05-05 21:42:21.9998',
                5: '2014-05-05 21:42:21.99984',
                6: '2014-05-05 21:42:21.999836',
            }[timestamp._precision]
            # For p == 0, try exact precision.  1e-6 is the smallest delta that can be reliably
            # added to a typical UNIX timestamp (eg.  1399326141.999836) in a double and still
            # expect it to affect the value (can store 15-17 decimal digits of precision).
            s,l			= (timestamp._epsilon*f for f in (0.9,1.1)) if p else (0,10**-6)
            assert     ts == ts + s
            assert     ts == ts - s
            assert not(ts == ts + l)
            assert not(ts == ts - l)
            assert     ts != ts + l
            assert     ts != ts - l
            assert not(ts <  ts + s)
            assert not(ts <  ts - s)
            assert     ts <  ts + l
            assert not(ts <  ts - l)
            assert     ts <= ts + s
            assert     ts <= ts - s
            assert     ts <= ts + l
            assert not(ts <= ts - l)
            assert not(ts >  ts + s)
            assert not(ts >  ts - s)
            assert not(ts >  ts + l)
            assert     ts >  ts - l
            assert     ts >= ts + s
            assert     ts >= ts - s
            assert not(ts >= ts + l)
            assert     ts >= ts - l
    finally:
        timestamp._precision,timestamp._epsilon = save


    # Maintain DST specificity when rendering in DST-specific timezones?  Nope, only when using
    # specially constructed non-DST versions of timezones, when they are made available by pytz.
    timestamp.support_abbreviations( None, reset=True )

    assert timestamp.timezone_info('MST') == (pytz.timezone( 'MST' ),None)
    assert timestamp( 1399326141.999836 ).render(
        tzinfo='MST', ms=False )		== '2014-05-05 14:42:21 MST'

    # Get MST/MDT etc., and CET/CEST abbreviations
    timestamp.support_abbreviations( ['CA','Europe/Berlin'], reset=True )

    assert timestamp.timezone_info('MST') == (pytz.timezone( 'America/Edmonton' ),False)
    assert timestamp( 1399326141.999836 ).render(
        tzinfo='MST', ms=False )		== '2014-05-05 15:42:21 MDT'


    # $ TZ=UTC date --date=@1388559600
    # Wed Jan  1 07:00:00 UTC 2014
    # 1396531199
    # Thu Apr  3 07:19:59 MDT 2014
    assert '2014-01-02 03:04:55.123'.translate( trtab ) == '2014 01 02 03 04 55 123'

    cnt				= 10000
    beg				= timer()
    for _ in range( cnt ):
        utc1			= utc_strp( '2014-01-02 03:04:55.123' )
    dur1			= timer() - beg
    beg				= timer()
    for _ in range( cnt ):
        utc2			= utc_trns( '2014-01-02 03:04:55.123' )
    dur2			= timer() - beg
    beg				= timer()
    for _ in range( cnt ):
        utc3			= timestamp.datetime_from_string( '2014-01-02 03:04:55.123' )
    dur3			= timer() - beg
    assert utc1.strftime( timestamp._fmt ) \
        == utc2.strftime( timestamp._fmt ) \
        == utc3.strftime( timestamp._fmt ) == '2014-01-02 03:04:55'
    logging.detail( "strptime: %d/s, translate: %d/s, timestamp: %d/s", cnt/dur1, cnt/dur2, cnt/dur3 )

    now				= timer()
    assert timestamp( now ) < timestamp( now + 1 )

    # From a numeric timestamp
    ts				= timestamp( 1396531199 )
    assert ts.utc	== '2014-04-03 13:19:59.000' == str( ts )

    assert ts.local	in ( '2014-04-03 07:19:59 MDT',
                             '2014-04-03 06:19:59 MST',
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
                             '2014-04-01 00:00:00 MST',
                             '2014-04-01 07:00:00 UTC' )

    # Make sure that local times are unambiguous over daylight savings time
    # Mar 9 02:00 -> 03:00    1394355540 == Mar 9 2014 01:59
    # Nov 2 02:00 -> 01:00    1414915140 == Nov 2 2014 01:59
    ts				= timestamp( 1394355540 )
    assert ts.local	in ( '2014-03-09 01:59:00 MST',
                             '2014-03-09 08:59:00 UTC' )
    ts			       += 61
    assert ts.local	in ( '2014-03-09 03:00:01 MDT',
                             '2014-03-09 02:00:01 MST',
                             '2014-03-09 09:00:01 UTC' )

    ts				= timestamp( 1414915140 )
    assert ts.local	in ( '2014-11-02 01:59:00 MDT',
                             '2014-11-02 00:59:00 MST',
                             '2014-11-02 07:59:00 UTC' )
    ts			       += 61
    assert ts.local	in ( '2014-11-02 01:00:01 MST',
                             '2014-03-09 02:00:01 MST',
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
                             '2014-03-09 02:00:01 MST',
                             '2014-03-09 09:00:01 UTC' )
    # However, we CAN use a specifically non-DST timezone to specify times non-existent in DST
    ts.local			= '2014-03-09 02:00:01 MST' # No such time in MDT!!
    assert 1394355600.999999 < ts.value < 1394355601.000001
    assert ts.utc	==   '2014-03-09 09:00:01.000'
    assert ts.local	in ( '2014-03-09 03:00:01 MDT',
                             '2014-03-09 02:00:01 MST',
                             '2014-03-09 09:00:01 UTC' )

    ts.local			= '2014-11-02 01:00:01 MST' # 1 second after the end of DST
    assert 1414915200.999999 < ts.value < 1414915201.000001
    assert ts.utc	==   '2014-11-02 08:00:01.000'
    assert ts.local	in ( '2014-11-02 01:00:01 MST',
                             '2014-11-02 00:59:59 MST',
                             '2014-11-02 08:00:01 UTC' )

    ts			       -= 2 # Go back 2 seconds, into DST
    assert ts.utc	==   '2014-11-02 07:59:59.000'
    assert ts.local	in ( '2014-11-02 01:59:59 MDT',
                             '2014-11-02 00:59:59 MST',
                             '2014-11-02 07:59:59 UTC' )

    ts.local			= '2014-11-02 01:59:58 MDT' # 2 seconds before end of DST
    assert 1414915197.999999 < ts.value < 1414915198.000001
    assert ts.utc	==   '2014-11-02 07:59:58.000'
    assert ts.local	in ( '2014-11-02 01:59:58 MDT',
                             '2014-11-02 00:59:58 MST',
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
                             '2014-11-01 23:59:59 MST',
                             '2014-11-02 06:59:59 UTC' )

    after			= timestamp( '2014-11-02 01:02:03.123 MST' ) # (Nov 2 2014 -- 1:02 *after* DST ended)
    before			= timestamp( '2014-11-02 01:02:03.456 MDT' ) # (Nov 2 2014 --  :58 *before* DST ends)
    assert before < after
    assert before.utc	==   '2014-11-02 07:02:03.456'
    assert before.local	in ( '2014-11-02 01:02:03 MDT',
                             '2014-11-02 00:02:03 MST',
                             '2014-11-02 07:02:03 UTC' )
    assert after.utc	==   '2014-11-02 08:02:03.123'
    assert after.local	in ( '2014-11-02 01:02:03 MST',
                             '2014-11-02 08:02:03 UTC' )

    after			= timestamp( '2014-10-26 02:01:00.123 CET' )  # (Nov 26 2014 -- 1:02 *after* DST ended)
    before			= timestamp( '2014-10-26 02:01:00.456 CEST' ) # (Nov 26 2014 --  :58 *before* DST ends)
    assert before < after
    assert before.utc	==   '2014-10-26 00:01:00.456'
    assert before.local	in ( '2014-10-25 18:01:00 MDT',
                             '2014-10-25 17:01:00 MST',
                             '2014-10-26 00:01:00 UTC' )
    assert after.utc	==   '2014-10-26 01:01:00.123'
    assert after.local	in ( '2014-10-25 19:01:00 MDT',
                             '2014-10-25 18:01:00 MST',
                             '2014-10-26 01:01:00 UTC' )


@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_opener():
    # Try opening all the compressed files in the 2 acceptable ways: context or iterator
    path		=  'tests/history'
    for f in os.listdir( path ):
        if f.startswith( 'hi' ):
            with opener( os.path.join( path, f )) as fd:
                assert next( fd ).decode() == "hi\n"
            try:
                fd	= opener( os.path.join( path, f ))
                for line in fd:
                    assert line.decode() == "hi\n"
            finally:
                fd.close()


@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_sequential():
    for _ in range( 3 ):
        path		= "/tmp/test_sequential_%d" % random.randint( 100000, 999999 )
        if os.path.exists( path ):
            continue
    assert not os.path.exists( path ), "Couldn't find an unused name: %s" % path 

    files		= []
    try:
        # Create a series of history files with decreasing timestamps as the numeric extension
        # increases.  Note: times are truncated to milliseconds, so timestamps saved out will
        # probably evaluate as < the original value when read back in!  Since each file contains
        # only one record, we must be careful to use 'strict', to ensure we open the next file
        # strictly greater than the last timestamp (or we'll open the same file again!)
        now		= timer()
        count		= 10
        for e in range( count ):
            f		= path + (( '.%d' % e ) if e else '') # 0'th file has 0 extension
            files.append( f )
            with logger( f ) as l:
                l.write( { 40001: count - e }, now=now - e )
            if e:
                # Compress .1 onward using a random format; randomly delete origin uncompressed file
                # so sometimes both files exist
                if random.choice( (True, False, False, False) ):
                    continue # Don't make a compressed version of  some files
                fz	 = f + '.%s' % random.choice( ('gz', 'bz2', 'xz') )
                files.append( fz )
                with opener( fz, mode='wb' ) as fd:
                    with open( f, 'rb' ) as rd:
                        fd.write( rd.read() )
                if random.choice( (True, False, False) ):
                    continue # Don't remove some of the uncompressed files
                os.unlink( f )
                files.pop( files.index( f ))

        # Attempt to begin loading history around the middle of the recording
        rdr		= reader( path,
                                  historical=now - random.uniform( 3.0, 9.0 ),
                                  basis=now + random.uniform( -.5, +.5 ),
                                  factor=3 )

        # Begin with the first historical file before our computed advancing historical time (we
        # could provide a specific timestamp here, if we wanted).  No lookahead.
        ts_l		= None
        f_l		= None
        after		= False # only first open is "before"; rest are "after"
        strict		= False # only goes false when timestamp increases in the same file
        deadline	= now + count
        while timer() <= deadline:
            # open next file beginning after the last ts
            o		= rdr.open( target=ts_l, after=after, strict=strict ) # Generator; doesn't do much here...
            after	= True
            strict	= True
            for (f,l,cur),(ts,js) in o: # raises HistoryExhausted on open() generator failure
                assert ts_l is None or ts >= ts_l, \
                    "Historical record out of sequence; %s isn't >= %s" % ( ts, ts_l )
                ts_l	= ts
                if js is None:
                    logging.info( "@%s: not yet available", ts )
                    assert ts > cur, "Next record should have been returned; not in future"
                    time.sleep( .1 )
                else:
                    logging.normal( "@%s: %r", ts, js )
                    assert ts <= cur, "Next record shouldn't have been returned; yet future"
                    if f == f_l and ts > ts_l:
                        strict = False
                f_l,ts_l= f,ts
        assert False, "Should have raised HistoryExhausted by now"
    except HistoryExhausted as exc:
        logging.normal( "History exhausted: %s", exc )

    except Exception as exc:
        logging.normal( "Test failed: %s", exc )
        raise

    finally:
        for f in files:
            logging.detail( "unlinking %s", f )
            try:
                os.unlink( f )
            except:
                pass


@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_unparsable():
    """Test history files rendered unparsable due to dropouts.  This should be handled with no problem
    except if the initial frame of register data on the first file is missing.

    """
    for _ in range( 3 ):
        path		= "/tmp/test_unparsable_%d" % random.randint( 100000, 999999 )
        if os.path.exists( path ):
            continue
    assert not os.path.exists( path ), "Couldn't find an unused name: %s" % path 

    files		= []
    try:
        # Create a series of history files with decreasing timestamps as the numeric extension
        # increases, containing records that are invalid.
        now		= timer()
        v		= 10000
        secs		= 10
        secs_ext	=  1.0  # adjust range of history to target out by this +/-
        basisext	=   .5  # adjust start basis time from now by this +/-
        minfactor	=   .25
        maxfactor	=  2.0
        maxlatency	=   .25
        # 1/N file lines corrupted (kills 2 records; the current and following).  0 --> no errors
        maxerror	= random.choice( [ None, 3, 10, 100 ] )
        oldest		= None
        newest		= None
        logging.normal( "Corrupting %s of all history lines", None if not maxerror else "1/%d" % maxerror )
        for e in range( secs ):
            f		= path + (( '.%d' % e ) if e else '') # 0'th file has no extension
            files.append( f )
            with logger( f ) as l:
                ssend	= 100
                for ss in range( 0, ssend ): # subseconds up to but not including ssend...
                    js	= json.dumps( { 40001: v + e * 1000 + (ss * 1000 // ssend) } ) + '\n'
                    if maxerror and not random.randint( 0, maxerror ):
                        # Truncate some of the records (as would occur in a filesystem full or halt)
                        js = js[:random.randint( 0, len( js ) - 1)]
                    ts	= timestamp( now - e + ss/ssend )
                    if oldest is None or ts < oldest:
                        oldest = ts
                    if newest is None or ts > newest:
                        newest = ts
                    l._append( '\t'.join( (str( ts ),json.dumps( None ),js) ) )

        # Load the historical records.  This will be robust against all errors except if the first
        # line of the first history file opened is corrupt, and we therefore cannot get the initial
        # frame of register data.
        historical	= timestamp( now - random.uniform( -secs_ext, secs + secs_ext ))
        basisdelay	= random.uniform( -basisext, +basisext )
        basis		= now + basisdelay
        factor		= random.uniform( minfactor, maxfactor )
        lookahead	= 1.0
        on_bad_iframe	= random.choice( (loader.RAISE, loader.FAIL, loader.SUPPRESS, loader.SUPPRESS, loader.SUPPRESS) )
        on_bad_data	= random.choice( (loader.RAISE, loader.FAIL, loader.SUPPRESS, loader.SUPPRESS, loader.SUPPRESS) )
        logging.normal( "Playback starts %s (%.1f%%) of history %s-%s, in %.3fs, at x %.2f rate w/%.1fs lookahead, on_bad_iframe=%s, on_bad_data=%s",
                        historical, ( historical.value - oldest.value ) * 100 / ( newest.value - oldest.value ),
                        oldest, newest, basisdelay, factor, lookahead,
                        "SUPPRESS" if on_bad_iframe == loader.SUPPRESS else "FAIL" if on_bad_iframe  == loader.FAIL else "RAISE",
                        "SUPPRESS" if on_bad_data   == loader.SUPPRESS else "FAIL" if on_bad_data    == loader.FAIL else "RAISE" )

        ld		= loader( path,
                                historical=historical, basis=basis, factor=factor, lookahead=lookahead )
        dur		= basisext + ( secs_ext + secs + secs_ext ) / factor + basisext + 2*maxlatency # Don't be tooo strict
        beg		= timer()
        count		= 0

        while ld:
            assert timer() - beg < dur, "The loader should have ended"
            cur,events	= ld.load( on_bad_iframe=on_bad_iframe, on_bad_data=on_bad_data )
            count      += len( events )
            logging.normal( "%s loaded up to %s; %d future, %d values: %d events: %s",
                            ld, cur, len( ld.future ), len( ld.values ), len( events ), 
                            repr( events ) if logging.root.isEnabledFor( logging.DEBUG ) else reprlib.repr( events ))
            time.sleep( random.uniform( 0.0, maxlatency ))

        if on_bad_data == ld.FAIL or on_bad_iframe == ld.FAIL:
            assert ld.state in (ld.COMPLETE, ld.FAILED)
        else:
            assert ld.state == ld.COMPLETE

    except IframeError as exc:
        logging.warning( "Detected error on initial frame of registers in first history file; failure expected: %s", exc )
        assert ld.state == ld.FAILED and count == 0, "Shouldn't have loaded any events -- only iframe failures expected"

    except DataError as exc:
        logging.warning( "Detected error on registers data in a history file; failure expected: %s", exc )
        assert ld.state == ld.FAILED

    except Exception as exc:
        logging.normal( "Test failed: %s", exc )
        for f in files:
            if os.path.exists( f ):
                logging.normal( "%s:\n    %s", f, "    ".join( l for l in open( f )))
            else:
                logging.warning( "%s: Couldn't find file", f )
        raise

    finally:
        for f in files:
            logging.detail( "unlinking %s", f )
            try:
                os.unlink( f )
            except:
                pass

# 
# Enable 'tracemalloc' tracing of test_history_performance by uncommenting the following block
# 
if 'TRACEMALLOC' in os.environ:
    try:
        import tracemalloc
    except ImportError:
        pass
    else:
        def display_top(snapshot, group_by='lineno', limit=10):
            snapshot = snapshot.filter_traces((
                tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
                tracemalloc.Filter(False, "<unknown>"),
            ))
            top_stats = snapshot.statistics(group_by)
        
            print("Top %s lines" % limit)
            for index, stat in enumerate(top_stats[:limit], 1):
                frame = stat.traceback[0]
                # replace "/path/to/module/file.py" with "module/file.py"
                filename = os.sep.join(frame.filename.split(os.sep)[-2:])
                print("#%s: %s:%s: %.1f KiB"
                      % (index, filename, frame.lineno,
                        stat.size / 1024))
        
            other = top_stats[limit:]
            if other:
                size = sum(stat.size for stat in other)
                print("%s other: %.1f KiB" % (len(other), size / 1024))
            total = sum(stat.size for stat in top_stats)
            print("Total allocated size: %.1f KiB" % (total / 1024))
        
        def display_biggest_traceback():
            snapshot = tracemalloc.take_snapshot()
            top_stats = snapshot.statistics('traceback')
        
            # pick the biggest memory block
            stat = top_stats[0]
            print("%s memory blocks: %.1f KiB" % (stat.count, stat.size / 1024))
            for line in stat.traceback.format():
                print(line)
    
@pytest.mark.skipif( not has_pytz or not got_localzone, reason="Needs pytz and localzone" )
def test_history_performance():
    try:
        tracemalloc.start()
    except:
        pass

    for _ in range( 3 ):
        path		= "/tmp/test_performance_%d" % random.randint( 100000, 999999 )
        if os.path.exists( path ):
            continue
    assert not os.path.exists( path ), "Couldn't find an unused name: %s" % path 

    files		= []
    try:
        day		= 24*60*60
        dur		= 3*day		# a few days worth of data
        regstps		= 0.0,5.0	# 0-5secs between updates
        numfiles	= dur//day+1	# ~1 file/day, but at least 2
        values		= {}		# Initial register values
        regscount	= 1000		# Number of different registers
        regschanged	= 1,10		# From 1-25 registers per row
        regsbase	= 40001

        start		= timer()

        now = beg	= start - dur
        linecnt		= 0
        for e in reversed( range( numfiles )):
            f		= path + (( '.%d' % e ) if e else '') # 0'th file has no extension
            files.append( f )
            with logger( f ) as l:
                if values:
                    l.write( values, now=now ); linecnt += 1
                while now < beg + len(files) * dur/numfiles:
                    lst	= now
                    now += random.uniform( *regstps )
                    assert now >= lst
                    assert timestamp( now ) >= timestamp( lst ), "now: %s, timestamp(now): %s" % ( now, timestamp( now ))
                    updates = {}
                    for _ in range( random.randint( *regschanged )):
                        updates[random.randint( regsbase, regsbase + regscount - 1 )] = random.randint( 0, 1<<16 - 1 )
                    values.update( updates )
                    l.write( updates, now=now ); linecnt += 1
                lst 	= now
                now    += random.uniform( *regstps )
                assert now >= lst
                assert timestamp( now ) >= timestamp( lst )
            if e:
                # Compress .1 onward using a random format; randomly delete origin uncompressed file
                # so sometimes both files exist
                if random.choice( (True, False, False, False) ):
                    continue # Don't make a compressed version of some files
                fz	 = f + '.%s' % random.choice( ('gz', 'bz2', 'xz') )
                files.append( fz )
                with opener( fz, mode='wb' ) as fd:
                    with open( f, 'rb' ) as rd:
                        fd.write( rd.read() )
                if random.choice( (True, False, False) ):
                    continue # Don't remove some of the uncompressed files
                os.unlink( f )
                files.pop( files.index( f ))

        logging.warning( "Generated data in %.3fs; lines: %d", timer() - start, linecnt )

        # Start somewhere within 0-1% the dur of the beg, forcing the load the look back to
        # find the first file.  Try to do it all in the next 'playback' second (just to push it to
        # the max), in 'chunks' pieces.
        historical	= timestamp( random.uniform( beg + dur*0/100, beg + dur*1/100 ))
        basis		= timer()
        playback	= 2.0 * dur/day # Can sustain ~2 seconds / day of history on a single CPU
        chunks		= 1000
        factor		= dur / playback
        lookahead	= 60.0
        duration	= None
        if random.choice( (True,False) ):
            duration	= random.uniform( dur * 98/100, dur * 102/100 )

        begoff		= historical.value - beg
        endoff		= 0 if duration is None else (( historical.value + duration ) - ( beg + dur ))
        logging.warning( "Playback starts at beginning %s %s, duration %s, ends at ending %s %s",
                         timestamp( beg ), format_offset( begoff, ms=False ),
                         None if duration is None else format_offset( duration, ms=False, symbols='-+' ),
                         timestamp( beg + dur ), format_offset( endoff, ms=False ))

        ld		= loader(
            path, historical=historical, basis=basis, factor=factor, lookahead=lookahead, duration=duration )
        eventcnt	= 0
        slept		= 0
        cur		= None
        while ld:
            once	= False
            while ld.state < ld.AWAITING or not once:
                once		= True
                upcoming	= None
                limit		= random.randint( 0, 250 )
                if random.choice( (True,False) ):
                    upcoming	= ld.advance()
                    if random.choice( (True,False) ) and cur:
                        # ~25% of the time, provide an 'upcoming' timestamp that is between the
                        # current advancing historical time and the last load time.
                        upcoming-= random.uniform( 0, upcoming.value - cur.value )
                cur,events	= ld.load( upcoming=upcoming, limit=limit )
                eventcnt       += len( events )
                advance		= ld.advance()
                offset		= advance.value - cur.value
                logging.detail( "%s loaded up to %s (%s w/ upcoming %14s); %4d future, %4d values: %4d events / %4d limit" ,
                                ld, cur, format_offset( offset ),
                                format_offset( upcoming.value - advance.value ) if upcoming is not None else None,
                                len( ld.future ), len( ld.values ), len( events ), limit )

            logging.warning( "%s loaded up to %s; %3d future, %4d values: %6d events total",
                                ld, cur, len( ld.future ), len( ld.values ), eventcnt )
            try:
                snapshot	= tracemalloc.take_snapshot()
                display_top( snapshot, limit=10 )
            except:
                pass

            time.sleep( playback/chunks )
            slept	       += playback/chunks

        elapsed		= timer() - basis
        eventtps	= eventcnt // ( elapsed - slept )
        logging.error( "Playback in %.3fs (slept %.3fs); events: %d ==> %d historical records/sec",
                       elapsed, slept, eventcnt, eventtps )
        if not logging.getLogger().isEnabledFor( logging.NORMAL ):
            # Ludicrously low threshold, to pass tests on very slow machines
            assert eventtps >= 1000, \
                "Historical event processing performance low: %d records/sec" % eventtps
        try:
            display_biggest_traceback()
        except:
            pass

    except Exception as exc:
        logging.normal( "Test failed: %s", exc )
        '''
        for f in files:
            logging.normal( "%s:\n    %s", f, "    ".join( l for l in open( f )))
        '''
        raise

    finally:
        for f in files:
            logging.detail( "unlinking %s", f )
            try:
                os.unlink( f )
            except:
                pass

if __name__ == "__main__":
    test_history_performance()
