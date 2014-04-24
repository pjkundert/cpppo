from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import datetime
import json
import logging
import os
import random
import string
import sys
import time

try:
    import reprlib
except ImportError:
    import repr as reprlib

from .misc	import timer
from .automata	import log_cfg
from .history	import *

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

#log_cfg['level']		= logging.INFO
logging.basicConfig( **log_cfg )

    
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
        terms[6]               += '0' * ( 6 - len( terms[6] ))
    return datetime.datetime( *map( int, terms ), tzinfo=pytz.utc )


def test_history_timestamp():
    """Ensure timestamp deals in UTC only"""
    if not has_pytz or not got_localzone:
        logging.warning( "Skipping cpppo.history.timestamp tests" )
        return

    abbrev			= timestamp.support_abbreviations( 'CA' )
    assert sorted( abbrev ) == ['ADT', 'AST', 'CDT', 'CST', 'EDT', 'EST', 'MDT', 'MST', 'NDT', 'NST', 'PDT', 'PST']
    try:
        abbrev			= timestamp.support_abbreviations( 'America' )
        assert False, "Many zones should have been ambiguously abbreviated"
    except AmbiguousTimeZoneError as exc:
        assert "America/Mazatlan" in str( exc )
    abbrev			= timestamp.support_abbreviations( 'America', 
        exclude=['America/Mazatlan', 'America/Merida', 'America/Mexico_City', 'America/Monterrey',
                 'America/Bahia_Banderas', 'America/Cancun', 'America/Chihuahua', 'America/Havana',
                 'America/Santa_Isabel'] )
    print( sorted( abbrev ))
    assert sorted( abbrev ) == ['AKDT', 'AKST', 'AMST', 'AMT', 'BRST', 'BRT', 'CLST', 'CLT', 'EGST', 'EGT',
                                'HADT', 'HAST', 'PMDT', 'PMST', 'PYST', 'PYT', 'UYST', 'UYT', 'WGST', 'WGT']

    abbrev			= timestamp.support_abbreviations( 'Europe/Berlin' )
    assert sorted( abbrev ) == ['CEST', 'CET']
    assert 'CEST' in timestamp._tzabbrev
    assert 'EEST' not in timestamp._tzabbrev
    abbrev			= timestamp.support_abbreviations( 'Europe', exclude=[ 'Europe/Simferopol', 'Europe/Istanbul'] )
    assert sorted( abbrev ) == ['BST', 'EEST', 'EET', 'GMT', 'IST', 'WEST', 'WET']
    assert 'EEST' in timestamp._tzabbrev
    try:
        timestamp.support_abbreviations( 'Asia' )
        assert False, "Asia/Jerusalem IST should have mismatched Europe/Dublin IST"
    except AmbiguousTimeZoneError as exc:
        assert "Asia/Jerusalem" in str( exc )
    timestamp.support_abbreviations( 'Australia' )

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
                    fd.write( open( f, 'rb' ).read() )
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
                    logging.detail( "@%s: not yet available", ts )
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
        
