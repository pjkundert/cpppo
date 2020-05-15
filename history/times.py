
# 
# Cpppo -- Communication Protocol Python Parser and Originator
# 
# Copyright (c) 2013, Hard Consulting Corporation.
# 
# Cpppo is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.  See the LICENSE file at the top of the source tree.
# 
# Cpppo is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 

from __future__ import absolute_import, print_function, division
try:
    from future_builtins import zip, map # Use Python 3 "lazy" zip, map
except ImportError:
    pass

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ["timestamp", "get_localzone", "zone_names", "timedelta_total_seconds",
                                   "parse_offset", "format_offset", "AmbiguousTimeZoneError", "TZ_wrapper"]

import bisect
import calendar
import datetime
import logging
import os
import string
import sys
import threading

def timedelta_total_seconds( td ):
    if hasattr( td, 'total_seconds' ):
        return td.total_seconds()
    # In Python 2.6, timedelta lacks total_seconds; add it
    return ( td.microseconds + ( td.seconds + td.days * 24 * 3600 ) * 1e6 ) / 1e6


from ..misc		import timer, mutexmethod
from ..automata		import type_str_base

log				= logging.getLogger( __package__ )

# Installed packages (eg. pip/setup.py install pytz tzlocal)
import pytz
try:
    from tzlocal import get_localzone
except ImportError:
    def get_localzone( _root='/' ):
        """No tzlocal; support basic Linux systems with a TZ variable or an /etc/timezone file"""
        # /etc/timezone, ... file?
        for tzbase in ( 'etc/timezone',			# Debian, Ubuntu, ...
                        'etc/sysconfig/clock' ):	# RedHat, ...
            tzpath		= os.path.join( _root, tzbase )
            if os.path.exists( tzpath ):
                with open( tzpath, 'rb' ) as tzfile:
                    tzname	= tzfile.read().decode().strip()
                if '#' in tzname:
                    # eg. 'Somewhere/Special # The Special Zone'
                    tzname	= tzname.split( '#', 1 )[0].strip()
                if ' ' in tzname:
                    # eg. 'America/Dawson Creek'.  Not really correct, but we'll handle it
                    tzname	= tzname.replace( ' ', '_' )
                return pytz.timezone( tzname )

        raise pytz.UnknownTimeZoneError( 'Can not find any timezone configuration' )

def TZ_wrapper():
    """Wrap get_localzone in a handler that respects a TZ variable before attempting other host-specific
    local timezone detection.

    """
    def decorate( func ):
        def call( *args, **kwds ):
            # TZ environment variable?  Either a tzinfo file or a timezone name.  Make this 
            tzenv		= os.environ.get( 'TZ' )
            if tzenv:
                if os.path.exists( tzenv ):
                    with open( tzenv, 'rb' ) as tzfile:
                        return pytz.tzfile.build_tzinfo( 'local', tzfile )
                return pytz.timezone( tzenv )
            return func( *args, **kwds )
        return call
    return decorate

# Manually apply the TZ_wrapper decorator to an existing get_localzone function
get_localzone = TZ_wrapper()( get_localzone )

    
def zone_names( region ):
    """Yields all zone names matching region, which may be a single identifier string or iterable.  If
    unrecognized, the supplied region is yielded unmodified.  The pytz {country,common}_timezones
    are consulted; the provided <region> strings may be country codes, or may match the leading
    <region> portion of <region>/<city> timezone names.

    """
    if isinstance( region, type_str_base ):
        region		= [ region ]
    elif region is None:
        region		= []
    for r in region:						# eg. [ 'CA', 'Canada', 'Europe/Berlin' ]
        zones		= pytz.country_timezones.get( r )	# eg 'CA'
        if zones is None:
            zones	= [ z for z in pytz.common_timezones	# eg. 'Canada/Mountain' or 'Europe'
                            if z.startswith( r ) ]		# 'Canada/Mountain' or 'Europe' or 'America/Argentina/'...
        if zones:
            for z in zones:
                yield z		# Matches {country,common}_timesones name(s)
        else:
            yield r		# Some random unrecognized zone name

def parse_offset( term, symbols='<>' ):
    """Convert a string like '</> h:mm:ss.sss' into -'ve/+'ve seconds."""
    try:
        sign		= max( *map( term.find, symbols ))
        assert sign >= 0, "missing sign"
        assert term[:sign].strip() == '', "garbage before sign"
        hms		= term[sign+1:].split( ':' )
        assert 1 <= len( hms ) <= 3, "only h:mm:ss.s allowed"
        while hms[0] == '':
            hms		= hms[1:] # <:02.5 is OK
        offset		= 0
        for v in hms:
            offset	= offset * 60 + float( v )
        if term[sign] == symbols[0]:
            offset	= -offset
    except Exception as exc:
        raise ValueError( "Invalid offset %r; must be %s[[h:]m:]s[.s]: %s" % ( term, '/'.join( symbols ), exc ))
    return offset

def format_offset( dt, ms=True, symbols='<>' ):
    """Convert a floating point number of -'ve/+'ve seconds into '</> h:mm:ss.sss'"""
    return (( symbols[0] if dt < 0 else symbols[1] ) + "%2d:%02d:" + ( "%06.3f" if ms else "%02d" )) % (
        int( abs( dt ) // 3600 ), 
        int( abs( dt ) % 3600 // 60 ), 
        abs( dt ) % 60 )


class AmbiguousTimeZoneError( pytz.UnknownTimeZoneError ):
    pass
    

class timestamp( object ):
    """Initialize from a timestamp or a UTC formatted date-time string, and produce float timestamp
    value or string.

    All comparisons between timestamps occurs in numeric form, to the precision specified by
    _epsilon; timestamps nearer than _epsilon seconds from each other are considered equal.  The
    default string format (to millisecond precision) and default _epsilon (10^-3) are chosen so that
    string form and numeric form timestamps compare equivalently.  In other words, two timestamps
    that compare > (if truncated to 3 digits of sub-second precision) will also compare identically
    as strings.

    Always has a .value which is the unix timestamp as a float.  The string version is lazily produced.

    """
    UTC				= pytz.utc
    LOC				= get_localzone()	# from environment TZ, /etc/timezone, etc.

    _precision			= 3			# How many default sub-second digits
    _epsilon			= 10**-_precision	# How small a difference to consider ==
    _timeseps			= ( string
                                    if sys.version_info[0] < 3
                                    else str ).maketrans( ":-.", "   " )
    _fmt			= '%Y-%m-%d %H:%M:%S'	# 2014-04-01 10:11:12

    # A map of all the common timezone abbreviations to their canonical timezones along with the
    # proper is_dst setting.
    _tzabbrev			= {}
    _cls_lock			= threading.Lock()

    @classmethod
    @mutexmethod( '_cls_lock' )
    def support_abbreviations( cls, region, exclude=None, at=None, reach=None, reset=False ):
        """Add all the DST and non-DST abbreviations for the specified region.  If a country code
        (eg. 'CA') is specified, we'll get all its timezones from pytz.country_timezones.
        Otherwise, we'll get all the matching '<region>[/<city>]' zone(s) from pytz's
        common_timezones.  Multiple invocations may be made, to include abbreviations covering
        multiple regions.

        We'll look for the first time transition within 'at' +/- 'reach' in pytz's
        _utc_transition_times list, and see if the timezone yields different timezone names and
        is_dst designations for the days surrounding that time.  If both are different, we'll use
        the abbreviations as DST and non-DST specific abbreviations.  There are instants when a
        timezone changes times, which are *NOT* DST changes; eg 'America/Eirunepe' (west Amazonas)
        on November 10, 2013, where the timezone switched from AMT (UTC-4) to ACT (UTC-5).  Neither
        of these are DST times; the timezone just permanently changed its offset.

        Once we find a set of DST-specific abbreviations for a timezone, we must ensure that they
        are consistent with the abbreviations that already appear in the abbreviations table.  For
        example, the 'IST' (Irish Summer Time) abbreviation presented by 'Europe/Dublin' timezone is
        different than the 'IST' (Isreal Standard Time) presented by the 'Asia/Jeruslem' timezone.
        You cannot load them both at once.  If multiple timezones produce the same abbreviation,
        they must have the same DST transitions between 'at' +/- 'reach', or AmbiguousTimeZoneError
        will be raised -- the timezone abbreviations have ambiguous meaning, and the zones cannot be
        identified via abbreviation at the same time.

        Returns all the timezone abbreviations added to the class's _tzabbrev; you may want to check:

            region		= 'CA'
            abbrevs		= timestamp.support_abbreviations( region )
            assert abbrevs, "Invalid region %r: Matches no timezones" % region

        Timezone definitions change over time.  A 'reach' timedelta (default: 1 year) on either side
        of the 'at' (a naive UTC datetime, default: current time) is required, in order for multiple
        zones to use the same abbreviation with guaranteed consistent definitions.

        """
        if reset and cls._tzabbrev:
            log.detail( "Resetting %d timezone abbreviations: %r", len( cls._tzabbrev), cls._tzabbrev.keys() )
            cls._tzabbrev	= {}

        def format_dst( dst ):
            return "dst" if dst else "n/a" if dst is None else "   "

        # Check consistency during relevant time periods for all timezones using the same
        # DST-specific abbreviations.  It is problematic to have multiple timezones with the same
        # abbreviation but with different DST change times or UTC offsets.
        if reach is None:# 1/2 year on either side by default
            reach		= datetime.timedelta( 365/2 )
        if at is None:	 # around the current time by default (naive, UTC)
            at			= datetime.datetime.utcnow()
        oneday			= datetime.timedelta( 1 )

        # Take a (shallow) copy to update; only when we complete integrating all the target
        # timezones successfully do we commit the updated abbrev dict.
        abbrev			= cls._tzabbrev.copy()
        incompatible		= []
        exclusions		= set( zone_names( exclude ))
        log.info( "Excluding: %r", exclusions )
        for tz in zone_names( region ): # eg 'America/Vancouver', 'America/Dawson_Creek', ...
            if tz in exclusions:
                log.detail( "%-30s: Ignoring; excluded", tz )
                continue

            tzinfo		= pytz.timezone( tz )
            tzdetails		= []

            # Find the nearest future transition time (> at - reach), or the list length if all are
            # <=. This will compute the index where 'at - reach' should be inserted to maintain the
            # list order, so it may index one beyond the end of the list.  Pick the index (next
            # higher than 'at - reach') time, and make sure it is in the future (not beyond the end
            # of the list).  Get the list of the zones' (time,abbrev,DST) settings (one if purely
            # non-DST, or two if a DST zone or a zone that has changed its UTC offset) in tzdetails.
            nxt			= bisect.bisect( tzinfo._utc_transition_times, at - reach )
            lst			= bisect.bisect( tzinfo._utc_transition_times, at + reach )
            if nxt == len( tzinfo._utc_transition_times ) or nxt == lst:
                # This is (in the at +/- reach time span, anyway) probably a non-DST timezone.
                loc		= tzinfo.normalize( pytz.UTC.localize( at ).astimezone( tzinfo ))
                abb		= loc.strftime( "%Z" )
                dst		= bool( loc.dst() )
                off		= loc.utcoffset()
                log.detail( "%-30s: %-5s %s %s: no time change in %s to %s",
                            tzinfo, abb, format_offset( timedelta_total_seconds( off ), ms=False ), format_dst( dst ),
                            at - reach, at + reach )
                tzdetails	= [ (at,abb,dst,off) ]
            else:
                # A DST zone?; found 1 or more time change.  Uses times 1 day before/after to get
                # appropriate abbreviations.  NOTE: This may be a time change, but isn't necessarily
                # a DST/non-DST change!  So, insdst/outdst may be the same (False) for both.  All
                # _utc_transition_times are naive UTC; probe the tzinfo at +/- one day around then
                # change, interpreting the localized UTC time as a time in the 'tzinfo' zone, and
                # pytz.normalize it to correct the DST information.
                ins,out		= ( tzinfo._utc_transition_times[nxt] - oneday,
                                    tzinfo._utc_transition_times[nxt] + oneday )
                insloc,outloc	= ( tzinfo.normalize( pytz.UTC.localize( dt ).astimezone( tzinfo ))
                                    			for dt in ( ins, out ))
                insoff,outoff	= ( dt.utcoffset()	for dt in ( insloc, outloc ))	# The net UTC offset
                insabb,outabb	= ( dt.strftime( "%Z" ) for dt in ( insloc, outloc ))	# The timezone abbrev.
                insdst,outdst	= ( bool( dt.dst() )    for dt in ( insloc, outloc ))	# Is there a DST offset?
                msg		= "%-5s %s %s / %-5s %s %s" % (
                        insabb, format_offset( timedelta_total_seconds( insoff ), ms=False ), format_dst( insdst ),
                        outabb, format_offset( timedelta_total_seconds( outoff ), ms=False ), format_dst( outdst ))
                if insabb == outabb:
                    # This timezone has the same name for DST/non-DST (eg. 'Australia/Adelaide' CST
                    # Australian Central Standard Time ).  Thus, 'is_dst' will be None, and times
                    # during the DST transition will still be ambiguous.
                    msg		+= ": abbreviations are the same; will be ambiguous during DST overlap"
                    log.detail( "%-30s: %s", tzinfo, msg )
                    tzdetails	= [ (ins,insabb,None,insoff) ]
                else:
                    # A regular DST/non-DST time change (eg. 'Canada/Mountain'), or a zone offset
                    # change (eg. 'America/Eirunepe', both DST false).
                    if insdst == outdst == True:
                        # This timezone has different names, but both are DST.  Strange, but possible.
                        msg       += ": both zones indicate DST; allowing..."

                    log.detail( "%-30s: %s", tzinfo, msg )
                    tzdetails	= [ (ins,insabb,insdst,insoff), (out,outabb,outdst,outoff) ]

            # Save the non-DST (eg. 'MST', 'GMT') and DST (eg. 'MDT', 'IST', 'CEST') timezones.  If
            # either timezone abbreviation is already in the abbreviations list, make certain it is
            # the exact same timezone; same UTC offset, same transition times if a DST zone
            # (different name ok), during the relevant period of time.  For the non-DST zones, the
            # transition times are not as important -- all non-DST times are unambiguous, so long as
            # the overall UTC offset is the same.  The 'dt' here is always a naive UTC datetime.
            for dt,abb,dst,off in tzdetails:
                # We can only handle timezone abbreviations in a certain format: "XYZ"; not "-03"
                # and the like.  Ignore any that don't match the pattern.
                if not all( l.isalpha() for l in abb ):
                    log.detail( "%-30s: Ignoring %s; invalid abbreviation pattern", tzinfo, abb )
                    continue
                # Also allow exclusion of timezone abbreviations (in addition to timezone names, above)
                if abb in exclusions:
                    log.detail( "%-30s: Ignoring %s; excluded", tzinfo, abb )
                    continue
                msg		= "%-5s %s %s" % (
                    abb, format_offset( timedelta_total_seconds( off ), ms=False ), format_dst( dst ))
                dup		= abb in abbrev
                if dup and not dst:
                    # A duplicate; non-DST or ambiguous, must have consistent UTC offset and DST
                    # designation.  We'll allow replacement of a dst=None (still ambiguous) zone with a dst=False zone

                    abbtzi,abbdst,abboff= abbrev[abb]
                    if abboff != off:
                        msg    += " x %-5s %s %s in %s; incompatible" % (
                            abb, format_offset( timedelta_total_seconds( abboff ), ms=False ), format_dst( abbdst ), abbtzi )
                        incompatible.append( "%s: %s" % ( tzinfo, msg ))
                        log.warning( "%-30s: %s", tzinfo, msg )
                    elif abbdst is None:
                        msg    += " ~ %-5s %s %s in %s; replacing ambiguous w/ concrete non-DST zone" % (
                            abb, format_offset( timedelta_total_seconds( abboff ), ms=False ), format_dst( abbdst ), abbtzi )
                        dup	= False

                if dup and dst:
                    # A duplicate; DST-specific, must be consistently specified; if not, just the
                    # main UTC offset must be consistent.
                    abbtzi	= abbrev[abb][0]
                    abbtzinxt	= bisect.bisect( abbtzi._utc_transition_times, at - reach )
                    abbtzilst	= bisect.bisect( abbtzi._utc_transition_times, at + reach )
                    if abbtzilst - abbtzinxt != lst - nxt:
                        msg	= "%s has %d time changes vs. %d in %s" % (
                            abb, lst-nxt, abbtzilst-abbtzinxt, abbtzi )
                        incompatible.append( "%s: %s" % ( tzinfo, msg ))
                        log.warning( "%-30s: %s", tzinfo, msg )
                        continue
                    chg		= zip( tzinfo._utc_transition_times[nxt:lst], tzinfo._transition_info[nxt:lst] )
                    abbchg	= zip( abbtzi._utc_transition_times[abbtzinxt:abbtzilst], abbtzi._transition_info[abbtzinxt:abbtzilst] )

                    def transition_consistent( zt1, zt2 ):
                        dt1,(off1,dst1,_)	= zt1
                        dt2,(off2,dst2,_)	= zt2
                        return off1 == off2 and dt1 == dt2 and dst1 == dst2

                    difs	= [ (a,b) for a,b in zip( chg, abbchg ) if not transition_consistent( a, b ) ]
                    if difs:
                        msg	= "%s time changes differ vs. %s" % ( abb, abbtzi )
                        incompatible.append( "%s: %s" % ( tzinfo, msg ))
                        desc	= " vs. ".join( "on %s, offset %s, dst %s" % ( dt, format_offset( timedelta_total_seconds( off ), ms=False ),
                                                                               format_offset( timedelta_total_seconds( dst ), ms=False ))
                                                for dt,(off,dst,_) in ( difs[0][0], difs[0][1] ))
                        log.warning( "%-30s: %s; %d differences: %s", tzinfo, msg, len( difs ), desc )
                        continue
                ( log.detail if dup else log.normal )( "%-30s: %-5s %s %s at %s UTC%s",
                    tzinfo, abb, format_offset( timedelta_total_seconds( off ), ms=False ), format_dst( dst ),
                                                       dt.strftime( cls._fmt ), "; Ignoring duplicate" if dup else "" )
                if not dup:
                    abbrev[abb]	= tzinfo,dst,off
        if incompatible:
            raise AmbiguousTimeZoneError( "%-30s region(s) incompatible: %s" % ( region, ", ".join( incompatible )))
        added			= list( set( abbrev ) - set( cls._tzabbrev ))
        cls._tzabbrev		= abbrev
        return added

    @classmethod
    @mutexmethod( '_cls_lock' )
    def timezone_info( cls, tzinfo ):
        """Return the (tzinfo,is_dst) of the supplied tz. (default is_dst: None).  Accepts either a
        tzinfo, or a string and looks up the corresponding timezone abbreviation (is_dst:
        True/False), or raw timezone (is_dst: None).

        """
        is_dst			= None
        if isinstance( tzinfo, type_str_base ):
            if tzinfo in cls._tzabbrev:
                tzinfo,is_dst,_	= cls._tzabbrev[tzinfo]
            else:
                tzinfo		= pytz.timezone( tzinfo )
        assert isinstance( tzinfo, datetime.tzinfo ), "Expected tzinfo, not %s" % type( tzinfo )
        return tzinfo,is_dst

    @classmethod
    def datetime_from_string( cls, s, tzinfo=None ):
        """Parse a time, in the specified timezone.  Or, if the time contains a timezone (the last
        element is not a number), use that as the timezone instead.  If the timezone is a generic
        timezone, then the default Daylight Savings Time is applied:

            2014-11-01 01:02:03.456 America/Edmonton   (Nov 1 2014 -- DST *is* in effect)

        To be specific about whether DST applies, use a DST-specific timezone abbreviation:
        
            2014-11-02 01:02:03.123 MST                (Nov 2 2014 -- 1:02 *after* DST ended)
            2014-11-02 01:02:03.456 MDT                (Nov 2 2014 --  :58 *before* DST ends)

        The time will be assumed to be UTC, unless otherwise specified.  Be aware that attempting to
        parse ambiguous or nonexistent times will raise an exception (eg. during spring-ahead time
        gap, or during fall-back time overlap).

        Supports specifying either a pytz tzinfo or a string specifying a timezone; either a
        supported DST-specific timezone abbreviation (eg. 'MST', 'MDT'), or a generic non
        DST-specific timezone (eg. 'America/Edmonton').

        """
        try:
            terms		= str( s ).translate( cls._timeseps ).split()
            if not terms[-1].isdigit(): # Hmm; Last term isn't digits; must be a timezone.
                terms,tzinfo	= terms[:-1],terms[-1]
            is_dst		= None
            if tzinfo is None:
                tzinfo		= cls.UTC
            elif not isinstance( tzinfo, datetime.tzinfo ):
                tzinfo,is_dst	= cls.timezone_info( tzinfo )

            assert 6 <= len( terms ) <= 7, "%d terms unexpected" % len( terms )
            if len( terms ) == 7:
                # convert .123 into 123000 microseconds
                terms[6]       += '0' * ( 6 - len( terms[6] ))
            # Create a "naive" datetime (no tzinfo), and then localize it to the target tzinfo.  We
            # cannot use the datetime.datetime( ..., tzinfo=... ) keyword, because it doesn't handle
            # dates in daylight savings time.  Because we do not pass the is_dst keyword, this will
            # fail for those ambiguous times at the start/end of Daylight savings time -- unless we
            # specify a Daylight Savings Time specific timezone, eg. MST/MDT.
            return tzinfo.localize( datetime.datetime( *map( int, terms )), is_dst=is_dst )
        except Exception as exc:
            raise ValueError( "Invalid time format %r; expect YYYY-MM-DD HH:MM:SS[.###] [TZ]: %s", s, exc )

    @classmethod
    def datetime_from_number( cls, n, tzinfo=None ):
        """Convert a numeric UNIX timestamp into a datetime in the specified timezone.  UNIX epoch times are
        unambiguous; the target timezone's is_dst hint is not required.

        TODO: When a datetime is assigned a time in a certain timezone that has DST (such as
        America/Edmonton, MST7MDT), that specific time is either "in" our "out" of DST.  When it is
        rendered, it will be rendered as MST or MDT.

        Ideally, it would be nice to force the produced datetime to have a fixed non-DST rendering
        such as MST, regardless of whether the time is "in" or "out" of DST.  There are certain 
        such timezone supplied by pytz:

            >>> [ z for z in pytz.all_timezones if len( z ) in (3,4) ]
            ['CET', 'Cuba', 'EET', 'EST', 'Eire', 'GMT', 'GMT0', 'HST', 'Iran', 'MET',\
            'MST', 'PRC', 'ROC', 'ROK', 'UCT', 'UTC', 'W-SU', 'WET', 'Zulu']

        These are *different* than the 'MST' abbreviation that would be made available by invoking
        timestamp.support_abbreviations( 'CA' ); simply the 'America/Edmonton' zone with an
        'is_dst=False' flag!  The pytz 'MST' zone is a full pytz.tzinfo without any DST changes.

            >>> ts=timestamp( 1399726367 )
            >>> ts
            <2014-05-10 12:52:47.000 =~= 1399726367.000000>
            >>> ts.render( 'America/Edmonton' )
            '2014-05-10 06:52:47.000 MDT'
            >>> ts.render( 'MST' )
            '2014-05-10 05:52:47.000 MST'

        Now, get the "abbreviations", including 'MST'.  Note that the time is now rendered using
        'America/Edmonton', and thus identifies the time as being in DST:

            >>> timestamp.support_abbreviations( 'CA')
            ['ADT', 'EST', 'AST', 'PDT', 'MST', 'CDT', 'PST', 'EDT', 'CST', 'NST', 'NDT', 'MDT']
            >>> ts.render( 'MST' )
            '2014-05-10 06:52:47.000 MDT'

            >>> timestamp( '2014-05-10 05:52:47.000 MST' )
            <2014-05-10 12:52:47.000 =~= 1399726367.000000>

        To sum up:

            >>> timestamp.support_abbreviations( None, reset=True )
            []
            >>> timestamp( '2014-05-10 05:52:47.000 MST' ).render( 'MST' )
            '2014-05-10 05:52:47.000 MST'
            >>> timestamp.support_abbreviations( 'CA' )
            ['ADT', 'EST', 'AST', 'PDT', 'MST', 'CDT', 'PST', 'EDT', 'CST', 'NST', 'NDT', 'MDT']
            >>> timestamp( '2014-05-10 05:52:47.000 MST' ).render( 'MST' )
            '2014-05-10 05:52:47.000 MDT'

        Unfortunately, the idea is simply not supported by Python datetime for the general case.
        The best we could do would be to "denormalize" the datetime, by adding an offset to bring
        the time "out" of DST (or by using a known non-DST time), and then adding an offset to that
        datetime to exactly yield the target datetime, and then avoid running pytz.tzinfo.normalize
        to "fix" the datetime's time and tzinfo.is_dst flag.  This would be a bit hacky, but might
        be possible (see the treatise at the bottom of the Python source
        .../Modules/datetimemodule.c for some possible pitfalls)

        """
        if tzinfo is None:
            tzinfo		= cls.UTC
        elif not isinstance( tzinfo, datetime.tzinfo ):
            tzinfo,_		= cls.timezone_info( tzinfo ) # Ignore is_dst; irrelevant
        try:
            return datetime.datetime.fromtimestamp( n, tz=tzinfo )
        except Exception as exc:
            raise ValueError( "Invalid time format; expect UNIX timestamp: %s", exc )

    @classmethod
    def number_from_datetime( cls, dt ):
        """Convert a timezone-aware datetime to a UNIX timestamp.  You'd think strftime( "%s.%f" )?  You'd
        be wrong; a timezone-aware datetime should always strftime to the same (correct) UNIX
        timestamp via its "%s" format, but this also doesn't work.

        Convert the time to a UTC time tuple, then use calendar.timegm to take a UTC time tuple and
        compute the UNIX timestamp.

        """
        return calendar.timegm( dt.utctimetuple() ) + dt.microsecond / 1000000

    def __init__( self, value=None ):
        self._str		= None
        if value is None:
            self.value		= timer()
        elif isinstance( value, (float, int)):
            self.value		= float( value )
        elif isinstance( value, type_str_base ):
            dt			= self.datetime_from_string( value )
            self.value		= self.number_from_datetime( dt )
        elif isinstance( value, timestamp ):
            self.value		= value.value
            self._str		= value._str
        elif isinstance( value, datetime.datetime ):
            self.value		= timestamp.number_from_datetime( value )
        else:
            raise ValueError( "Invalid timestamp of %s: %r", type( value ), value )

    def render( self, tzinfo=None, ms=True ):
        """Render the time in the specified zone, optionally with milliseconds.  If the resultant
        timezone is not UTC, include the timezone designation in the output.

        Since we are "rounding" to (default) 3 places after the decimal, and since floating point
        values are not very precise for values that are not sums of fractions whose denominators are
        powers of 2, we want to make sure that obvious problems don't occur.  You may specify from 0
        to 6 decimals of sub-second precision.

        The python floating point formatting operators seem to get it right most times by rounding,
        but the datetime.datetime.strftime doesn't use them to format milliseconds.  You get
        different result between Python 2/3:

            [datasim@debian-8-amd64 ~]$ python
            Python 2.7.6 (default, Mar 22 2014, 15:40:47)
            [GCC 4.8.2] on linux2
            Type "help", "copyright", "credits" or "license" for more information.
            >>> import datetime
            >>> for v in [1414915323.122, 1414915323.123, 1414915323.124, 1414915323.125, 1414915323.126, 1414915323.127 ]:
            ...  print( "%.9f == %s" % ( v, datetime.datetime.fromtimestamp( v ).strftime( "%f" )))
            ...
            1414915323.121999979 == 122000
            1414915323.122999907 == 123000
            1414915323.124000072 == 124000
            1414915323.125000000 == 125000
            1414915323.125999928 == 126000
            1414915323.127000093 == 127000
            >>>
            [datasim@debian-8-amd64 ~]$ python3
            Python 3.3.5 (default, Mar 22 2014, 13:24:53)
            [GCC 4.8.2] on linux
            Type "help", "copyright", "credits" or "license" for more information.
            >>> import datetime
            >>> for v in [1414915323.122, 1414915323.123, 1414915323.124, 1414915323.125, 1414915323.126, 1414915323.127 ]:
            ...  print( "%.9f == %s" % ( v, datetime.datetime.fromtimestamp( v ).strftime( "%f" )))
            ...
            1414915323.121999979 == 121999
            1414915323.122999907 == 122999
            1414915323.124000072 == 124000
            1414915323.125000000 == 125000
            1414915323.125999928 == 125999
            1414915323.127000093 == 127000
            >>>

        It appears that Python 2 datetime.strftime rounds to 6 decimal points, but that python 3
        just truncates.  So, we could compensate by simply using the Python floating point formatter
        to properly round the fractional part to the desired number of decimal places.
        Unfortunately, this doesn't take into account the rounding up to the next second that would
        occur with (for example) a timestamp like 1399326141.999836:

            > assert timestamp( 1399326141.999836 ) >= timestamp( 1399326141.374836 )
            E assert <2014-05-05 21:42:21.000 =~= 1399326141.999836> >= <2014-05-05 21:42:21.375 =~= 1399326141.374836>

        So, we round to specified places of sub-second precision first, used the rounded timestamp
        to generate the datetime for formatting, and then use floating point formatting to generate
        the rounded microseconds: this produces identical results on Python 2/3:

            >>> from cpppo.history import timestamp
            >>> for v in [1414915323.122, 1414915323.123, 1414915323.124, 1414915323.125, 1414915323.126, 1414915323.127, 1399326141.999836 ]:
            ...  print( "%.9f == %.9f == %.3f == %s" % ( v, round( v, 3 ), round( v, 3 ), timestamp( v ) ))
            1414915323.121999979 == 1414915323.121999979 == 1414915323.122 == 2014-11-02 08:02:03.122
            1414915323.122999907 == 1414915323.122999907 == 1414915323.123 == 2014-11-02 08:02:03.123
            1414915323.124000072 == 1414915323.124000072 == 1414915323.124 == 2014-11-02 08:02:03.124
            1414915323.125000000 == 1414915323.125000000 == 1414915323.125 == 2014-11-02 08:02:03.125
            1414915323.125999928 == 1414915323.125999928 == 1414915323.126 == 2014-11-02 08:02:03.126
            1414915323.127000093 == 1414915323.127000093 == 1414915323.127 == 2014-11-02 08:02:03.127
            1399326141.999835968 == 1399326142.000000000 == 1399326142.000 == 2014-05-05 21:42:22.000

        """
        subsecond		= self._precision if ms is True else int( ms ) if ms else 0
        assert 0 <= subsecond <= 6, "Invalid sub-second precision; must be 0-6 digits"
        value			= round( self.value, subsecond ) if subsecond else self.value
        dt			= self.datetime_from_number( value, tzinfo=tzinfo )
        result			= dt.strftime( self._fmt )
        if subsecond:
            result	       += ( '%.*f' % ( subsecond, value ))[-subsecond-1:]
        if dt.tzinfo is not self.UTC:
            result	       += dt.strftime( ' %Z' )
        return result

    def __float__( self ):
        return self.value

    def __int__( self ):
        return int( self.value )

    def __str__( self ):
        """Lazily produce (and cache) the UTC string formatted version."""
        if self._str is None:
            self._str		= self.render( ms=True )
        return self._str

    def __repr__( self ):
        return '<%s =~= %.6f>' % ( self, self.value )

    @property
    def utc( self ):
        return str( self )
    @utc.setter
    def utc( self, utctime ):
        """Changed the timestamp to the UTC timezone wall-clock time provided, in seconds w/ optional
        microseconds, and invalidate the cached string version.

        We understand only a very simple YYYY-MM-DD HH:MM:SS[.sss] [TZ] time format (default TZ: UTC)

        Note that we default to interpreting a bare timezone-free value as UTC; since the caller may
        have included a timezone, eg: '2014-05-05 11:22:33 MST', the result will be a datetime
        localized to the target timezone; number_from_datetime correctly handles datetimes localized
        to any timezone, and produces the correct UNIX timestamp.

        """
        self.value		= self.number_from_datetime( self.datetime_from_string( utctime ))
        self._str		= None

    @property
    def local( self ):
        """Return the timestamp's string format in local timezone wall-clock time, in seconds + timezone.
        These representations are sometimes ambiguous (unless a timezone abbreviation implying the
        precise timezone is included, eg. MST, MDT).  The Daylight Savings Times specific timezones
        are supported, if timestamp.support_abbreviations( "<region>" ) has been called.

        We understand only a very simple YYYY-MM-DD HH:MM:SS[.sss] [TZ] time format (default: the
        host's local timezone)

        The problem with local times, of course, is that in the spring there is a period of time
        between 02:00:00 - 02:59:59 that doesn't exist (is skipped) when you "spring ahead", and in
        the fall 02:00:00 - 02:59:59 is repeated (and is therefore ambiguous) when you "fall back".

        Therefore, using a standard generic timezone designation (eg. 'America/Edmonton') along with
        these ambiguous/impossible times leads to an AmbiguousTimeError or NonExistentTimeError
        Exception.  Use one of the DST-specific timezone designations instead, such as 'MST' (a
        non-DST timezone where there are no non-existent times, so NonExistentTimeError is not
        possible), or the DST-specific 'MDT', to specify that you mean the DST version of one of the
        ambiguous times during the DST to non-DST transition hour in the fall.

        """
        return self.render( tzinfo=self.LOC, ms=False )
    @local.setter
    def local( self, loctime ):
        self.value		= self.number_from_datetime( self.datetime_from_string( loctime, self.LOC ))
        self._str		= None

    # Comparisons.  Always equivalent to lexicographically, in UTC to 3 decimal places.  However,
    # we'll compare numerically, to avoid having to render/compare strings; if the <self>.value is
    # within _epsilon (default: 0.001) of <rhs>.value, it is considered equal.
    def __lt__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return self.value + self.__class__._epsilon < rhs.value
    def __gt__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return self.value - self.__class__._epsilon > rhs.value
    def __le__( self, rhs ):
        return not self.__gt__( rhs )
    def __ge__( self, rhs ):
        return not self.__lt__( rhs )
    def __eq__( self, rhs ):
        return not self.__ne__( rhs )
    def __ne__( self, rhs ):
        return self.__lt__( rhs ) or self.__gt__( rhs )

    # Add/subtract numeric seconds.  +/- 0 is a noop/copy.
    def __add__( self, rhs ):
        if rhs:
            return timestamp( self.value + rhs )
        return timestamp( self )
    def __iadd__( self, rhs ):
        if rhs:
            self.value	       += rhs
            self._str		= None
        return self
    def __sub__( self, rhs ):
        if rhs:
            return timestamp( self.value - rhs )
        return timestamp( self )
    def __isub__( self, rhs ):
        if rhs:
            self.value	       -= rhs
            self._str		= None
        return self
