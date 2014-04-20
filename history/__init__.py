
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

from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ["timestamp", "get_localzone"]

import bisect
import bz2
import calendar
import collections
import datetime
import gzip
import json
import logging
import os
import re
import string
import subprocess
import sys
import time
import traceback

import cpppo
from   cpppo import misc

log				= logging.getLogger( __file__ )

# Installed packages (eg. pip/setup.py install)
import pytz
try:
    from tzlocal import get_localzone
except ImportError:
    def get_localzone( _root='/' ):
        """No tzlocal; support basic Linux systems with a TZ variable or an /etc/timezone file"""

        # TZ environment variable?  Either a tzinfo file or a timezone name
        tzenv			= os.environ.get( 'TZ' )
        if tzenv:
            if os.path.exists( tzenv ):
                with open( tzenv, 'rb' ) as tzfile:
                    return pytz.tzfile.build_tzinfo( 'local', tzfile )
            return pytz.timezone( tzenv )

        # /etc/timezone file?
        tzpath			= os.path.join( _root, 'etc/timezone' )
        if os.path.exists( tzpath ):
            with open( tzpath, 'rb' ) as tzfile:
                tzname		= tzfile.read().decode().strip()
            if '#' in tzname:
                # eg. 'Somewhere/Special # The Special Zone'
                tzname	= tzname.split( '#', 1 )[0].strip()
            if ' ' in tzname:
                # eg. 'America/Dawson Creek'.  Not really correct, but we'll handle it
                tzname	= tzname.replace( ' ', '_' )
            return pytz.timezone( tzname )

        raise pytz.UnknownTimeZoneError( 'Can not find any timezone configuration' )

    
class timestamp( object ):
    """Initialize from a timestamp or a UTC formatted date-time string, and produce float timestamp
    value or string.

    All numeric timestamps are converted to string, and all comparisons between timestamps should be
    in string form, to ensure that all timestamps are truncated to the same precision.  The format
    is chosen to ensure that it is lexicographically comparable while maintaining monotonic and
    increasing comparability of timestamps.  In other words, two timestamps that compare > (if
    truncated to 3 digits of sub-second precision) will also compare identically as strings.

    Always has a .value which is the unix timestamp as a float.  The string version is lazily produced.
    """
    UTC				= pytz.utc
    LOC				= get_localzone() # from environment TZ, /etc/timezone, etc.

    _timeseps			= ( string 
                                    if sys.version_info.major < 3
                                    else str ).maketrans( ":-.", "   " )
    _fmt			= '%Y-%m-%d %H:%M:%S' # 2014-04-01 10:11:12

    # A map of all the common timezone abbreviations to their canonical timezones along with the
    # proper is_dst setting.
    _tzabbrev			= {}
    @classmethod
    def support_abbreviations( cls, region ):
        """Add all the DST and non-DST abbreviations for the specified region.  If a country code
        (eg. 'CA') is specified, we'll get all its timezones from pytz.country_timezones.
        Otherwise, we'll get all the matching '<region>/<city>' zones from pytz.common_timezones.

        We'll look for any time transitions in the future of the current time in pytz's
        _utc_transition_times list, and see if the timezone yields different timezone names and
        is_dst designations for the days surrounding that time.  If both are different, we'll use
        the abbreviations.

        """
        zones			= pytz.country_timezones.get( region )
        if zones is None:
            zones		= [z for z in pytz.common_timezones if z.split( '/' )[0] == region]
        assert len( zones ), "Invalid region %r: Matches no timezones" % region
        for tz in zones: # eg 'America/Vancouver', 'America/Dawson_Creek', ...
            tzinfo		= pytz.timezone( tz )
            reject		= False
            # Find the nearest transition time. This will compute the index where 'now' should be
            # inserted to maintain the list order, so it may index one beyond the end of the list.
            # Pick the highest (newest) time, and make sure it is in the future.
            now			= datetime.datetime.utcnow()
            i			= bisect.bisect_left( tzinfo._utc_transition_times, now )
            if i == len( tzinfo._utc_transition_times ):
                #print( "%-24s: Ignoring; no time change in future" % ( tzinfo ))
                continue
            nexttrans		= tzinfo._utc_transition_times[i]
            ins,out		= ( tzinfo.localize( dt )
                                    for dt in ( nexttrans + datetime.timedelta( 1 ),
                                                nexttrans - datetime.timedelta( 1 ) ))
            insabb,outabb	= ( dt.strftime( "%Z" ) for dt in ( ins, out ))
            insdst,outdst	= ( bool( dt.dst() )    for dt in ( ins, out ))

            if insabb == outabb or insdst == outdst:
                #print( "%-24s ==> %-4s, DST %-5s; Ignoring; abbreviation / DST same" % ( tzinfo, insabb, insdst ))
                continue
            # There is a timezone name and DST change for this timezone in the future.  Save them.
            #print( "%-24s %s ==> %-4s, DST %-5s%s" % (
            #    tzinfo, ins, insabb, insdst, "" if insabb not in cls._tzabbrev else "; Ignoring; already exists" ))
            if insabb not in cls._tzabbrev:
                cls._tzabbrev[insabb]= ins.tzinfo,insdst
            #print( "%-24s %s ==> %-4s, DST %-5s%s" % (
            #    tzinfo, out, outabb, outdst, "" if outabb not in cls._tzabbrev else "; Ignoring; already exists" ))
            if outabb not in cls._tzabbrev:
                cls._tzabbrev[outabb]= out.tzinfo,outdst

    @classmethod
    def datetime_from_string( cls, s, tzinfo=UTC ):
        """Parse a time, in the specified timezone.  Or, if the time contains a timezone (the last
        element is not a number), use that as the timezone instead.  If the timezone is a generic
        timezone, then the default Daylight Savings Time is applied:

            2014-11-01 01:02:03.456 America/Edmonton   (Nov 1 2014 -- DST *is* in effect)

        To be specific about whether DST applies, use a DSt_specific timezone abbreviation:
        
            2014-11-02 01:02:03.123 MST                (Nov 2 2014 -- 1:02 *after* DST ended)
            2014-11-02 01:02:03.456 MDT                (Nov 2 2014 --  :58 *before* DST ends)

        """
        try:
            terms		= s.translate( cls._timeseps ).split()
            is_dst		= None
            if not terms[-1].isdigit():
                # Hmm; Last term isn't digits; must be a timezone.  If we identify one of the
                # DST-specific abbreviation variants of the standard timezones, set is_dst and use
                # the standard timezone.
                terms,tz	= terms[:-1],terms[-1]
                if tz in cls._tzabbrev:
                    tzinfo,is_dst= cls._tzabbrev[tz]	
                else:
                    tzinfo	= pytz.timezone( tz )
                #print( "Timezone %s --> %s, DST %s" % ( tz, tzinfo, is_dst ))

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
    def datetime_from_number( cls, n, tzinfo=UTC ):
        """Convert a numeric timestamp, into a datetime in the specified timezone."""
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
            self.value		= misc.timer()
        elif type( value ) in (float, int):
            self.value		= float( value )
        elif isinstance( value, cpppo.type_str_base ):
            self.utc		= value
        elif isinstance( value, timestamp ):
            self.value		= value.value
            self._str		= value._str
        else:
            raise ValueError( "Invalid timestamp of %s: %r", type( value ), value )

    def format( self, tzinfo=UTC, ms=True ):
        """Format the time in the specified zone, optionally with milliseconds.  If the specified
        timezone is not UTC, include the timezone designation.

        Since we are "rounding" to 3 places after the decimal, and since floating point values are
        not very precise for values that are not sums of fractions whose denominators are powers of
        2, we want to make sure that obvious problems don't occur.

        The python floating point formatting operators seem to get it right most times, but the
        datetime.datetime.strftime doesn't use them to format milliseconds.  You get different
        result between Python 2/3:

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
        just truncates.  So, we'll compensate by simply using the Python floating point formatter to
        properly round the fractional part to the desired number of decimal places.

        """
        dt			= self.datetime_from_number( self.value )
        result			= dt.strftime( self._fmt )
        if ms:
            result	       += ( "%.3f" % self.value ) [-4:]
        if tzinfo is not self.UTC:
            result	       += dt.strftime( ' %Z' )
        return result

    def __str__( self ):
        """Lazily produce (and cache) the UTC string formatted version.

        """
        if self._str is None:
            self._str		= self.format( ms=True )
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
        self.value		= self.number_from_datetime( self.datetime_from_string( utctime, self.UTC ))
        self._str		= None

    @property
    def local( self ):
        """Return the timestamp's string format in local timezone wall-clock time, in seconds +
        timezone.  These representations are ambiguous (unless the precise timezone is included,
        eg. MST, MDT).  The Daylight Savings Times specific timezones are supported.

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
        return self.format( tzinfo=self.LOC, ms=False )
    @local.setter
    def local( self, loctime ):
        self.value		= self.number_from_datetime( self.datetime_from_string( loctime, self.LOC ))
        self._str		= None

    # Comparisons.  Always lexicographically, in UTC
    def __lt__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return str( self ) < str( rhs )
    def __le__( self, rhs ):
        return str( self ) <= str( rhs )
    def __gt__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return str( self ) > str( rhs )
    def __ge__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return str( self ) >= str( rhs )
    def __eq__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return str( self ) == str( rhs )
    def __ne__( self, rhs ):
        assert isinstance( rhs, timestamp )
        return str( self ) != str( rhs )

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
