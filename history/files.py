
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

__all__				= ["opener", "logger", "parse_record",
                                   "HistoryExhausted", "reader",
                                   "DataError", "IframeError", "loader"]

import bz2
import collections
import gzip
import json
import logging
import os
import subprocess
import traceback

from .times		import timestamp, format_offset
from ..misc		import timer, natural, reprlib
from ..automata		import type_str_base

log				= logging.getLogger( __package__ )

def opener( path, mode='rb', bufsize=4*1024 ):
    """Open a file in the specified mode ('r', 'w'), using the appropriate compressor if necessary.  All
    objects returned must be context managers (respond to 'with <obj>: ... ' by closing the object).
    Presently this limits us to .gz, .bz2, .xz and (default) plain files.

    WARNING
    
    The present implementation does *not* properly present the I/O stream of a subprocess.Popen
    (used for lzma '.xz' files); it returns it either as an iterator, or via a context manager which
    presents the open stdin/stdout file descriptor.  Therefore, it may *only* be used in the form
    'with <fd> as <var>: ...' or 'for <var> in <fd>: ...'

    """
    r, w			= 'r' in mode, 'w' in mode
    assert ( r or w ) and ( r ^ w ), "Invalid mode: %s" % mode

    class closer( object ):
        """Present an open stream via context manager (close automatically) or iterator (close manually)."""
        def __init__( self, path, fd ):
            self.path		= path
            self.fd		= fd
        def __iter__( self ):
            return self.fd
        def __enter__( self ):
            return self.fd
        def __exit__( self, typ, val, tbk ):
            self.close()
            return False
        def close( self ):
            self.fd.close()
            log.info( "Closed file %s", self.path )

    class closer_subprocess( closer ):
        """Present a subprocess.Popen.{stdin,stdout,stderr} stream via context manager or iterator, closing
        all streams and waiting for the process to terminate when closed.
        """
        def __init__( self, path, fd, sub, terminate=None ):
            super( closer_subprocess, self ).__init__( path, fd )
            self.sub		= sub
            self.terminate	= terminate
        def close( self ):
            for s in self.sub.stdin, self.sub.stderr, self.sub.stdout:
                if s:
                    s.close()
            try:
                if self.terminate:
                    self.sub.terminate()
            except:
                pass
            self.sub.wait()
            log.info("Closed subprocess (%s) for %s", self.sub.returncode, self.path )

    if path.endswith( '.bz2' ):
        log.info( "Opening bzip file for %s: %s", mode, path )
        return closer( path, bz2.BZ2File( path, mode=mode ))
    elif path.endswith( '.gz' ):
        log.info( "Opening gzip file for %s: %s", mode, path )
        return closer( path, gzip.GzipFile( path, mode=mode ))
    elif path.endswith( '.xz' ):
        log.info( "Opening lzma sub. for %s: %s", mode, path )
        if r:
            sub			= subprocess.Popen( ['xz', '--decompress', '--stdout', path],
                                    shell=False, bufsize=bufsize, stdout=subprocess.PIPE )
            # Reading; terminate the subprocess, because we don't want any more of the 
            # output decompressed
            return closer_subprocess( path, sub.stdout, sub, terminate=True )
        else:
            sub			= subprocess.Popen( 'xz --compress > ' + path,
                                    shell=True, bufsize=bufsize, stdin=subprocess.PIPE )
            # Writing; do not terminate; close the stdin stream and wait for the subprocess
            # to detect EOF and terminate naturally.
            return closer_subprocess( path, sub.stdin, sub )
    else:
        log.info( "Opening raw  file for %s: %s", mode, path )
        return closer( path, open( path, mode, bufsize ))


class logger( object ):
    """Log history data to a file.

    We need to cleanly handle two failure modes; unable to open the file and, unable to write once
    opened.  In either case, we want to log the failure once, but keep trying.

    The default bufsize is None (system default, probably 1-4k).  If desired, change the bufsize to
    1 (line buffering) or a specific buffer size.  This can be changed by setting the .bufsize
    attribute between opens, and will take effect on the next log rotation.  If playback may catch
    up to the current time, it is critical to set line buffering.

    """
    DFLT_BUF			= None
    LINE_BUF			= 1

    def __init__( self, path, bufsize=DFLT_BUF ):
        log.info( "Logging history to path: %s", path )
        if type( path ) is str:
            path_dir		= os.path.dirname( path )
            if path_dir and not os.path.exists(path_dir):
                os.makedirs(path_dir)

        self.path		= path
        self.f			= None
        self.error		= False
        self.bufsize		= bufsize

    def __nonzero__( self ):
        """History logger should evaluate to false if:
        
        - The file is closed (covers path being None)
        - There is an active error

        """
        log.debug( "f = %s, error: %s", self.f, self.error )
        return bool( self.f and not self.error )

    __bool__			= __nonzero__		# Python3

    def __enter__( self ):
        return self

    def __exit__( self, typ, val, tbk ):
        try:
            self.close()
        except Exception as exc:
            log.warning( "Suppressed close failure on logger.__exit__: %s", exc )
        return False # suppress no exceptions

    def buffering( self, bufsize=None ):
        """Change the buffering, and force re-opening of the file.  Instead of allowing the file to
        open automatically (and cause other possible side-effects, such as triggering an "initial"
        frame of register data), we will re-open it here if it is already opened.

        """
        if bufsize == 'line':
            bufsize		= 1
        if self.bufsize != bufsize:
            log.detail( "Changing buffering from %r to %r",
                             "line" if self.bufsize == self.LINE_BUF else self.bufsize,
                             "line" if bufsize == self.LINE_BUF else bufsize )
            self.bufsize	= bufsize
            if self.opened():
                self.close()
                self.open()

    def opened( self ):
        return bool( self.f )

    def open( self ):
        if self.path:
            log.info( "Opening history file: %s", self.path )
            self.f		= open( self.path, 'ab+', *( [] if self.bufsize is None else [self.bufsize]) )
            return True
        else:
            return False

    def close( self ):
        if self.f:
            log.info( "Closing history file: %s", self.path )
            try:
                self.f.close()			# May raise if file system full
            finally:
                self.f		= None		# maintain integrity by clearing self.f

    def _append( self, msg, encoding=None ):
        """Appends the raw msg str (which should contain a newline) to the file (open if
        necessary).  Raises an exception on any failure.

        The default encoding is 'ascii'; no non-ASCII UTF-8 symbols allowed in the provided string.

        """
        if not self.f:
            assert self.open(), "Could not open file %s for writing" % self.path
        self.f.write( msg.encode( encoding or 'ascii' ))
        
    def comment( self, s, encoding=None ):
        if self.path is None:
            return
        try:
            self._append( '# ' + s + '\n', encoding=encoding )
        except:
            pass

    def write( self, data, now=None, serial=None, encoding=None ):
        """Log the provided json to the history file; 'now' defaults to the current wall-clock time.
        Log (and absorb) failures.

        """
        if self.path is None:
            return
        ts		= timestamp( now )
        try:
            self._append( '\t'.join( (str( ts ), json.dumps( serial ), json.dumps( data ))) + '\n',
                          encoding=encoding )
            if self.error:
                log.error( "History writing resumed at %s", ts )
            self.error		= False
        except Exception as exc:
            if not self.error:
                log.error( "History writing failure at %s: %s", ts, exc )
            self.error		= True

def parse_record( fd, n=-1, encoding=None ):
    """Parse the next non-comment record from a history file.  The date-time and serial number must be
    intact, but the remainder of the line are returned as-is.  Raise StopIteration if no record
    found, or some other Exception if the timestamp or serial number cannot be parsed.

    The default 'ascii' encoding assumes no non-ASCII (eg. UTF-8) characters in the file, or an
    exception will be raised.

    """
    l				= None
    for l in fd:
        n		       += 1
        l			= l.decode( encoding or 'ascii' ).lstrip()
        if not l or l.startswith( '#' ):
            l			= None
            continue # blank or comment
        break
    if not l:
        raise StopIteration( "Empty file" )
    dt,sn,js			= l.split( '\t', 2 )
    return n,(timestamp( dt ), json.loads( sn ), js )


class HistoryExhausted( Exception ):
    pass

class reader( object ):
    """Open the specified history file(s) and read register values from them, yielding a stream of
    <fileinfo>,<record> tuples.  Produces data until the "current" historical time is reached,
    relative to current wall-clock time.  There is no provision to force reader.open to yield
    records up to a "historical" time that maps to some other wall-clock time; derived classes may,
    however, store up the records and absorb them at a different rate and/or order.

    Replays history from the provided 'historical' timestamp.  The history files will be searched for
    the first file beginning at or before 'historical'.  If none found, then historical playback
    will proceed at the oldest available file, and its initial values will be considered as "frozen"
    before that time.

    Playback will be scheduled to synchronize at 'basis' wall-clock time, and proceed at 'factor' of
    wall-clock time.  History playback will begin as soon as the first time register or updates is
    called; even if this is "before" the provided 'basis'; the target historical time will be
    computed accordingly (eg. perhaps negatively from specified 'historical' target time).

    If the historical playback time reaches current real time, or no historical files satisfying the
    request can be found, then reader evaluates False, and register/updates will raise an exception
    if called; it is recommended that the user cease using the reader and discard it.

    """
    def __init__( self, path, historical, basis=None, factor=None ):
        log.info( "Reading history from path: %s", path )
        self.path		= path
        self.dirs		= os.path.dirname( self.path )
        self.name		= os.path.basename( self.path )
        self.historical		= timestamp( historical )
        self.basis		= timestamp( basis )
        self.factor		= factor or 1.0

    def __str__( self ):
        """Gives the historical start time, followed by how far the current historical time has advanced."""
        dt			= ( timer() - self.basis.value ) * self.factor
        return "%s %s%3d:%02d:%06.3f x %4.2f %s" % ( self.historical, '<' if dt < 0 else '>',
            int( abs( dt ) // 3600 ), int( abs( dt ) % 3600 // 60 ), abs( dt ) % 60,
            self.factor, self.name )

    def __repr__( self ):
        return '<' + self.__str__() + '>'

    def advance( self, now=None ):
        """Return a timestamp representing the computed historical time.  Compute the historical
        timestamp, from the present real time 'now' and the specified starting time basis, and time
        scaling factor.  Accepts int/float UNIX time, <timestamp>, or any type <timestamp> accepts.

        """
        if now is None:
            now			= timer()
        elif type( now ) not in (int,float):
            if not isinstance( now, timestamp ):
                now		= timestamp( now )
            now			= now.value
        return self.historical + ( now - self.basis.value ) * self.factor

    def realtime( self, when ):
        """Return the realtime wall-clock UNIX timestamp that the provided <ts> corresponds to.
        Accepts int/float UNIX time, <timestamp>, or any type <timestamp> accepts.  Inverts the
        formula used by advance:
        
            <ts>			= <historical> + ( <now> - <basis>.value ) * <factor>

            <ts> - <historical		=                ( <now> - <basis>.value ) * <factor>

            <ts> - <historical
            ------------------		=                  <now> - <basis>.value 
            <factor>

            <ts> - <historical>
            ------------------ + <basis>=                  <now>
            <factor>

        These values would be the ones used when historical values are inserted into data structures
        that need to be ordered and compared using realtime wall-clock UNIX timestamps.

        """
        if when is None:
            when		= timer()
        elif type( when ) not in (int,float):
            if not isinstance( when, timestamp ):
                when		= timestamp( when )
            when		= when.value
        return ( when - self.historical.value ) / self.factor + self.basis.value

    def open( self, target=None, after=True, lookahead=None, strict=False, encoding=None ):
        """Open an iterator which will yield its historical records vs. self.historical, at the
        prescribed self.{basis,rate}, relative to the initial timestamp 'target' (eg. the last
        timestamp from the previous file).  If no appropriate historical file can be found, raises a
        HistoryExhausted exception.  If lookahead is provided, yields records up to that many
        wall-clock seconds into the future (ie. *ahead* of the current historical time).  Yields
        records of the form:
        
            (f,n,cur),(ts,js)

        where f,n,cur is the file, line number and current historical timestamp (NOT including
        lookahead), and ts,js describes the history record found (if any).

        Once an appropriate file is found, yields (<timestamp>,"<json>") records continually until
        it is caught up vs. self.{history,basis,rate}, then will yield (<timestamp>,None).  It is
        expected that the caller will call it whenever it needs all the records up to the current
        time, and will stop when a <json> payload of None is yielded, 'til later when more records
        are required.

        If a parsing error occurs (no 'YYYY-MM-DD HH:MM:SS' <timestamp> could be parsed on the
        current line, or no ' <json>' payload followed), then a warning will be logged and
        (None,None) will be yielded indicating no record could be parsed.  The caller may choose to
        power thru the problem and continue parsing 'til a record is recognized, or may choose to
        fail.

        Once the file is exhausted, raises StopIteration.  It is expected that the caller invoke us
        again with 'target' being the timestamp of the last record from the previous file; the
        default behavior is to find the next file "after" that 'target' timestamp, and start
        returning its records.  If 'strict', then the file MUST be strictly > (if 'after'), or < (if
        "before").  This is important if a file is loaded with only one line in it, or lines with
        all the same timestamp -- we would open the same file again (the file would satisfy 'after',
        because the file's initial timestamp would satisfy >= its own last timestamp)!  So, until
        the current file contains increasing timestamps, pass 'strict=True' on the next 'open' call.

        Find the highest numbered historical file starting at or after 'target', assuming:
        
            blah.hst		# < most recent
            blah.hst.0
            blah.hst.1		# < being compressed; may disappear momentarily
            blah.hst.1.gz
            blah.hst.2.gz
            ...
            blah.hst.9.gz	# < oldest
        
        So, we'll find all the files in the path's dir starting with the base name, and then sort
        them in "natural" collation order (embedded numbers are compared numerically).
        
        Tries to safely handles files disappearing between globbing and opening due to compression
        and log rotation; we open all files immediately, so it unlikely that the a file has been
        renamed between scanning the directory and opening the files by name.  If a duplicate file
        (eg. blah.hst.1 and blah.hst.1.gz ) is detected, the earlier (uncompressed) is preferred,
        addressing potential issues with using a file currently being compressed.

        If an appropriate file is found, opens it and puts its first record in self.{fd,rec}, and
        returns the filename.  Otherwise, returns None.  If an exception is raised, it may be
        prudent to try again in a few milliseconds, in case files are being rotated at that instant
        and two subsequent files (momentarily) had the same timestamp, because it was moved.

        """
        if target is None:
            # If no target is supplied, we'll guess that we want to start from where we presently
            # are in the advancing historical playback time.  Normally, we'd be using this function
            # to open the "next" history file after the last record of some history file -- so we'd
            # want 'target' to be the last timestamp from that file.  On an initial open, we'd want
            # 'target' to be the desired starting time, and 'after=False', to force us to look for
            # the newest file whose first timestamp is "before" the desired start time.
            target		= self.advance()
        else:
            # Support a numeric UNIX timestamp, UTC string or timestamp()
            target		= timestamp( target )
        log.detail( "%s Opening file %s%s%s", self, '>' if after else '<', ' ' if strict else '=', target )

        # Evaluate each file.  The timestamps should be monotonic and increasing.  Open all files,
        # appending to opened so we can unwind on failure.  We cannot easily discard duplicate files
        # here by name, eg. blah.1 and blah.1.gz; what about blah and blah.0, which differ only by
        # an extension, but are not duplicates?
        opened			= []
        try:
            # Evaluate all available history files, leaving the desired one open in 'fd'; 'f' is
            # only the file name extension!
            fd			= None
            flen		= len( self.name )
            for f in sorted(( n[flen:] for n in os.listdir( self.dirs ) if n.startswith( self.name )), key=natural ):
                fd		= None
                try:
                    # Evaluate this file; load the first record and check before/after target If
                    # anything is wrong with the file or the header, skip it.  We are intolerant of
                    # errors at the beginning of a file, because this is where the "iframe" of all
                    # current register values must be.
                    fd		= opener( self.path + f )
                    n		= -1
                    n,(ts,sn,js)= parse_record( fd, encoding=encoding )
                except StopIteration:
                    # No more records; on to the next file
                    break
                except Exception as exc:
                    log.warning( "%s Ignoring history file %s: %s", self, self.name+f, exc )
                    if fd:
                        fd.close()
                    continue

                # Opened the fd, got a ts; check it against target.  Stack the file extension, line
                # number, fd and record onto opened, in case we need to go back to it (and to clean
                # them up on exit).  On success, the last file on opened is the winner.
                if after and not( ts > target if strict else ts >= target ):
                    # want after, and file is first not newer than target; use last opened
                    log.detail(  "%s Rejected history file %s (%s after %s fails)", self, self.name+f, ts, target )
                    fd.close()
                    break

                log.info( "%s Defered history file %s (%s after %s)", self, self.name+f, ts, target )
                opened.append( (f,n,fd,(ts,js)) )
                if not after and ( ts < target if strict else ts <= target ):
                    # want records before target, and this file is older than target; use last opened
                    break

            # The last opened file is the winner.  Close any extras right now, leaving the last one
            # in opened, so that we can clean it up on exit
            if len( opened ) == 0:
                raise HistoryExhausted( "No history files found for %s %s" % ( "after" if after else "before", target ))
            while len( opened ) > 1:
                f,n,fd,(ts,js)	= opened.pop( 0 )
                fd.close()

            f,n,fd,(ts,js)	= opened[0]
            log.debug( "%s Playback starting on %s, line %d (%s %s %s)", self,
                             self.name+f, n, ts, "after" if after else "before", target )

            # Yield records from the history file 'til we reach a record that is beyond the
            # advancing historical time plus lookahead (only recompute when it fails).  The meanings
            # of combinations of <timestamp>,<data>:
            # 
            #     <timestamp>,<data>		Meaning
            #     None        None/string	No timestamp parsed due to error in history file
            #     (valid)     None		No data ready yet; next valid record is in the future
            #     (valid)     '{ ... }'		A timestamp record
            cur			= self.advance()
            adv			= cur + ( lookahead or 0.0 )
            while True:
                if ts > adv:
                    cur		= self.advance()
                    adv		= cur + ( lookahead or 0.0 )
                    if ts > adv:
                        #log.info( "%s %.3fs delay to next record %s", ts.value - cur.value, ts )
                        yield (f,n,cur),(ts,None)
                        continue

                # OK, this record's ts is <= our advancing historical time incl. lookahead
                yield (f,n,cur),(ts,js)

                # Get another; after this stanza, we must have a (ts,js).  If this fails, we'll
                # raise an exception, which should cause the caller to drop out of the historical
                # processing mode; it is not likely safe for them to try again, because they'll
                # probably process the same file and get the same error.  Report the file and
                # timestamp so it can be fixed, if necessary...  If empty file, raise StopIteration
                try:
                    n,(ts,sn,js) = parse_record( fd, n=n, encoding=encoding )
                except StopIteration:
                    break

                # a valid (ts,js) has been parsed; loop to advancing historical time, and return it
                # when appropriate.

                #log.debug( "%s Playback reading: %s, line %4d (%s), serial %8s: %s", self,
                #           f, n, ts, sn, js[:-1] if js.endswith( '\n' ) else js )

            # Exhausted playback of this history file
            log.debug( "%s Playback complete: %s, line %d", self, f, n )
            return # raise StopIteration

        finally:
            # On success or failure, every remaining opened file must be closed
            for f,n,fd,(ts,js) in opened:
                fd.close()

class DataError( ValueError ):
    """There was an error parsing historical data."""
    pass

class IframeError( DataError ):
    """There was an error parsing the initial frame of historical data."""
    pass

class loader( reader ):
    """Make a single pass thru history, evaluating True 'til the history is exhausted.  Logs parsing
    errors, but attempts to power thru."""

    INITIAL			= 0		# Need to open the initial history file (one "before" target time)
    SWITCHING			= 1		# Need to open the next history file (one "after" target time)
    STREAMING			= 2		# Have opened a generator, still producing events
    EXHAUSTED			= 3		# History empty, may still have unconsumed lookahead events
    AWAITING			= 4		# Have a generator, but it is awaiting future historical time
    COMPLETE			= 5		# All events have been consumed
    FAILED			= 6

    statename			= {
        INITIAL:	"INITIAL",
        SWITCHING:	"SWITCHING",
        STREAMING:	"STREAMING",
        EXHAUSTED:	"EXHAUSTED",
        AWAITING:	"AWAITING",
        COMPLETE:	"COMPLETE",
        FAILED:		"FAILED",
    }
    statelogger			= {
        INITIAL:		logging.NORMAL,
        SWITCHING:		logging.NORMAL,
        STREAMING:		logging.INFO,
        EXHAUSTED:		logging.NORMAL,
        AWAITING:		logging.DETAIL,
        COMPLETE:		logging.WARNING,
        FAILED:			logging.WARNING,
        (INITIAL,STREAMING):	logging.WARNING,
        (INITIAL,AWAITING):	logging.WARNING,
        (SWITCHING,STREAMING):	logging.NORMAL,
        (SWITCHING,AWAITING):	logging.NORMAL,
    }

    def __init__( self, path, historical, basis=None, factor=None, lookahead=None, duration=None, values=None ):
        super( loader, self ).__init__( path=path, historical=historical, basis=basis, factor=factor )
        self.lookahead		= lookahead
        self._duration		= None
        self._deadline		= None
        self.duration		= duration		# How many historical seconds to run before terminating
        self.future		= collections.deque()	# Available events; may be in future
        self.until		= None			#   and the timestamp of the last event's registers loaded into .values
        self._state		= self.INITIAL
        self._i			= None			# The generator yielding historical records
        self._f			= ''			#   and the file self.name/path extension
        self._n			= 0			#   and line we're currently parsing
        self._ts		= None			# Last received timestamp; if None, open will use advancing historical time
        self._strict		= False			#   True after opening a new file, goes False when _ts increases
        self.values		= {}			# Historical values at historical timestamp
        if values:
            # Some default values are provided; initialize our values to them, with a 0.0 timestamp
            # This allows us to return values on a full update (eg. since 0.0).  We need to do this
            # in an environment where clients are already receiving value updates, and we want to
            # make certain we over-write them to default values, until the initial historical
            # playback record is returned.
            self.values.update( ( (int( r ),(0.0,int( v ))) for r,v in values.items() ) )
            log.warning( "%s Providing %d initial default register values: %s", self,
                              len( values ), reprlib.repr( values ))

    @property
    def duration( self ):
        return self._duration
    @duration.setter
    def duration( self, value ):
        self._duration		= value
        self._deadline		= None if value is None else self.historical + value

    @property
    def state( self ):
        return self._state
    @state.setter
    def state( self, value ):
        if type( value ) in (list,tuple):
            value,msg		= value
        else:
            msg			= None
        if self._state != value:
            # Find the right logger, by (<from>,<into>), then just <into>
            lev			= self.statelogger.get( (self._state,value) )
            if lev is None:
                lev		= self.statelogger.get( value )
            if log.isEnabledFor( lev ):
                log.log( lev, "%s %-10s -> %-10s%s",
                              self, self.statename[self._state], self.statename[value],
                              ': ' + str( msg ) if msg is not None else '' )
            self._state		= value

    def __str__( self ):
        return super( loader, self ).__str__() + "%-7s(%5d)" % ( ' none' if self._f is None else self._f, self._n )

    def __nonzero__( self ):
        return self.state < self.COMPLETE

    __bool__			= __nonzero__		# Python3

    SUPPRESS			= 0
    FAIL			= 1
    RAISE			= 2
    def load( self, limit=None, upcoming=None, on_bad_iframe=FAIL, on_bad_data=SUPPRESS, encoding=None ):
        """Load values up to the current historical timestamp (optionally defined by 'now') into
        self.values, and fill self.future with pending input.  As records are loaded from history
        files, generate a list of (up to 'limit') events which are returned).  Events are of the
        form: [ { "timestamp": <2014-04-01 ...>, "command": "register", "values": { "40001": 12345, ... }
        }, ...  ].   Returns:

            <timestamp>,<events>

        where <timestamp> is the current advancing historical timestamp (ie. that of the last
        historical record applied to self.values, if any, or the current historical timestamp), and
        <events> is the list of any newly loaded events.

        If already open, continue reading.  If not, find the history file containing data at/before
        the given/current historical time.  Read any pending events into self.future, up to
        'historical' timestamp + lookahead.  Load self.future into self.value, up to the
        given/current 'historical' timestamp.  Note that the underlying 'open' iterator will always
        return values up to the current advancing historical timestamp + lookahead; if we are
        provided with a 'now', it should be close to the current time; this function will load all
        incoming values up to and including that time, and leave the rest in self.future.  If
        loading the values takes considerable time (eg. due to disk I/O), then the values loaded
        into self.values may be slightly behind the current advancing historical time.

        To avoid a possible degenerate memory usage condition where a large amount of history is
        loaded, and 'load' collects and returns a large number (eg. millions) of events, set 'limit'
        to a positive value, and repeatedly call <loader>.load until it doesn't return any events:

            ld			= loader( ... )
            events		= []
            e			= True
            while e:
                cur,e		= ld.load( limit=1000 )
                events.extend( e )

        If an 'upcoming' timestamp is provided, no events >= this timestamp will be processed and
        returned (they will be stored in self.future 'til 'upcoming' is advanced).  In this case,
        since no events may be returned, use the <loader>.state < loader.AWAITING to determine if
        <loader>.load should be called again.  Alternatively, if an 'upcoming=<timestamp>' is
        supplied, continue until the returned <timestamp>,<list> returns an empty <list> and a
        <timestamp> less than the supplied 'upcoming=<timestamp>'.  This indicates that the
        <loader>.load stopped before 'limit', and returned no events.


            ld			= loader( ..., limit=<timestamp> )
            events		= []
            upcoming		= <timestamp>	# some historical time >= <loader>.until
            while True:
                cur,e		= ld.load( limit=1000, upcoming=upcoming )
                if ld.state >= loader.AWAITING:
                    break
                if not e:
                    # No events returned, but not AWAITING/COMPLETE/FAILED -- advance 'upcoming'
                    upcoming	= <timestamp>	# The next historical event to advance to, or None

        """
        cur,events		= self.advance(),[]

        if not self:
            log.warning( "%s History already exhausted", self )
            return cur,events

        first			= True
        while self.state <= self.STREAMING or first:
            first		= False
            try:
                # We are not (yet) done.  Keep reading; we'll pop out at the end of first loop if
                # we're still AWAITING.
                if self.state in (self.INITIAL, self.SWITCHING ):
                    # We need to open the initial (or next) history file.
                    after	= ( self.state != self.INITIAL )
                    self._i	= self.open( target=self._ts, after=after, lookahead=self.lookahead,
                                             strict=self._strict, encoding=encoding )
                    self._strict= True # remains until we see increasing timestamps

                assert self.state in (self.INITIAL, self.SWITCHING, self.STREAMING, self.EXHAUSTED, self.AWAITING)
                # We have an open generator; process records.  We also still know if it was our
                # INITIAL open, or a SWITCHING open; if initial, we can tolerate no JSON errors, or
                # we'll miss our "iframe" of initial register values!  Only yields ts,js where <ts>
                # <= advancing historical time + lookahead; cur is always simply advancing
                # historical time.
                for (self._f,self._n,cur),(ts,js) in self._i:

                    # If js is None there is no record ready; if it evaluates to a string, then
                    # there is no record, it is just a Note.  If something goes wrong after here, we
                    # can put a note in data, or fail or raise an Exception.
                    data		= None
                    data_bad		= False
                    try:
                        if js is not None:
                            data	= json.loads( js )
                    except Exception as exc:
                        # JSON parsing failure.  Power thru (except on initial "iframe" of register values)...
                        if self.state == self.INITIAL:
                            data	= "Parsing problem: Initial frame of historical register data corrupt: %s" % exc
                            if on_bad_iframe != self.SUPPRESS:
                                raise IframeError( data )
                        else:
                            data	= "Parsing problem: Historical register data corrupt: %s" % exc
                        data_bad	= True

                    if ts is None:
                        # A parsing error occurred.  Power thru...  We should never see this just after
                        # opening a new history file, because the reader.open generator is intolerant of
                        # timestamp errors at the start of a file.
                        data		= "Parsing problem: Historical timestamp data corrupt: %s" % (
                            data if isinstance( data, type_str_base ) else "unknown problem" )
                        data_bad	= True
                        assert self.state not in (self.INITIAL, self.SWITCHING)
                        continue
                    if self._deadline is not None and self.state < self.EXHAUSTED and ts >= self._deadline:
                        # A deadline, and not yet marked EXHAUSTED; switch state, then consume lookahead
                        raise HistoryExhausted( "Exhausted history duration %s" %
                                                format_offset( self._duration, symbols='-+' ))

                    if js is None:
                        # Our incoming <js> was None; Parsing timestamp (at least) was OK, but is in
                        # the future!  Estimate the real wall-clock time we'll have to wait before
                        # the record would be yielded.
                        dt		= ts.value - cur.value - ( self.lookahead or 0.0 )
                        self.state	= self.AWAITING, \
                            "Playback waiting: %.3fs for %.3fs future timestamp %s" % (
                                dt / self.factor, dt, ts )
                        break

                    # We got a non-None <ts>,<js>; if we aren't exhausted, we're now streaming!
                    if self._strict:
                        # But first, carefully release self._strict.  If we opened a file, we'll set
                        # _strict.  The last file's final timestamp will be in self._ts; say it's
                        # "2014-04-01 00:00:00", and there was increasing data in it, so
                        # self._strict is false, and we just opened a new file, and its first and
                        # only record also has timestamp "2014-04-01 00:00:01"; thus ts > self._ts;
                        # So, do we want to release self._strict here?  No, because we'd re-open the
                        # same file next time!  Therefore, we have to see ts > self._ts and
                        # self.state isn't INITIAL/SWITCHING (eg. we've already seen records from
                        # the file )
                        if self.state not in (self.INITIAL, self.SWITCHING) and (
                                self._ts is None or ts > self._ts ):
                            log.debug( "%s Playback releasing strict for next open: %s > %s", self, ts, self._ts )
                            self._strict	= False

                    if self.state in (self.INITIAL, self.SWITCHING, self.AWAITING):
                        self.state	= self.STREAMING

                    if data is None and self.state != self.EXHAUSTED:
                        data		= "Parsing problem: ignoring historical record with 'null' data"
                        data_bad	= True

                    # If not None or a note by this time, the data payload must be register data.
                    # Produce the regs={r:(t,v), ...} we'll send back later; use realtime wall-clock
                    # UNIX timestamps in this dict, NOT the "historical" timestamp value.
                    if data and not isinstance( data, type_str_base ):
                        regs		= {}
                        try:
                            assert isinstance( data, dict ), "Unsupported %s" % type( data )
                            realtime	= self.realtime( ts )
                            regs	= dict( ( (int( r ),(realtime,int( v ))) for r,v in data.items() ) )
                        except Exception as exc:
                            data	= "Parsing problem: invalid register data: %s" % exc
                            data_bad	= True

                    if isinstance( data, type_str_base ):
                        # A Note, or (if 'data_bad') an Error message regarding the current record;
                        # Do not return.  Unless failing on bad data, just log a note regarding the
                        # parsing failure.  If data_bad wasn't set, then this was just a
                        # JSON-encoded string in the data stream, which is just a note.
                        log.warning( "%s %s: %s", self, "FAIL" if data_bad else "NOTE", data )
                        if data_bad and on_bad_data != self.SUPPRESS:
                            raise DataError( data )
                        continue
        
                    # Got a <timestamp> and the <data> decoded from JSON; might just have started a new
                    # history file.  We're STREAMING now.
                    assert self.state in (self.EXHAUSTED, self.STREAMING)
                    if data:
                        # A new value; if <ts> is monotonic and increasing, append <ts>,<regs> to
                        # future and generate an event with <ts>,<data>; otherwise, log/ignore it.
                        if self._ts is None or ts >= self._ts:
                            self._ts	= ts
                            events.append( {
                                'timestamp':	ts,
                                'command':	'register',
                                'values':	data,
                            } )
                            self.future.append( (ts,regs) )
                        else:
                            log.warning( "%s: Playback ignoring out-of-order timestamp: %s < %s", self, ts, self._ts )
                        self.state	= self.STREAMING, ts

                    while len( self.future ) and self.future[0][0] <= cur:
                        # Process element(s) from self.history whose time has come, updating 'until'
                        if upcoming is not None and self.future[0][0] >= upcoming:
                            # But, if the 'upcoming' event is exceeded, return the events up to the
                            # designated 'upcoming' timestamp (always with self.state < AWAITING)
                            return upcoming,events
                        ts,regs		= self.future.popleft()
                        log.info( "%s Absorbing %3d regs", self, len( regs ))
                        self.values.update( regs )
                        self.until	= ts

                    if self.state == self.EXHAUSTED:
                        if not self.future:
                            self.state = self.COMPLETE, "Playback complete; history exhausted, lookahead empty"
                        break

                    if limit is not None and len( events ) >= limit:
                        # Event limit exceeded.  We could still be STREAMING/EXHAUSTED, so return
                        # directly the events up to the last processed timestamp.
                        return self.until,events

                    # Out of ready values in self.future; go get more from the file via self._i
 
                # Done processing file, or perhaps done completely; loop unless we (probably) just popped out
                # while AWAITING/EXHAUSTED and not yet reached advancing historical time.
                assert self.state in (self.STREAMING, self.SWITCHING, self.AWAITING, self.EXHAUSTED, self.COMPLETE)
                if self.state in (self.STREAMING, ):
                    self.state	= self.SWITCHING, "Playback continuing: Ended current history file"

            except HistoryExhausted as exc:
                # If our history input generator loop blows out on a HistoryExhausted, we'll flip to
                # EXHAUSTED mode, which will allow us to drain our lookahead events from self.future
                # as historical time advances.  Generate a series of events containing advancing
                # time and a <js> payload that evaluates to None; this is only allowed/expected in
                # EXHAUSTED mode.
                self.state	= self.EXHAUSTED, "Playback completing: %s" % exc
                def noop():
                    while True:
                        cur	= self.advance()
                        yield (None,0,cur),(cur,'null')
                self._i		= noop()

            except IframeError as exc:
                self.state	= self.FAILED, "Playback exception: %s" % exc
                if on_bad_iframe == self.RAISE:
                    raise

            except DataError as exc:
                self.state	= self.FAILED, "Playback exception: %s" % exc
                if on_bad_data == self.RAISE:
                    raise

            except Exception as exc:
                self.state	= self.FAILED, "Playback failed: %s" % exc
                log.detail( "%s", traceback.format_exc() )

	# We're in a state >= AWAITING; either we have remaining unprocessed records in self.future
        # or in the history file and we'll evaluate True (caller should come back later for more
        # history), or we're COMPLETE/FAILED and we'll evaluate False (no more history to process).
        # Return the events processed, and the current advancing historical timestamp.
        return cur,events
