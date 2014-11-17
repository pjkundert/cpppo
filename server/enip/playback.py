
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

# 
# cpppo.server.enip.playback
# 
# 
# Record Tag(s) from a remote PLC, and provide playback at the specified timestamp and rate
# 

from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2013 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

import collections
import logging
import select
import sys
import threading
import traceback
import readline

from cpppo import history, dotdict
from cpppo.misc import mutexmethod
from cpppo.server.enip import device
from cpppo.server.enip.main import main, logrotate_request


class daemon( threading.Thread ):
    def __init__( self, **kwds ):
        super( daemon, self ).__init__( **kwds )
        self.daemon		= True
        self.halt		= False

    def stop( self ):
        self.halt		= True

    def join( self, timeout=None ):
        self.stop()
        super( daemon, self ).join( timeout=timeout )


class daemon_command( daemon ):
    """Read commands, adding each to a deque (accessed by other Threads).  Evaluates Truthy while
    running (not at EOF).  Indexing and len returns the underlying command deque.

    """
    command			= collections.deque()

    def run( self ):
        while not self.halt:
            try:
                prompt		= str( history.timestamp() ) + ": " if sys.stdin.isatty() else ""
                command		= ( raw_input if sys.version_info.major < 3 else input )( prompt )
                logging.info( "%s: command: %r", self.__class__.__name__, command )
                if command:
                    command	= command.strip()
                    if command.startswith( '#' ):
                        continue
                    self.__class__.command.append( command )
            except EOFError as exc:
                logging.warning( "%s terminated with EOF", self.__class__.__name__ )
                break
            except Exception as exc:
                logging.warning( "%s terminated unexpectedly: %s\n%s", self.__class__.__name__,
                                 exc, traceback.format_exc() )
                break

    def __len__( self ):
        return len( self.command )

    def __getitem__( self, key ):
        return self.command[key]

    def __nonzero__( self ):
        return self.is_alive()
    
    __bool__			= __nonzero__	# Python3


def attribute_path( basename, attribute ):
    if os.path.isdir( basename ):
        path		= os.path.join( basename, attribute.name )
    else:
        path		= basename + '_' + attribute.name
    path		       += '.hst'
    return path


class daemon_recorder( daemon ):
    """Poll a remote Controller's Tag data, and record it to a file.

    """
    def __init__( self, basename, attribute, record, **kwds ):
        self.attribute		= attribute
        self.record		= record # address of other Controller
        path			= attribute_path( basename, attribute )
        self.writer		= history.logger( path=path )

    def run( self ):
        pass


class daemon_playback( daemon ):
    """Implement historical playback for an Attribute.  Await next playback specification, and
    then perform the playback.  Will report self.finished after daemon_command sees EOF (and
    terminates), and last playback finished (self.reader evaluates False).

    """
    def __init__( self, basename, attribute, command, recorder=None, **kwds ):
        super( daemon_playback, self ).__init__( **kwds )
        self.attribute		= attribute
        self.command		= command # has __len__, __getitem__ and __nonzero__ (not done)
        self.commandnum		= 0
        self.reader		= None
        self.recorder		= recorder
        if not self.recorder:
            # Make up a fake recorder.writer with a path and a no-op buffering method
            self.recorder			= dotdict()
            self.recorder.writer		= {}
            self.recorder.writer.path		= attribute_path( basename, attribute )
            self.recorder.writer.buffering	= lambda *args: None

        self.lock		= threading.Lock()
        self.reset()

    def reset( self ):
        self.forces		= {}

    @property
    def finished( self ):
        return self.halt and not self # told to stop, playback is done and no more commands

    def __nonzero__( self ):
        """Evaluates Falsey if our playback reader is done, and there are no more commands"""
        return not self.reader and self.commandnum >= len( self.command ) and not self.command.is_alive()

    __bool__			= __nonzero__	# Python3

    def run( self ):
        try:
            while not self.finished:
                if len( self.command ) <= self.commandnum:
                    time.sleep( .1 )
                    continue
                command		= self.command[self.commandnum]
                self.commandnum+= 1

                self.reset()
                try:
                    self.playback( command )
                except Exception as exc:
                    logging.warning( "Invalid playback specification: %s; %s\n%s", command,
                                     exc, traceback.format_exc() )
                    continue
                while self.reader:
                    time.sleep( self.update( .1 ))
        except Exception as exc:
            logging.warning( "%s terminated with: %s; %s", self.__class__.__name__,
                             exc, traceback.format_exc() )
        finally: # EOF, probably
            self.halt		= True

    @mutexmethod( 'lock' )
    def __getitem__( self, key ):
        """Retrieves historical data.  Data received via __setitem__ overwrites historical data 'til
        more recent historical data is received.  The 'key' may be an integer or a slice; missing
        indices default to 0.

        """
        if isinstance( key, slice ):
            indices		= range( *key.indices( len( self.attribute )))
        else:
            indices		= [ key ]
        return [ self.forces[r] if r in self.forces
                 else self.reader.values[r] if r in self.reader.values
                 else 0
                 for r in indices ]

    @mutexmethod( 'lock' )
    def __setitem__( self, key, value ):
        """Saves forced data; temporarily overrides historical data 'til fresh historical value arrives."""
        if isinstance( key, slice ):
            indices		= range( *key.indices( len( self.attribute )))
        else:
            indices		= [ key ]
        for r,v in zip( indices, value ):
            self.forces[r]	= v

    @mutexmethod( 'lock' )
    def update( self, latency=0 ):
        """Loads any pending events (updating self.reader.values with up-to-date historical data), and
        updates self.forces overwritten by fresh historical data.  Return the number of seconds 'til
        the next pending event ('latency' if unknown).

        """
        delay			= None
        events			= True
        cnt			= 0
        while events:
            cur,events		= self.reader.load( limit=1000 )
            for e in events:
                for r,v in e['values']:
                    if r in self.forces:
                        logging.detail( "Release force %7r on index %3d", self.forces[r], r )
                        del self.forces[r]
                    logging.info( "Updated value %7r on index %3d", v, r )
            cnt	       	       += len( events )
            logging.info( "Loaded %5d events; %5d total", len( events ), cnt )

        if self.reader.future:
            ts			= self.reader.future[0][0]
            now			= misc.timer()
            if ts > now:
                delay		= ts - now
        logging.debug( "Next future event in %7r (%d pending)", delay, len( self.reader.future ))

        return latency if delay is None else delay


    REALTIME			= 'realtime'
    @mutexmethod( 'lock' )
    def playback( self, mode=None ):
        """Attempts to switch to the designated playback mode, returning a canonical string describing
        the mode if successful.  Raise Exception on failure.

        If a timezone is specified, it is used, and the response mode string will be denominated in
        the same timezone, converted to the local, unambiguous DST-specific abbreviation, eg:
        'America/Edmonton' --> 'MST'/'MDT' as appropriate.  If a time is supplied with an
        ambiguous/impossible interpretation (eg. using 'America/Edmonton' during the "missing" hour
        in the spring, or during the "overlapping" hour in the fall), an exception will be raised.

        None, False, '', 'realtime':

            Revert to 'realtime' playback mode..

        YYYY-MM-DD HH:MM:SS [TZ]

            Start historical playback starting with the specified time (optionally with timezone;
            default: UTC).

        </> [[[h]:m:]s[.ss]
	
            Adjust a running historical playback by the specified forward/reverse time.  If no
            playback is running, then adjust the historical playback time provided by the given
            offset.  If not historical time provided, use basis (and offset must be -'ve).

        +   [[[h]:m:]s[.ss]

            Set a historical playback duration, in hours/minutes/seconds of historical time.

        @ YYYY-MM-DD HH:MM:SS [TZ]

            Synchronize playback relative to the specified @ <basis> time (optionally with timezone;
            default: UTC).  Default is "now", if not specified.  May have a different timezone than
            the historical playback time; the response mode string will be denominated in the same
            timezone.

        x #.#

            With a time scale factor x <factor>.   Default is factor 1.0.

        , TZ

            The default timezone to use for interpreting any times that don't specify specific
            timezones.  The resultant mode string will be denominated in this timezone.

        When changing the history mode, we need to change the running history.logger's output
        buffering to line-buffered, so that (if we read the same log file) we don't miss records.

        """
        if not mode:
            mode		= ''
        assert isinstance( mode, cpppo.type_str_base ), "Invalid playback mode: %r; must be str/unicode" % mode

        historical		= None
        historical_tz		= None
        duration		= None
        factor			= None
        basis			= None
        basis_tz		= None
        offset			= None
        timezone		= None
        # ['realtime'|''|<date> <time>] [</> <time>] [+ <time>] [@ <date> <time>] [x <factor>] [, <timezone].
        # Parses out playback components available, strips remains and assigns as a historical start
        # time.  If all remain None, or if they indicate a start time >= now, then revert to
        # 'realtime' playback.  Retain the preferred historical/basis timezones, so we can re-render
        # them.  We may (often will) receive 'realtime, TZ' or simply ', TZ', indicating current
        # wall-clock realtime playback, but with a timezone designation appended by the client.
        # This is fine; the default historical and basis time must be different, and yield a
        # computed historical + offset time in the past, or we will flip into "realtime" mode.
        # 
        # Typically, to synchronize playback, you'll specify some 'basis' time near the current
        # time, and some historical time earlier than that, perhaps with a multiplier.  This means
        # to begin playing back starting from the historical time, beginning at the basis time.  So
        # long as the historical time is less than the provided basis time, there is a possibility
        # that there may be history to play back (otherwise, you're saying to play back data,
        # starting relative to the basis time).  Thus, long as historical + offset < basis, we
        # should try to start a historical loader.  And thus, if we don't have a valid history time
        # specified (eg. '', or 'realtime'), it will default to basis, and unless we have specified
        # a -'ve offset (eg. <10:00), the < basis check will fail, and we'll revert to 'realtime'
        # playback.
        # 
        #  time ...-|-------------------|----|--------...
        #           ^                   ^    ^
        #           historical          now  basis
        # 
        try:
            remains		= mode
            symbols		= '+x@<>,'
            while remains:
                # Keep finding the rightmost symbol; if duplicates (eg. '... x 20 ... x 10'), the
                # leftmost instance will win.
                i		= max( map( remains.rfind, symbols ))
                if i < 0:
                    break
                if remains[i] == 'x':
                    factor	= remains[i+1:].strip() or None
                elif remains[i] == '@':
                    basis	= remains[i+1:].strip() or None
                elif remains[i] in ('<','>'):
                    offset	= remains[i:].strip() or None # Offset </>hhh:mm:ss.sss; must include the </> sign
                elif remains[i] == '+':
                    duration	= remains[i:].strip() or None # Duration +hhh:mm:ss.sss; must include the + sign
                elif remains[i] == ',':
                    timezone	= remains[i+1:].strip() or None
                remains		= remains[:i].strip()
            historical		= remains or None	# Whatever is left over must be the historical start time
            if historical == self.REALTIME:
                historical	= None

            if timezone:
                historical_tz	= timezone
                basis_tz	= timezone
                logging.normal( "playback timezone , %s", timezone )
            if historical:
                dt		= history.timestamp.datetime_from_string( historical, timezone )
                historical	= history.timestamp( dt )
                historical_tz	= timezone or dt.tzinfo
                logging.normal( "playback starts   : %s", historical )
            if offset:
                offset		= history.parse_offset( offset )
                logging.normal( "playback offset   %s", history.format_offset( offset, ms=False ))
            if duration:
                duration	= history.parse_offset( duration, symbols='-+' )
                logging.normal( "playback duration %s", history.format_offset( duration, ms=False, symbols='-+' ))
            if basis:
                dt		= history.timestamp.datetime_from_string( basis, timezone )
                basis		= history.timestamp( dt )
                basis_tz	= timezone or dt.tzinfo
                logging.normal( "playback basis    @ %s", basis )
            if factor:
                factor		= float( factor )
                logging.normal( "playback factor   x %s", factor )
        except Exception as exc:
            logging.warning( "Invalid playback mode %s: %s", mode, exc )
            raise

        # Check for acceptable adjustments to a currently running playback, and if matching, capture
        # any un-configured parameters.  Later, if these all match, the current self.reader will be
        # retained.
        if ( self.reader is not None
             and ( historical is None or historical == self.reader.historical )
             and ( basis is None or basis == self.reader.basis )
             and ( factor is None or defaults.near( factor, self.reader.factor ))):
            # Rewind/Fast-Forward the existing playback.
            if offset and offset > 0:
                # Fast-forwarding the present playback; adjust its historical time backwards,
                # causing it to rush ahead to catch up.  See:
                # 
                #     reader.advance = <historical> + ( <now> - <basis> ) * <factor>
                # 
                # We want advance to return a greater value next time it's called, so we have to
                # either decrease <basis> (multiplies <offset> by <factor>) or increase
                # <historical> (applies <offset> linearly).  We want to fast-forward by
                # <offset>'s worth of the *underlying* historical data's time, not wall-clock
                # time -- so adjust <historical> forward to move reader.advance forward linearly
                # in <historical> time.
                logging.warning( "Fast-forward retaining the existing playback by %s",
                                  history.format_offset( offset, ms=False ))
                basis		= history.timestamp( self.reader.basis )
                historical	= history.timestamp( self.reader.historical )
                factor		= self.reader.factor
                self.reader.historical += offset
            elif offset and offset < 0:
                # Rewind; requires us to create a new reader.  But, uses the existing one's
                # basis and factor, so it'll appear like a rewind.
                logging.warning( "Rewind using parameters of existing playback by %s",
                                  history.format_offset( offset, ms=False ))
                basis		= history.timestamp( self.reader.basis )
                historical	= history.timestamp( self.reader.historical )
                factor		= self.reader.factor

        # If we have an existing loader, if all specs (including offset) are consistent, keep it.
        if ( self.reader is not None
             and historical is not None and historical + ( offset or 0 ) == self.reader.historical
             and basis is not None and basis == self.reader.basis
             and ( factor is None or defaults.near( factor, self.reader.factor ))):
            # All consistent; the duration can safely updated.  
            factor		= self.reader.factor
            self.reader.duration= duration
            logging.warning( "Current playback is consistent; continuing" )
        else:
            # Default any parameters to 'now'.  This is where realtime (all parameters None), or
            # playback time in the future will be detected, and trigger reversion to realtime.
            now			= history.timestamp()
            if basis is None:
                basis		= history.timestamp( now )
            if historical is None:
                historical	= history.timestamp( basis )

            # Either a historical time in the past, or a -'ve offset are required for playback.
            if historical + ( offset or 0 ) >= now:
                self.reader	= None
                self.since	= None
                self.recorder.writer.buffering( history.logger.DFLT_BUF )
            else:
                # Historical playback available, target time is in the past.  Do it!  Provide a set
                # of default values that will fully overwrite all currently known and reported field
                # values.  If we don't do this, then the client will *not* get an initial update
                # containing all currently known field values, if either A) the historical playback
                # time has not yet reached the timestamp of the oldest available history file, or B)
                # if the history file doesn't contain initial values for all *currently* known
                # registers; ie. someone added new registers since the history file was created.
                assert self.writer.path, "History disabled; invalid history path: %r" % self.writer.path
                self.reader	= history.loader( self.recorder.writer.path, lookahead=self.lookahead,
                            historical=historical + ( offset or 0 ), basis=basis, factor=factor,
                            duration=duration, values={ r: 0 for r in self._field_values } )
                self.since	= None
                self.recorder.writer.buffering( history.logger.LINE_BUF )

        # Finally, return a description of the historical loader (if any) created / left in place.
        if self.reader is None:
            description		= self.REALTIME
        else:
            historical	       += offset or 0
            desclist		= [ historical.render( tzinfo=historical_tz, ms=None ) ]
            if duration is not None:
                desclist       += [ history.format_offset( duration, ms=False, symbols='-+' ) ]
            if factor and not defaults.near( factor, 1 ):
                desclist       += [ 'x%g' % factor ]
            desclist	       += [ '@' + basis.render( tzinfo=basis_tz, ms=None ) ]
            description		= ' '.join( desclist )

        logging.normal( "Entering playback: %s", description )
        return description


if __name__ == "__main__":

    # 
    # Extract record/playback-specific options; remaining options processed by main.
    # 
    #     <filename>
    #     --record <addr>   address:port of the EtherNet/IP PLC to poll and record to filename
    #     --playback <spec> A playback specification, eg: "2014-10-24 16:00:00 MST < 1:00 x 3"
    # 
    # All Tags created (in remaining args) will be polled and recorded in filename (if --record <addr>
    # specifed).  Regardless, Tag values will be read from filename at the specified playback rate (read
    # from stdin)
    # 
    _filename			= None
    _record			= None
    while (( not _filename and len( sys.argv ) > 1 )
           or ( not _record and len( sys.argv ) > 2 and sys.argv[1] == '--record' )):
        if sys.argv[1] == '--record':
            sys.argv.pop( 1 )
            _record		= sys.argv.pop( 1 )
        else:
            _filename		= sys.argv.pop( 1 )

    _command			= daemon_command()
    _command.start()


    # 
    # Attribute_playback -- intercept all EtherNet/IP Attribute I/O, and playback from file
    # 
    #     Captures the (just parsed) _filename, _record and (just started) daemon_command.
    # 
    class Attribute_playback( device.Attribute ):
        """Fire up a daemon_playback to handle retrieving historical data from the appropriate file,
        eg. <basename>/<Attribute>.hst or <basename>_<Attribute>.hst.  During playback
        (self.player.reader is Truthy), respond to requests from the self.player.
    
        Also fire up a daemon_recorder to poll Tag data from another Controller and use a history.logger
        to save it to the same file, and to the underlying Attribute storage.  When not in playback
        (self.player.reader is Falsey) pass them thru to the underlying Attribute storage (ie. realtime
        data).
    
        Since the daemon_recorder will be retrieving data and inserting it into this Attribute
        asynchronously, we'll need to arrange to protect the underlying data store via a mutex.

        """
        _attributes		= []
    
        def __init__( self, *args, **kwds ):
            super( Attribute_playback, self ).__init__( *args, **kwds )
            self.lock		= threading.Lock()
            self.recorder	= None
            if _record:
                self.recorder	= daemon_recorder(
                    basename=_filename, attribute=self, record=_record )
                self.recorder.start()
            self.player		= daemon_playback(
                basename=_filename, attribute=self, command=_command, recorder=self.recorder )
            self.player.start()
            self.__class__._attributes.append( self )

        def __enter__( self ):
            self.lock.acquire()
            return self
    
        def __exit__( self, typ, val, tbk ):
            self.lock.release()
            return False # suppress no exceptions
    
        def __getitem__( self, key ):
            if self.player:
                value		= self.player[key]
            else:
                with self:
                    value	= super( Attribute_playback, self ).__getitem__( key )
            return value
    
        def __setitem__( self, key, value ):
            if self.player:
                self.player[key]= value
            else:
                with self:
                    super( Attribute_playback, self ).__setitem__( key, value )


    # Finally, run the main loop creating all the Attribute_playback instances; when all their
    # .player (daemon_player instances) and the daemon_command instance report Falsey, it's time to
    # quit.

    def eof_at_prompt():
        """EOF at prompt, and no commands left, and loader absent/complete; done!"""
        if not _command and not any( a.player for a in Attribute_playback._attributes ):
            raise Exception( "EOF" )

    sys.exit( main( attribute_class=Attribute_playback, idle_service=eof_at_prompt ))
