
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
__copyright__                   = "Copyright (c) 2015 Hard Consulting Corporation"
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"

__all__				= ["existence", "duration"]

import errno
import logging
import re
import time

from .. import misc

log				= logging.getLogger( __package__ )

class existence( object ):
    """Waits for zero or more numeric <timeout> and/or <filename> (existence) [and %<regex> (content)]
    and/or predicate truth events, yielding a sequence of True/False indicators as terms are
    processed.  Unless a floating-point numeric timeout is specified, the default timeout waits
    forever, sampling from time to time.

    Assuming args.wait is a list of 0 or more #[.#] numeric or 'filename[%regex]' terms, to process
    the condition terms 'til the first failure, and then raise an Exception:

        assert all( waits.existence()( *args.wait )), \
            "Failed waiting for <timeout> and/or <filename>[%<regex>]: %r" % ( args.wait )

    To process each term and log the details of which term failed (the default str() representation 
    of an waits.existence instance, is the last term waited for):
    
        waiter			= waits.existence( terms=args.wait )
        for success in waiter:
            assert success, \
                "Failed waiting for <timeout> and/or <filename>[%<regex>]: %s" % ( waiter )
            logging.info( "Successfully waited: %s", waiter )

    The 'presence' can be set False, if we want to wait for the removal of the file, or the cessation
    of matching the regular expression.

    The default timeout (None) is an infinite timeout.  This is also available by specifying '+inf'
    as a timeout.

    WARNING

    Files named after any legal floating-point value are unsupported.  Perhaps surprisingly, this
    includes files with names like: [+-]{inf,nan}, 0e0, ...  To avoid this, include a path
    (eg. './') before names which might possibly also be interpreted as numbers.

    """
    def __init__( self, terms=None, delay_min=0.1, delay_max=30.0, regex_sep='%', presence=True,
                  timeout=None, idle_service=None ):
        self.terms		= list( terms ) if terms else []

        self.delay_min		= delay_min
        self.delay_max		= delay_max
        self.regex_sep		= regex_sep
        self.presence		= presence
        self.idle_service	= idle_service

        self.timeout		= timeout	# None (default) ==> no timeout; wait forever
        self.started		= misc.timer()
        self.awaited		= False

        self.last		= None

    def __str__( self ):
        """Evaluates to the string representation of the last term evaluated, or "" if None"""
        return "" if self.last is None else str( self.last )

    def __call__( self, *args ):
        """Waits for all the the specified <timeout> and/or <filename>[%<regex>] terms.  Adds the supplied terms
        after any yet pending processing.  New terms can be added at any time, even during iteration.

        """
        self.terms.extend( args )
        return self

    def __iter__( self ):
        return self

    def __next__( self ):
        """Process the next term, yielding True if it completed successfully, False otherwise.  When all
        terms are complete, any terminal timeout is processed.  Otherwise, intervening timeouts are
        applied to subsequent filename[:regex] existence checks, which all must complete before the
        timeout expires.

        """
        if self.terms:
            self.last, self.terms= self.terms[0], self.terms[1:]

            # Each time we see a #[.#] timeout, reset the started time for subsequent files
            # waited for.  +inf ==> None (no timeout).
            try:
                self.timeout	= float( self.last )
                if misc.isinf( self.timeout ):
                    self.timeout= None
                else:
                    assert self.timeout >= 0, "waits timeout must be a +'ve value"
                self.started	= misc.timer()
                self.awaited	= False
                self.last	= "(timeout %s)" % ( "%.3fs" % self.timeout if self.timeout is not None else self.timeout )
                log.debug( "waits timeout: %s",
                                "%.3fs" % self.timeout if self.timeout is not None else self.timeout )
                return True
            except ( ValueError, TypeError ):	# Not a numeric timeout
                pass

            if hasattr(self.last, "__call__"):
                self.awaited	= True
                return self.truth( self.last )

            # Otherwise, wait 'til the file exists, and contains any regex (or timeout expires).
            self.awaited	= True
            return self.exists( *self.last.split( self.regex_sep, 1 ))

        # Done all terms.  Handle any terminal bare <timeout> (+'ve non-zero/None) with no
        # subsequent awaited filename.
        self.last		= None
        if self.timeout and not self.awaited: # Non-zero timeout, bare
            now			= misc.timer()
            remains		= self.started + self.timeout - now
            if remains > 0:
                log.debug( "waits terminal timeout: %.3fs", self.timeout )
                time.sleep( remains )
            else:
                log.debug( "waits terminal timeout: satisfied" )
        else:
            log.debug( "waits terminal" )
        raise StopIteration

    next			= __next__

    def delay( self, target=0, now=None ):
        """Return a delay appropriate for the remaining timeout.  We'll default to the suggested
        target, or 1/2 the remaining timeout (or the delay_max), whichever is less.  Assumes
        self.started is a valid time.  You might usually invoke this with double the last delay, to
        implement an exponential back-off:

            delay		= 0
            while not done:
                ...
                delay		= self.delay( target=2*delay )
                time.sleep( delay )

        With no timeout, the delay would increase exponentially to delay_max.  With a
        timeout, the delay would increase exponentially up to delay_max (if timeout is long), and
        then back down as we near the timeout.  This maximizes detection of the file existence or
        regular expression initially and at the end of the timeout, while minimizing the intervening
        (potentially expensive) regular expression searches over the file if the timeout is long.

        """
        timeouts		= [ self.delay_max, self.delay_min if target < self.delay_min else target ]
        if self.timeout is not None: # A finite timeout
            if now is None:
                now		= misc.timer()
            # target 1/2 of remaining timeout, but at most delay_min, and at least 0
            rem			= self.started + self.timeout - now
            timeouts.append( max( rem / 2, min( self.delay_min, rem ), 0 ))
        return min( timeouts )

    def truth( self, predicate ):
        """Waits for predicate to evaluate.  We'll keep doubling the delay (exponential backoff) 'til we
        get to 1/2 the timeout, when we'll begin using 1/2 the remaining timeout.

        The only valid states are that that the file doesn't exist, or that it exists and is
        readable.  Everything else (eg. exists but unreadable, some other I/O error) is
        indeterminate, and results in the existence detection continuing (until timeout).

        """
        delay			= 0
        found			= None
        while found != self.presence:
            found		= bool(predicate())
            if found != self.presence:
                now		= misc.timer()
                if self.timeout is not None: # A finite timeout
                    if now >= self.started + self.timeout:
                        log.info( "waits for truth: %r; timeout of %s exceeded" % (
                            predicate, None if self.timeout is None else "%.3fs" % self.timeout ))
                        return False
                if self.idle_service:
                    self.idle_service()
                delay		= self.delay( target=delay*2, now=now )
                log.info( "waits for truth for %7.3fs: %r", delay, predicate )
                time.sleep( delay )
        return True

    def exists( self, filename, regex=None ):
        """Wait for <filename> with an optional %<regex>.  We'll keep trying to search for the regex after
        we find the file exists, 'til we find a match or time out (use start/end anchors if exact
        matching is desired).  We'll keep doubling the delay (exponential backoff) 'til we get to
        1/2 the timeout, when we'll begin using 1/2 the remaining timeout.

        The only valid states are that that the file doesn't exist, or that it exists and is
        readable.  Everything else (eg. exists but unreadable, some other I/O error) is
        indeterminate, and results in the existence detection continuing (until timeout).

        """
        delay			= 0
        found			= None # Will achieve None (indeterminate)/True/False 'til acceptable
        pattern			= None
        opened			= None
        matched			= None
        while found != self.presence:
            opened		= None
            matched		= None
            try:
                with open( filename, 'r' ) as f:
                    # File exists and is readable.  Check any regex. 
                    found 	= opened = True
                    if regex:
                        if pattern is None:
                            pattern = re.compile( regex )
                        found	= matched = any( pattern.search( line ) for line in f )
            except IOError as error:
                if error.errno == errno.ENOENT:
                    found	= opened = False
                elif error.errno == errno.EISDIR and not regex:
                    # It's a directory (and no regex); consider it as existing
                    found	= opened = True
                else:
                    # eg. EACCES (Permission denied), etc. 
                    log.debug( "wait for filename:?%r, regex: %r; indeterminate file state: %s", 
                                    filename, regex, error )
            if found != self.presence:
                now		= misc.timer()
                if self.timeout is not None: # A finite timeout
                    if now >= self.started + self.timeout:
                        log.info( "wait for filename: %r, regex: %r; timeout of %s exceeded" % (
                            filename, regex,
                            None if self.timeout is None else "%.3fs" % self.timeout ))
                        return False
                if self.idle_service:
                    self.idle_service()
                delay		= self.delay( target=delay*2, now=now )
                log.info( "wait for filename:%s%r, regex:%s%r, for %.3fs of %s...", 
                    ( "?" if opened is None else ">" if opened else " " ), filename, 
                    ( ">" if matched else " " ), regex, 
                    delay, None if self.timeout is None else "%.3fs" % self.timeout )
                time.sleep( delay )

        log.info( "wait for filename:%s%r, regex:%s%r, in  %.3fs of %s; successful",
                       ( "?" if opened is None else ">" if opened else " " ), filename, 
                       ( ">" if matched else " " ), regex,
                       misc.timer() - self.started,
                       None if self.timeout is None else "%.3fs" % self.timeout )
        return True


def duration( events, what="predicate" ):
    """Yields a sequence (..., (<event>,<elapsed>), ...) for the provided sequence of events.  Iterators
    that have a .timeout attribute (None --> no timeout) will display that in the logging message.

    If you have a single predicate, timeout, and description, test and time it using something like:
    
        truth,timing = next( duration( existence( [ predicate ], timeout=timeout ), what=description ))

    """
    begun			= misc.timer()
    for truth in events:
        elapsed			= misc.timer() - begun
        timeout			= getattr( events, 'timeout', None )
        if timeout is None:
            timeout		= misc.inf
        logging.info( "After %7.3f/%7.3f %s %s", elapsed, timeout, "detected" if truth else "missed  ", what )
        yield truth,elapsed


def waitfor( predicate, what="predicate", timeout=None, intervals=None ):
    """Wait for the given predicate, returning: (success,elapsed).  If a specific number of intervals is
    desired, then doesn't use the automatic exponential back-off algorithm for testing intervals.

    """
    kwds		= dict( timeout=timeout )
    if timeout and intervals:
        kwds.update( delay_min=timeout/intervals, delay_max=timeout/intervals )
    return next( duration( existence( [ predicate ], **kwds ), what=what ))

