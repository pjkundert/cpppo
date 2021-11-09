#!/usr/bin/env python3

# -*- coding: utf-8 -*-
#
# Cpppo -- Communication Protocol Python Parser and Originator
#
# Copyright (c) 2021, Dominion Research & Development Corp.
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

"""
    Implements the Cpppo Licensing Server
"""

from __future__ import print_function, absolute_import, division

__author__                      = "Perry Kundert"
__email__                       = "perry@hardconsulting.com"
__copyright__                   = "Copyright (c) 2021 Dominion Research & Development Corp."
__license__                     = "Dual License: GPLv3 (or later) and Commercial (see LICENSE)"


import argparse
import collections
import copy
import curses, curses.ascii, curses.panel
import datetime
import dateutil.tz
import glob
import json
import logging
import math
import os
import random
import re
import signal
import socket
import sqlite3
import sys
import textwrap
import threading
import time
import timeit
import traceback
import uuid

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen


# Used for Web GUI, and for licensing database
import web
import web.httpserver
import wsgilog

web.config.debug 		= False
web.config.session_parameters.update( {
    'cookie_name':	'session',
    'ignore_expiry':	True,
    'ignore_change_ip':	True,
    'timeout':		7*24*60*60,	# 1 week
} )

session_initializer		= {
    'user_id':	0,
    'name':	'',
    'pin':	0,
    'login':	0,			# 0 guest, 1 user, 2 admin
}



from ...history.times	import timestamp, duration
from ...misc		import timer
from ...automata	import log_cfg
from ...server.enip.defaults import config_open, ConfigNotFoundError
from .verification	import LicenseSigned

log				= logging.getLogger( "licensing" )

# Output files are stored in the CWD
LOGFILE				= "licensing.log"
DB_FILE				= "licensing.db"
ACCFILE				= "licensing.access"

# SQL configurations are typically found in cpppo/crypto/licensing/, but may be customized and
# placed in any of the Cpppo configuration file paths (eg. ~/.cpppo/, /etc/cpppo/, or the current
# working directory)
SQLFILE				= "licensing.sql" # this + .* are loaded

OURPATH				= os.path.dirname( os.path.abspath( __file__ ))
TPLPATH				= os.path.join( OURPATH, "static/resources/templates/" )


# The database: global 'db', which is a web.database connection.  Since sqlite3 is thread-safe, but
# will raise an exception if multiple threads attempt to write, provide a threading.Lock() to allow
# serializing of all db insert, update, etc. between threads.

# We will *always* execute all of the available ...sql* scripts.  These contain 'CREATE TABLE' and
# 'INSERT' commands, which will fail if the specified table/row already exists, so are safe to run
# repeatedly.  When we add tables and/or rows that don't already exist, they'll be created by these
# scripts.  This provides us with a rudimentary database update mechanism between releases, as long
# as we carefully migrate data from old to new tables.

init_db				= None
db_file_path			= DB_FILE
sqlfile_path			= SQLFILE
try:
    # Load all licensing.sql* config files into the licensing.db Sqlite3 file.  If it can be found
    # somewhere in the configuration path, use it -- otherwise, assume its here in the CWD.
    try:
        with config_open( DB_FILE ) as f:
            db_file_path	= f.name
    except ConfigNotFoundError:
        pass
    init_db			= sqlite3.connect( db_file_path )
    with config_open( SQLFILE, extra=[OURPATH] ) as f:
        sqlfile_path		= f.name
    for sql in sorted( glob.glob( sqlfile_path + '*' )):
        if sql.endswith( '~' ):
            continue
        try:
            with open( sql ) as f:
                init_db.executescript( f.read() )
        except (sqlite3.OperationalError,sqlite3.IntegrityError) as exc:
            logging.warning( "Failed to load %s (continuing): %s", f.name, exc )
except Exception as exc:
    logging.warning( "Failed to execute {}* scripts into DB {}: {}".format(
        sqlfile_path, db_file_path, exc ))
    raise
finally:
    if init_db:
        init_db.close()
assert os.access( db_file_path, os.W_OK ), \
    "Cannot access licensing DB: {}".format( db_file_path )

# OK, the DB has been initialized, and is at db_file_path
db				= web.database( dbn='sqlite', db=db_file_path )
assert hasattr( db, 'query' ), \
    "Unrecognized licensing DB connection: {!r}" % ( db )
db_lock				= threading.Lock()


# Various static values that should be saved/restored.  Always begins at defaults on start-up!
# But, also read from database.  All floating point.
db_statics		= {}
for r in db.select( 'statics' ):
    db_statics[r.key]	= float( r.value )

    
def state_save():
    """Dump out any persistent licensing data, etc. that should be loaded next time.  This should be done
    from time to time, so we don't get too far behind, in case of a cold reboot.  Of course, save 
    immediately upon license creation, etc.

    Make certain that all sqlite3 database calls are run in a single Thread.  We'll do the loading
    right below (here, in the Main Thread), but all other database I/O (including state_save()) must
    occur in the webpy Thread...

    From https://github.com/sampsyo/beets
    """
    with db_lock:
        logging.info( "Saving state (thread: %s)", threading.current_thread().ident )

        for k in db_statics:
            if not db.update( 'statics', where="key = $key", vars={ "key": k }, value=db_statics[k] ):
                if not db.insert( 'statics', key=k, value=db_statics[k] ):
                    logging.warning( "Failed to store statics key %s value %s" % ( k, db_statics[k] ))


# Set up signal handling (log rotation, log level, etc.)
# Output logging to a file, and handle UNIX-y log file rotation via 'logrotate', which sends
# signals to indicate that a service's log file has been moved/renamed and it should re-open

uptime_basis			= timer()
uptime_signalled		= False
shutdown_signalled		= False
logrotate_signalled		= False
levelmap_change			= 0 # may become +'ve/-'ve

logging_levelmap		= {
    0: logging.WARNING,
    1: logging.NORMAL,
    2: logging.DETAIL,
    3: logging.INFO,
    4: logging.DEBUG,
}

def uptime_request( signum, frame ):
    global uptime_signalled
    uptime_signalled		= True

def shutdown_request( signum, frame ):
    global shutdown_signalled
    shutdown_signalled		= True

def logrotate_request( signum, frame ):
    global logrotate_signalled
    logrotate_signalled		= True

def loglevelup_request( signum, frame ):
    global levelmap_change
    levelmap_change	       += 1

def logleveldn_request( signum, frame ):
    global levelmap_change
    levelmap_change	       -= 1

def signal_service():
    """Service known signals.  When logging, default to logat NORMAL, but ensure the
    message is seen if higher (eg. WARNING).  Support being in unknown logging
    levels when in/decreasing.

    """
    global levelmap_change
    if levelmap_change:
        rootlog			= logging.getLogger()
        actual			= rootlog.getEffectiveLevel()
        closest			= min( logging_levelmap.values(), key=lambda x:abs(x-actual) )
        highest			= max( logging_levelmap.keys() )
        for i,lvl in logging_levelmap.items():
            if lvl == closest:
                key		= i + levelmap_change
                break
        desired			= logging_levelmap.get( key, logging.DEBUG if key > highest else logging.ERROR )
        if actual != desired:
            rootlog.setLevel( desired )
        levelmap_change		= 0

    global logrotate_signalled
    global uptime_signalled
    if logrotate_signalled:
        logrotate_signalled	= False
        uptime_signalled	= True

        rootlog			= logging.getLogger()
        actual			= rootlog.getEffectiveLevel()
        rootlog.log( max( logging.WARNING, actual ), "Rotating log files due to signal" )
        for hdlr in logging.root.handlers:
            if isinstance( hdlr, logging.FileHandler ):
                hdlr.close()

    global uptime_basis
    if uptime_signalled:
        uptime_signalled	= False
        uptime			= timer() - uptime_basis

        rootlog			= logging.getLogger()
        actual			= rootlog.getEffectiveLevel()
        rootlog.log( max( logging.WARNING, actual ), "Uptime: %3d:%02d:%06.3f",
                     int( uptime // 3600 ), int( uptime % 3600 // 60 ), uptime % 60 )


signal.signal( signal.SIGHUP,  logrotate_request )
signal.signal( signal.SIGUSR1, loglevelup_request )
signal.signal( signal.SIGUSR2, logleveldn_request )
signal.signal( signal.SIGTERM, shutdown_request )
signal.signal( signal.SIGURG,  uptime_request )


now				= timer()

def daytime( ts ):
    return timestamp( ts )

#
# Curses-based Textual UI.
#

def message( window, text, row = 23, col = 0, clear = True ):
    rows,cols			= window.getmaxyx()
    if col < -len( text ) or row < 0 or row >= rows or col >= cols:
        return
    if col < 0:
        text			= text[-col:]
        col			= 0
    try:
        window.addstr( int( row ), int( col ), text[:cols-col] )
        if clear:
            window.clrtoeol()
    except:
        pass


#
# pan{siz,loc} -- compute appropriate size and location for sensor detail panel
#
def pansiz( rows, cols ):
    return rows * 9 // 10, cols // 3


def panloc( c, rows, cols ):
    return rows//15, ( c < cols//2 ) and ( cols//2 + cols//10 ) or ( 0 + cols//10 )


def txt( win, cnf ):

    global now
    last			= now
    selected			= 0

    rows, cols			= 0, 0

    logging.info("threads: %2d: %s" % (
            threading.active_count(),
            ', '.join( [ t.name for t in threading.enumerate() ] )))



    display			= 'licenses'		# Start off displaying Licenses
    input			= 0
    delta			= 0.0
    pansel			= None
    while not cnf['stop']:
        message( win, "%s (%7.3f): (%3d == '%c') Quit [qy/n]?"
                 % (  daytime( now ), delta,
                      input, curses.ascii.isprint( input ) and chr( input ) or '?'),
                 row = 0, clear = False )


        curses.panel.update_panels()
        curses.doupdate()

        # End of display loop; display updated; Beginning of next loop; await input
        input			= win.getch()

        # Refresh the things to include in the selected display.
        include			= cnf[display]
        if hasattr( include, '__call__' ):
            include		= list( include() )

        # Compute time advance since last thermodynamic update
        real			= timer()
        delta			= real - last

        # Detect window size changes, and adjust detail panel accordingly (creating if necessary)
        if (rows, cols) != win.getmaxyx():
            rows, cols		= win.getmaxyx()
            winsel		= curses.newwin( * pansiz( rows, cols ) + panloc( 0, rows, cols ))
            try:
                pansel.replace( winsel )
            except:
                pansel		= curses.panel.new_panel( winsel )


        # Process input, adjusting parameters
        if 0 < input <= 255 and chr( input ) == 'q':
            cnf['stop'] = True
            return

        if 0 < input <= 255 and chr( input ) == '\f': # FF, ^L
            # ^L -- clear screen
            winsel.clear()

        # Select next space, adjust target temp
        if input == curses.ascii.SP:				# ' '
            if pansel.hidden():
                pansel.show()
            else:
                pansel.hide()

        if input in ( curses.ascii.STX, curses.KEY_LEFT, 260 ):	# ^b, <--
            selected		= ( selected - 1 ) % len( include )
        if input in ( curses.ascii.ACK, curses.KEY_RIGHT, 261 ):# ^f, -->
            selected		= ( selected + 1 ) % len( include )
        if input in ( curses.ascii.DLE, curses.KEY_UP, 259 ):	# ^p, ^
            if include[selected] == 'world':			#     |
                # do something to world...
                pass
            else:
                curses.beep()
        if input in ( curses.ascii.SO, curses.KEY_DOWN, 258 ):	#     |
            if include[selected] == 'world':			# ^n, v
                pass
            else:
                curses.beep()

        if 0 < input <= 255 and chr( input ) in ( 'C', 'c', 'M', 'm' ):
            # Character keypresses
            pass

        # When a keypress is detected, always loop back and get another key, to absorb multiple
        # keypresses (eg. due to key repeat), but only do it if less then 1/3 second has passed.
        if 0 < input and delta < .3:
            continue

        # We'll be computing a new model; advance (and remember) time
        last			= real
        now                     = real


        # Next frame of animation
        win.erase()

        topmargin               = 2
        #botmargin		= 9
        #botrow			= rows - botmargin

        # Compute screen size and display headers.  We want cells a bit higher than wide, and at
        # least 20 characters wide.  Keep piling 'til we are either over 20 characters wide, or less
        # than 5/4ths as high as wide.  If we can't find a way to get cells >= 10 rows high, fail
        # and loop 'til they fix the display size.
        try:
            areas		= len( include )
            pile		= 1
            rank		= areas // pile
            height		= rows - topmargin
            width		= cols // ( rank + 1 )
            while height > 20 or width < 20 or ( height >= 5 * width / 4 ):
                pile           += 1
                rank		= ( areas + pile - 1 ) // pile	# ensure integer div rounds up
                height		= ( rows - topmargin ) // pile
                width		= cols // ( rank + 1 )
            assert height >= 10 and width >= 20
        except:
            message( win, "Insufficient screen size (%d areas, %d ranks of %dx%d); increase height/width, or reduce font size" % (
                areas, pile, width, height ),
                     col = 0, row = 0 )
            time.sleep( 2 )
            continue

        # Make h- and v-bars, everwhere except top margin
        for r in range( topmargin, rows ):
            if ( rows - r ) % height == 0:
                win.hline( r, 0, curses.ACS_HLINE, cols )
        for c in range( width, cols, width):
            win.vline( topmargin, c, curses.ACS_VLINE, rows - topmargin )


        # Update
        winsel.erase()
        wsrows, wscols		= winsel.getmaxyx()

        r			= 2
        try:   winsel.hline( r, 1, curses.ACS_HLINE, wscols - 2 )
        except: pass
        r                      += 1

        try:    winsel.hline( r, 1, curses.ACS_HLINE, wscols - 2 )
        except: pass
        r                      += 1

        winsel.border( 0 )

    # Final refresh (in case of error message)
    win.refresh()


def deduce_encoding( available, environ, accept=None ):
    """Deduce acceptable encoding from HTTP Accept: header:

        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

    If it remains None (or the supplied one is unrecognized), the
    caller should fail to produce the desired content, and return an
    HTML status code 406 Not Acceptable.

    If no Accept: encoding is supplied in the environ, the default
    (first) encoding in order is used.

    We don't test a supplied 'accept' encoding against the HTTP_ACCEPT
    settings, because certain URLs have a fixed encoding.  For
    example, /some/url/blah.json always wants to return
    "application/json", regardless of whether the browser's Accept:
    header indicates it is acceptable.  We *do* however test the
    supplied 'accept' encoding against the 'available' encodings,
    because these are the only ones known to the caller.

    Otherwise, return the first acceptable encoding in 'available'.

    """
    if accept:
        # A desired encoding; make sure it is available
        accept		= accept.lower()
        if accept not in available:
            accept	= None
        return accept

    # No predefined accept encoding; deduce preferred available one.
    # Accept: may contain */*, */json, etc.  If multiple matches,
    # select the one with the highest Accept: quality value (our
    # present None starts with a quality metric of 0.0).  Test
    # available: ["application/json", "text/html"], vs. HTTP_ACCEPT
    # "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    # Since earlier matches are the for more preferred encodings,
    # later matches must *exceed* the quality metric of the earlier.
    HTTP_ACCEPT		= environ.get( "HTTP_ACCEPT", "*/*" ).lower() if environ else "*/*"
    quality		= 0.0
    for stanza in HTTP_ACCEPT.split( ',' ):
        # application/xml;q=0.9
        q		= 1.0
        for encoding in reversed( stanza.split( ';' )):
            if encoding.startswith( "q=" ):
                q	= float( encoding[2:] )
        for avail in available:
            match	= True
            for a, t in zip( avail.split( '/' ), encoding.split( '/' )):
                if a != t and t != '*':
                    match = False
            if match:
                if q > quality:
                    quality	= q
                    accept	= avail
    return accept


def http_exception( framework, status, message ):
    """Return an exception appropriate for the given web framework,
    encoding the HTTP status code and message provided.
    """
    if framework and framework.__name__ == "web":
        if status == 404:
            return framework.NotFound( message )

        if status == 406:
            return framework.NotAcceptable() # Will not accept a message

    return Exception( "%d %s" % ( status, message ))


def issue_request( render, path, environ, accept, framework,
                    queries=None, posted=None, logged=None, proxy=None ):
    """Returns a License issuance response, as HTML or JSON.

        api/issue		-- all licenses

    When an application running on a host finds that it does not have an appropriate signed License
    available, it may request one from a cpppo.crypto.licensing server.  If such a License is
    available to issue, it will be returned.

    If the License specifies a certain Client Public key, then the request must be signed by the
    corresponding Ed25519 Signing key.

    Only if sufficient License(s) are available in the server will they be issued.

    """
    # When using jQuery $.ajax() w/dataType: 'jsonp', it appends a
    # ?callback=... query, and sends an Accept: ... text/javascript
    # header.  Hence, accept either form.
    content			= deduce_encoding( [ "text/html",
                                                     "application/json", "text/javascript",
                                                     "text/plain" ],
                                                   environ=environ, accept=accept )
    response			= ""

    variables			= queries or posted or {}

    data			= {}
    data["title"]		= path or "Issue"
    data["path"]		= path
    data["list"]		= []
    data["keys"]		= ["description", "family", "id", "value"]
    data["editable"]		= ["value"]

    if content and content in ( "application/json", "text/javascript", "text/plain" ):
        callback		= variables.get( 'callback', "" )
        if callback:
            response           += callback + "( "
        response               += json.dumps( data, indent=4 )
        if callback:
            response           += " )"
    elif content and content in ( "text/html" ):
        response		= render.keylist( data )
    else:
        raise http_exception( framework, 406, "Unable to produce %s content" % (
                content or accept or "unknown" ))

    return content, response





def inline( filename ):
    """A web.py templetor global function to inline files, relative to the
    directory of this python file.  Use:

    $:inline( "some/javascript/file.js" )

    """
    with open( os.path.join( OURPATH, filename ), 'r' ) as f:
        return f.read()


def webpy( config ):
    """web.py interface.  Deduces accept encoding from Accept: header, or force
    JSON Content-Type: if .json path was explicitly requested.

    """
    config.setdefault( 'address',("0.0.0.0", 8000) )

    session			= None		# Will become a web.session.Session

    def logged( admin=False ):
        """Checked that the session's user is logged in.  Even if a user authenticates, their account
        may be disabled.

        """
        return session and session.login >= ( 2 if admin else 1 )

    def proxy( env ):
        """Detects if we are behind a proxy, and creates correct path if
        necessary, to use the original forwarded host.

        """
        proxy			= env.get( "HTTP_X_FORWARDED_HOST", "" )
        if proxy:
            proxy		= "http://" + proxy
        return proxy

    urls			= (
        "/",				"index",
        "/index(\.html)?",		"index",
        "/(.*)/",			"trailing_stuff",
        "/(.*)\.html",			"trailing_stuff",
        "/favicon.ico",			"favicon",
        "/robots.txt",			"robots",
        "/login",			"login",
        "/logout",			"logout",
        "/api/issue(\.json)?",		"issue",                 # path: "", ".json"
        "/api/issue/(.+)?",		"issue",                 # path: "...", "....json"
    )

    class trailing_stuff:
        def GET( self, path ):
            web.seeother( proxy( web.ctx.environ ) + '/' + path )

    class favicon:
        def GET( self ):
            """Always permanently redirect favicon.ico requests to our favicon.png.
            The reason we do this instead of putting a <link "icon"...> is because
            all *other* requests from browsers (ie. api/... ) returning non-HTML
            response Content-Types such as application/json *also* request
            favicon.ico, and we don't have an HTML <head> to specify any icon link.
            Furthermore, they continue to request it 'til satisfied, so we do a 301
            Permanent Redirect to satisfy the browser and prevent future requests.
            So, this is the most general way to handle the favicon.ico"""
            web.redirect( '/static/images/favicon.ico' )

    class robots:
        def GET( self ):
            web.header( "Content-Type", "text/plain" )
            return """\
User-agent: *
Disallow: /
"""

    class index:
        def GET( self, path=None ):
            render		= web.template.render(
                TPLPATH, base="layout", globals={'inline': inline, 'session': session} )
            response		= render.index( {
                "title": 	"Licensing",
                "text":		"Hello, world!",
            } )
            web.header( "Content-Type", "text/html" )
            return response

    class logout:
        def GET( self ):
            session.login	= 0
            web.seeother( proxy( web.ctx.environ ) + '/login' )

    def user_heritage( user_id ):
        """
        Return a dict containing the heirarchy of user names created by the specified user.
        """
        result			= {}

        spawn			= db.select( 'users', where='creator = $user_id', vars={ "user_id": user_id })
        for child in spawn:
            if child.user_id == user_id:
                continue

            key			= (child.name, child.user_id)
            result[key]		= user_heritage( child.user_id )

        return result

    def user_heritage_print( h, level=0 ):
        if not h:
            return
        for key in h:
            name,user_id	= key
            logging.info("%s %s" % ( ' '*level, name ))
            if h[key]:
                user_heritage_print( h[key], level+1 )

    class login:
        """
        Takes an optional ?redirect=url and passes it via the POST.
        """
        def GET( self ):
            """Allow login; if session.login already true, then display PIN change dialog."""
            logging.info( "Session: %r" % ( session.items() ))
            children		= None
            if logged():
                children	= user_heritage( session.user_id )
                user_heritage_print( children )

            render		= web.template.render(
                TPLPATH, base="layout", globals={'inline': inline, 'session': session} )
            response		= render.login(
                {
                    "title":	( "Login"
                                  if not logged() else
                                  "Welcome %s" % ( session.name.capitalize() )),
                    "redirect":	web.input().get( "redirect", "" ),
                    "children": children,
                })
            web.header( "Cache-Control", "no-cache" )
            web.header( "Content-Type", "text/html" )
            return response

        def POST( self ):
            """Use the provided PIN to authenticate a user, and then remember the credentials in the
            session.  If already logged in, and the 'pinnew' value and 'change' button was supplied,
            then change the user's PIN.

            """
            logging.info( "Session: %r, input: %r" % ( session.items(), web.input().items() ))
            render		= web.template.render(
                TPLPATH, base="layout", globals={'inline': inline, 'session': session} )

            if "add" in web.input():
                # Post via "add" button; add a new user/PIN w/ a selected subset of current user's
                # zones.  Try update first (of existing user/PIN in the session users heritage),
                # then insert.
                error		= None
                try:
                    assert logged(), "Not logged in"
                    name	= web.input().get( "name" )
                    assert name, "Empty name"
                    login	= web.input().get( "login", 1 )
                    assert 0 <= int( login ) <= 2, "Invalid login Disable(0)/Normal(1)/Admin(2)"
                    pin		= web.input().get( "pin" )
                    zones	= " ".join( z for z in session.zones.split()
                                            if z in web.input() )
                    update	= None
                    if logged( admin=True ):
                        # If the current user is an admin user, we can alter an existing user
                        # that we've created; change a pin or login privileges
                        evaluate		= user_heritage( session.user_id ).items()
                        target			= None
                        while evaluate:
                            item		= evaluate.pop()
                            (inam,iuid),subs	= item
                            if inam == name:
                                target		= iuid
                                break
                            else:
                                # Not updating this user; perhaps one of their sub-users?
                                evaluate       += subs.items()
                        if target:
                            logging.info( "Updating user: %r" % ( name ))
                            kwds		= {}
                            kwds["login"]	= login
                            if zones: # Update zones, if supplied
                                kwds["zones"]	= zones
                            if pin: # Update pin too, if supplied
                                kwds["pin"]	= pin
                            with db_lock:
                                update= db.update( 'users', where='user_id = $user_id',
                                                   vars={ "user_id": target }, **kwds )
                            assert update, "Update failed"
                    if not update:
                        # Existing user not found and updated; insert a new one
                        assert pin, "Empty PIN"
                        assert zones, "No zones delegated"
                        logging.info( "Adding User: %r" % ( name ))
                        with db_lock:
                            insert = db.insert( 'users',
                                                creator=session.user_id,
                                                name=name.lower(),
                                                pin=pin,
                                                login=login,
                                                zones=zones )
                        assert insert, "Insert failed"
                except Exception as exc:
                    logging.info( "Add/Update user failure: %s: %s" % ( exc, traceback.format_exc() ))
                    error	= str( exc )
                response	= render.login(
                    {
                        "title":	( "Add User Failed: %s" % ( error )
                                          if error else
                                          "Updated User %s" % ( name )
                                          if update else
                                          "Added User %s" % ( name )),
                        "redirect":	web.input().get( "redirect", "" ),
                        "children":	user_heritage( session.user_id ),
                    })
                web.header( "Cache-Control", "no-cache" )
                web.header( "Content-Type", "text/html" )
                return response

            if "change" in web.input():
                # Post via "change" button, and a new PIN provided; update the record for the logged
                # in user/PIN, who may have several with different PINs and capabilities.
                error		= None
                try:
                    assert logged(), "Not logged in"
                    pin		= web.input().get( "pin" )
                    assert pin, "Empty PIN"
                    with db_lock:
                        query	= db.update( 'users', where='name = $name AND pin = $pin',
                                             pin=web.input().get( 'pin' ),
                                             vars={
                                                 "name": session.name.lower(),
                                                 "pin": session.pin,
                                             })
                    assert query, "Update failed: %r" % ( query )
                except Exception as exc:
                    logging.info( "PIN change failure: %s: %s" % ( exc, traceback.format_exc() ))
                    error	= str( exc )
                response	= render.login(
                    {
                        "title":	( "PIN Changed for %s" % ( session.name )
                                          if not error else
                                          "PIN Change Failed: %s" % ( error )),
                        "redirect":	web.input().get( "redirect", "" ),
                        "children":	user_heritage( session.user_id ),
                    })
                web.header( "Cache-Control", "no-cache" )
                web.header( "Content-Type", "text/html" )
                return response

            if "delete" in web.input():
                # Delete users.  We can only delete users we've created.  Get our user heritage, and
                # see if matching "delete-<user>-<user_id>" checkboxes show up in the form.
                error		= None
                removed		= []
                try:
                    assert logged(), "Not logged in"
                    # [((name,user_id),{...}), ...]
                    evaluate	= user_heritage( session.user_id ).items()
                    exterminate	= []
                    while evaluate:
                        item		= evaluate.pop()
                        (name,uid),subs	= item
                        checkbox	= "delete-%s-%s" % ( name, uid )
                        if checkbox in web.input():
                            # Yup; this (and all their kids) are gone.
                            exterminate.append( item )
                        else:
                            # Not deleting this user; perhaps one of their sub-users?
                            evaluate   += subs.items()
                    while exterminate:
                        item		= exterminate.pop()
                        (name,uid),subs	= item
                        exterminate    += subs.items()
                        logging.warning("Delete user %s (%s)" % ( name, uid ))
                        with db_lock:
                            db.delete( 'users', where='user_id = $user_id',
                                       vars={
                                           "user_id": uid,
                                       })
                        removed.append( name )

                except Exception as exc:
                    logging.info( "Delete user failure: %s: %s" % ( exc, traceback.format_exc() ))
                    error	= str( exc )
                removed		= ", ".join( str(u) for u in removed ) if removed else "nobody"
                response	= render.login(
                    {
                        "title":	( "Deleted %s" % ( removed )
                                          if not error else
                                          "Deleted %s; Failed: %s" % ( removed, error )),
                        "redirect":	web.input().get( "redirect", "" ),
                        "children":	user_heritage( session.user_id ),
                    })
                web.header( "Cache-Control", "no-cache" )
                web.header( "Content-Type", "text/html" )
                return response


            # Post via "go" button (or via event on PIN input); attempt to login
            ident		= None
            error		= None
            try:
                name		= web.input().get( "name" )
                pin		= web.input().get( "pin" )
                assert name and pin, "Invalid user/PIN"
                query		= db.select( 'users', where='name=$name', vars={"name": name.strip().lower()} )
                assert query, "User not found: %r" % ( query )
                for i in query:
                    logging.info( "name: %r vs. %r, pin: %r vs %r" % ( i['name'], name, i['pin'], pin ))
                    if i['pin'] == int( pin ):
                        ident	= i
                        break
                assert ident, "Unrecognized user/PIN"
            except Exception as exc:
                logging.warning( "Login failed: name: %r, pin: %r: %s: %s" % ( name, pin, exc, traceback.format_exc() ))
                error		= str( exc )
            if ident:
                logging.info( "Login ident:   %r" % ( ident.items() ))
                session.update( ident )
                logging.info( "Login session: %r" % ( session.items() ))
                web.seeother( proxy( web.ctx.environ ) + web.input().get( "redirect", "" ))
            else:
                # No ident found; error contains explanatory string.  Try again.
                session.login	= 0
                response	= render.login(
                    {
                        "title":	"Login Failed: %s" % error,
                        "redirect":	web.input().get( "redirect", "" ),
                    })
                web.header( "Cache-Control", "no-cache" )
                web.header( "Content-Type", "text/html" )
                return response

    class issue:
        def GET( self, path, input_variable="queries" ):
            render		= web.template.render(
                TPLPATH, base="layout", globals={'inline': inline, 'session': session} )
            accept		= None
            if path and path.endswith( ".json" ):
                path		= path[:-5]		# clip off ".json"
                accept		= "application/json"

            # Always returns a content-type and response.  If an exception is
            # raised, it should be an appropriate one from the supplied framework to
            # carry a meaningful HTTP status code.  Otherwise, a generic 500 Server
            # Error will be produced.
            content, response	= issue_request(
                render=render, path=path, environ=web.ctx.environ,
                accept=accept, framework=web, logged=logged,
                **{ input_variable: web.input() } )
            web.header( "Cache-Control", "no-cache" )
            web.header( "Content-Type", content )
            return response

        def POST( self, path ):
            # form data posted in web.input(), just like queries
            return self.GET( path, input_variable="posted" )


    # Log web.py HTTP requests to licensing.access
    class LogStdout( wsgilog.LogStdout ):
        """Implement the missing flush API to avoid warnings"""
        def flush(self):
            pass

    class Log( wsgilog.WsgiLog ):
        def __init__( self, application ):
            """Set up logging, and then make sure sys.stderr goes to whereever sys.stdout is now going.  This
            ensures that environ['wsgi.errors'] (which is always set to sys.stderr by web.py) goes
            to the .access log file; this is used to log each incoming HTTP request.

            """
            wsgilog.WsgiLog.__init__(
                self, application,
                logformat	= "%(message)s",
                log		= True,
                tohtml		= True,			# Exceptions generate HTML
                tofile		= True,			# Send logging to file
                file		= ACCFILE,
                interval	= 'd',
                backups		= 7,
            )

            sys.stdout		= LogStdout( self.logger, logging.INFO )
            sys.stderr		= sys.stdout


    # Implement our own version of StaticApp and StaticMiddleware so we can return proper caching
    # headers, and specify a specific basedir for static file access.
    class StaticAppDir( web.httpserver.StaticApp ):
        def __init__( self, environ, start_response, directory ):
            super( StaticAppDir, self ).__init__( environ, start_response )
            self.directory	= directory

    cache_max_age		= 30*24*60*60
    class StaticMiddlewareDir( web.httpserver.StaticMiddleware ):
        """WSGI middleware for serving static files from the specified basedir."""
        def __init__( self, app, prefix="/static/", basedir=os.getcwd() ):
            super( StaticMiddlewareDir, self ).__init__( app, prefix=prefix )
            self.basedir	= basedir
            logging.detail( "Serving static files out of {}".format( basedir + prefix ))

        def __call__( self, environ, start_response ):
            path 		= environ.get( 'PATH_INFO', '' )
            path 		= self.normpath( path )
            if path.startswith(self.prefix):
                app 		= StaticAppDir( environ, start_response, self.basedir )
                app.send_header( 'Cache-Control', 'public, max-age=%d' % ( cache_max_age ))
                return app
            else:
                return self.app( environ, start_response )


    # Get the required web.py classes from the local namespace.  The iface:port must always passed
    # on argv[1] to use app.run(), so use lower-level web.httpserver.runsimple interface.  This sets
    # up the WSGI middleware chain, prints the address and then invokes
    # httpserver.WSGIserver.start(), which does the bind, and then makes WSGI calls
    app				= web.application( urls, locals() )

    # Sessions
    global session_initializer
    session			= web.session.Session(
        app, web.session.DBStore( db, 'sessions' ), initializer=session_initializer )

    # We can't use the stock runsimple; we have to build up our own chain of WSGI middleware and run
    # its server, in order to get our custom StaticMiddleware/StaticApp.
    func			= app.wsgifunc( Log )
    func			= StaticMiddlewareDir( func, "/static/", os.path.dirname( __file__ ))
    func			= web.httpserver.LogMiddleware( func )
    webpy.server		= web.httpserver.WSGIServer( config['address'], func )

    logging.detail( "Web Interface Thread server starting" )
    try:
        webpy.server.start()
    except (KeyboardInterrupt, SystemExit) as exc:
        logging.warning( "Web Interface Thread uncontrolled shutdown: %s", exc )
    except Exception as exc:
        logging.warning( "Web Interface Thread exception shutdown: %s", exc )
    finally:
        logging.detail( "Web Interface Thread stopping..." )
        try:
            webpy.server.stop()
        except Exception as exc:
            logging.warning( "Web Interface Thread stop failure: %s", exc )
        webpy.server		= None
        logging.normal( "Web Interface Thread exiting" )

# To stop the server externally, hit webpy.server.stop
webpy.server			= None

def txtgui( cnf ):
    """Run curses UI, catching all exceptions.  Returns True on failure."""
    failure			= None
    try:        # Initialize curses
        stdscr			= curses.initscr()
        curses.noecho();
        curses.cbreak();
        curses.halfdelay( 1 )
        stdscr.keypad( 1 )

        txt( stdscr, cnf )               # Enter the mainloop
    except:
        failure			= traceback.format_exc()
    finally:
        cnf['stop']		= True
        stdscr.keypad(0)
        curses.echo() ; curses.nocbreak()
        curses.endwin()
        time.sleep(.25)
    if failure:
        logging.error( "Curses GUI Exception: %s", failure )
        return True
    return False


def control( beg, cnf ):
    """Execute one loop of the control system"""
    pass


def main( argv=None, **kwds ):
    """Pass the desired argv (excluding the program name in sys.arg[0]; typically pass argv=None, which
    is equivalent to argv=sys.argv[1:], the default for argparse.  Requires at least one tag to be
    defined.
    """

    ap				= argparse.ArgumentParser(
        description	= "A Cpppo Crypto Licensing Server",
        epilog		= ""
    )
    ap.add_argument( '-v', '--verbose', action="count",
                     default=0, 
                     help="Display logging information." )
    ap.add_argument( '-w', '--web', default="0.0.0.0:8000",
                       help='enable web interface (default: 0.0.0.0:8000)' )
    ap.add_argument( '--no-web', dest='web', action="store_false",
                       help='disable web interface (default: False)' )
    ap.add_argument( '--no-gui', dest='gui',
                       action="store_false", default=True,
                       help='disable Curses GUI interface (default: False)' )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired (default, if text gui: {LOGFILE})".format( LOGFILE=LOGFILE ))

    args = ap.parse_args( argv )

    # Set up logging (may have already triggered and been
    log_cfg['level']		= ( logging_levelmap[args.verbose] 
                                    if args.verbose in logging_levelmap
                                    else logging.DEBUG )
    if args.log or args.gui:
        log_cfg['filename']	= args.log or LOGFILE
    logging.basicConfig( **log_cfg )


    # The caller obtains all current Licenses
    def licenses():
        for r in db.select( 'licenses' ):
            yield LicenseSigned( license=r.license, signature=r.signature, confirm=False )

    
    # Start up Curses consule GUI...
    txtcnf			= {
        'stop':   False,
        'title': 'Licensing',
        'licenses': licenses,
    }

    class daemon( threading.Thread ):
        def __init__( self, config=None, **kwds ):
            super( daemon, self ).__init__( **kwds )
            self.daemon		= True
            self.config		= config or {}

        def stop( self ):
            logging.detail( "Stopping %s Thread", self.name )
            self.config['stop']	= True

        def join( self, *args, **kwds ):
            self.stop()
            logging.info( "Joining %s Thread...", self.name )
            super( daemon, self ).join( *args, **kwds )
            logging.detail( "Joined %s Thread", self.name )

    class txtthread( daemon ):
        def run( self ):
            try:
                while not self.config.get( 'stop' ):
                    if txtgui( self.config ):
                        # Textual GUI has failed!  Don't restart.
                        break
            except Exception as exc:
                logging.error("Text GUI failed: %s\n%s", exc, traceback.format_exc())
            finally:
                logging.normal( "Text GUI exiting" )
                self.stop()

    class webthread( daemon ):
        def run( self ):
            try:
                webpy( self.config )
            except Exception as exc:
                logging.error( "Web GUI failed: %s\n%s", exc, traceback.format_exc() )
            finally:
                self.stop()
                logging.normal( "Web GUI exiting" )

        def stop( self ):
            super( webthread, self ).stop()
            if webpy.server:
                logging.detail( "Web GUI stopping..." )
                webpy.server.stop()
                logging.detail( "Web GUI stopped" )

    class ctlthread( daemon ):
        def run( self ):
            try:
                while not self.config.get( 'stop' ):
                    beg		= timer()
                    control( beg, self.config )
                    dur		= timer() - beg
                    cyc		= self.config.get( 'cycle', 1.0 )
                    if dur < cyc:
                        time.sleep( cyc - dur )
            except Exception as exc:
                logging.error( "Control system failed: %s\n%s", exc, traceback.format_exc() )
            finally:
                logging.normal( "Control system exiting" )
                self.stop()

    threads			= []
    try:
        # Start the control system Thread.
        ctlthr			= ctlthread( config={ 'cycle': 1.0 }, name='control' )
        ctlthr.start()
        threads.append( ctlthr )

        # Start the Text UI (if desired)
        txtthr			= None
        if args.gui:
            txtthr		= txtthread( txtcnf, name='curses' )
            txtthr.start()
            threads.append( txtthr )
    
        # Start the web UI (if desired)
        webthr			= None
        if args.web:
            # Deduce interface:port to bind, and correct types
            address		= args.web.split( ':' )
            assert 1 <= len( address ) <= 2, "Web address must be in the form <interface>:<port>"
            address		= ( str( address[0] ),
                                    int( address[1] ) if len( address ) > 1 else 8000 )
    
            webthr		= webthread( config={ 'address': address }, name='web' )
            webthr.name		= 'web.py'
            webthr.start()
            threads.append( webthr )

        # Just wait for any thread (web or text GUI, control) to finish
        while not shutdown_signalled and all( t.is_alive() for t in threads ):
            signal_service()
            time.sleep( .1 )
    except:
        logging.error( "Main thread Exception: %s", traceback.format_exc() )
    finally:
        # Either the Web or the Curses GUI completed, or something blew up.  Shut all the
        # threads down, and save state.
        for t in threads:
            t.join( timeout=10.0 )
        logging.detail( "Saving state..." )
        state_save()
