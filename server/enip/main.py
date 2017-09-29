#! /usr/bin/env python3

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


"""
enip		-- An server recognizing an Ethernet/IP protocol subset

USAGE
    python -m cpppo.server.enip


"""

__all__				= ['main']

import argparse
import contextlib
import fnmatch
import json
import logging
import random
import signal
import socket
import sys
import threading
import time
import traceback

import cpppo
from .. import network
from . import defaults, parser, device, ucmm, logix

log				= logging.getLogger( "enip.srv" )


# Maintain a global 'options' cpppo.dotdict() containing all our configuration options, configured
# from incoming parsed command-line options.  This'll be passed (ultimately) to the server and
# web_api Thread Thread target functions, broken out as keyword parameters.  As a result, the second
# (and lower) levels of this dotdict will remain as dotdict objects assigned to keywords determined
# by the top level dict keys.  
options				= cpppo.dotdict()

# The stats for the connections presently open, indexed by <interface>:<port>.   Of particular
# interest is connections['key'].eof, which will terminate the connection if set to 1
connections			= cpppo.dotdict()

# All known tags, their CIP Attribute and desired error code
tags				= cpppo.dotdict()

# Server control signals
srv_ctl				= cpppo.dotdict()


# Optional modules.  This module is optional, and only used if the -w|--web option is specified
try:
    import web
except:
    pass

# 
# The Web API, implemented using web.py
# 
# 
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

    Otherwise, return the first acceptable encoding in 'available'.  If no
    matching encodings are avaliable, return the (original) None.
    """
    if accept:
        # A desired encoding; make sure it is available
        accept		= accept.lower()
        if accept not in available:
            accept	= None
        return accept

    # No predefined accept encoding; deduce preferred available one.  Accept:
    # may contain */*, */json, etc.  If multiple matches, select the one with
    # the highest Accept: quality value (our present None starts with a quality
    # metric of 0.0).  Test available: ["application/json", "text/html"],
    # vs. HTTP_ACCEPT
    # "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" Since
    # earlier matches are for the more preferred encodings, later matches must
    # *exceed* the quality metric of the earlier.
    accept		= None # may be "", False, {}, [], ()
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
                log.debug( "Found %16s == %-16s;q=%.1f %s %-16s;q=%.1f",
                           avail, encoding, q,
                           '> ' if q > quality else '<=',
                           accept, quality )
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
            class NotAcceptable( framework.NotAcceptable ):
                def __init__(self, message):
                    self.message = '; '.join( [self.message, message] )
                    framework.NotAcceptable.__init__(self)
            return NotAcceptable( message )
    '''
    elif framework and framework.__name__ == "itty":
        if status == 404:
            return framework.NotFound( message )

        if status == 406:
            class NotAcceptable( itty.RequestError ):
                status  = 406
            return NotAcceptable( message )
    '''
    return Exception( "%d %s" % ( status, message ))


def html_head( thing, head="<title>%(title)s</title>", **kwargs ):
    """Emit our minimal HTML5 wrapping.  The default 'head' requires only a
    'title' keyword parameter.  <html>, <head> and <body> are all implied."""
    prefix		= """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    """ + ( head  % kwargs ) + """
</head>
<body>
"""

    postfix		= """
</body>
</html>
"""
    return prefix + thing + postfix

def html_wrap( thing, tag="div", **kwargs ):
    """Wrap a thing in a standard HTML <tag>...</tag>, with optional attributes"""
    prefix		= "<"
    prefix     	       += tag
    for attr, value in kwargs.items():
        prefix	       += " %s='%s'" % ( attr, value )
    prefix	       += ">\n"
    return prefix + thing + "\n</%s>\n" % tag

#
# URL request handlers
#
#     api_request	-- Returns all specified, after executing (optional) command
# 
# 
#   group       / match   / command / value	description
#   -----         -----     -------   -----	----------- 
#   tag         / <tag>   / value[x]/ 1000	Set the given tag's attribute's value[x] to 1000
#   tag         / <tag>   / value   / [1,2,3]
# 
#   option      / delay   / value   / 1.2	Set the option delay.value=1.2
#   connections / *       / eof     / true	Signal an EOF to the specified connection
#   server      / control / disable / true      Disable the server, dropping connections (false re-enable)
#   server      / control / done    / true      Terminate the server (as if hit with a ^C)
# 
def api_request( group, match, command, value,
                      queries=None, environ=None, accept=None,
                      framework=None ):
    """Return a JSON object containing the response to the request:
      {
        data:     { ... },
        ...,
      }

    The data list contains objects representing all matching objects, executing
    the optional command.  If an accept encoding is supplied, use it.
    Otherwise, detect it from the environ's' "HTTP_ACCEPT"; default to
    "application/json".

        group		-- A device group, w/globbing; no default
        match		-- A device id match, w/globbing; default is: '*'
        command		-- The command to execute on the device; default is: 'get'
        value		-- All remaining query parameters; default is: []

        queries		-- All HTTP queries and/or form parameters
        environ		-- The HTTP request environment
        accept		-- A forced MIME encoding (eg. application/json).
        framework	-- The web framework module being used
    """

    global options
    global connections
    global tags
    global srv_ctl
    accept		= deduce_encoding( [ "application/json",
                                             "text/javascript",
                                             "text/plain",
                                             "text/html" ],
                                           environ=environ, accept=accept )

    # Deduce the device group and id match, and the optional command and value.
    # Values provided on the URL are overridden by those provided as query options.
    if "group" in queries and queries["group"]:
        group		= queries["group"]
        del queries["group"]
    if not group:
        group		= "*"

    if "match" in queries and queries["match"]:
        match		= queries["match"]
        del queries["match"]
    if not match:
        match		= "*" 

    # The command/value defaults to the HTTP request, but also may be overridden by
    # the query option.
    if "command" in queries and queries["command"]:
        command		= queries["command"]
        del queries["command"]
    if "value" in queries and queries["value"]:
        value		= queries["value"]
        del queries["value"]

    # The "since" query option may be supplied, and is used to prevent (None) or
    # limit (0,...)  the "alarm" responses to those that have been updated/added
    # since the specified time.
    since		= None
    if "since" in queries and queries["since"]:
        since		= float( queries["since"] )
        del queries["since"]

    # Collect up all the matching objects, execute any command, and then get
    # their attributes, adding any command { success: ..., message: ... }
    content		= {
        "alarm":	[],
        "command":	None,
        "data":		{},
        "since":	since,		# time, 0, None (null)
        "until":	cpppo.timer(),	# time (default, unless we return alarms)
        }

    logging.debug( "Searching for %s/%s, since: %s (%s)",
            group, match, since, 
            None if since is None else time.ctime( since ))

    # Effectively:
    #     group.match.command = value
    # Look through each "group" object's dir of available attributes for "match".  Then, see if 
    # that target attribute exists, and is something we can get attributes from.
    for grp, obj in [ 
            ('options',		options),
            ('connections', 	connections),
            ('tags',		tags ),
            ('server',		srv_ctl )]: 
        for mch in [ m for m in dir( obj ) if not m.startswith( '_' ) ]:
            log.detail( "Evaluating %s.%s: %r", grp, mch, getattr( obj, mch, None ))
            if not fnmatch.fnmatch( grp, group ):
                continue
            if not fnmatch.fnmatch( mch, match ):
                continue
            target		= getattr( obj, mch, None )
            if not target:
                log.warning( "Couldn't find advertised attribute %s.%s", grp, mch )
                continue
            if not hasattr( target, '__getattr__' ):
                continue
          
            # The obj's group name 'grp' matches requested group (glob), and the entry 'mch' matches
            # request match (glob).  /<group>/<match> matches this obj.key.
            result		= {}
            if command is not None:
                # A request/assignment is being made.  Retain the same type as the current value,
                # and allow indexing!  We want to ensure that we don't cause failures by corrupting
                # the types of value.  Unfortunately, this makes it tricky to support "bool", as
                # coercion from string is not supported.
                try:
                    cur		= getattr( target, command )
                    result["message"] = "%s.%s.%s: %r" % ( grp, mch, command, cur )
                    if value is not None:
                        typ	= type( cur )
                        if typ is bool:
                            # Either 'true'/'yes' or 'false'/'no', otherwise it must be a number
                            if value.lower() in ('true', 'yes'):
                                cvt	= True
                            elif value.lower() in ('false', 'no'):
                                cvt	= False
                            else:
                                cvt	= bool( int( value ))
                        else:
                            cvt		= typ( value )
                        setattr( target, command, cvt )
                        result["message"] = "%s.%s.%s=%r (%r)" % ( grp, mch, command, value, cvt )
                    result["success"]	= True
                except Exception as exc:
                    result["success"]	= False
                    result["message"]	= "%s.%s.%s=%r failed: %s" % ( grp, mch, command, value, exc )
                    logging.warning( "%s.%s.%s=%s failed: %s\n%s" % ( grp, mch, command, value, exc,
                                                                       traceback.format_exc() ))

            # Get all of target's attributes (except _*) advertised by its dir() results
            attrs		= [ a for a in dir( target ) if not a.startswith('_') ]
            data		= {}
            for a in attrs:
                data[a]		= getattr( target, a )
            content["command"]	= result
            content["data"].setdefault( grp, {} )[mch] = data
        

    # Report the end of the time-span of alarm results returned; if none, then
    # the default time will be the _timer() at beginning of this function.  This
    # ensures we don't duplicately report alarms (or miss any)
    if content["alarm"]:
        content["until"]= content["alarm"][0]["time"]

    # JSON
    response            = json.dumps( content, sort_keys=True, indent=4, default=lambda obj: repr( obj ))

    if accept in ("text/html"):
        # HTML; dump any request query options, wrap JSON response in <pre>
        response	= html_wrap( "Response:", "h2" ) \
            		+ html_wrap( response, "pre" )
        response        = html_wrap( "Queries:",  "h2" ) \
            		+ html_wrap( "\n".join(
                            ( "%(query)-16.16s %(value)r" % {
                                "query":	str( query ) + ":",
                                "value":	value,
                                }
                              for iterable in ( queries,
                                                [("group", group),
                                                 ("match", match),
                                                 ("command", command),
                                                 ("value", value),
                                                 ("since", since),
                                                 ] )
                                  for query, value in iterable )), tag="pre" ) \
                  	+ response
        response        = html_head( response,
                                     title='/'.join( ["api", group or '', match or '', command or ''] ))
    elif accept and accept not in ("application/json", "text/javascript", "text/plain"):
        # Invalid encoding requested.  Return appropriate 406 Not Acceptable
        message		=  "Invalid encoding: %s, for Accept: %s" % (
            accept, environ.get( "HTTP_ACCEPT", "*.*" ))
        raise http_exception( framework, 406, message )

    # Return the content-type we've agreed to produce, and the result.
    return accept, response


# 
# The web.py url endpoints, and their classes
# 
class trailing_slash:
    def GET( self, path ):
        web.seeother( path )

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
        web.redirect( '/static/images/favicon.png' )

class home:
    def GET( self ):
        """Forward to an appropriate start page.  Detect if behind a
        proxy, and use the original forwarded host.
        """
        # print json.dumps(web.ctx, skipkeys=True, default=repr, indent=4,)
        proxy		= web.ctx.environ.get( "HTTP_X_FORWARDED_HOST", "" )
        if proxy:
            proxy	= "http://" + proxy
        target		= proxy + "/static/index.html"
        web.seeother( target )

class api:
    def GET( self, *args ):
        """Expects exactly 4 arguments, all of which may be empty, or
        contain a / followed by 0 or more non-/ characters.  Deduce
        accept encoding from Accept: header, or force JSON if .json path
        was explicitly requested.  These 4 arguments are the device
        group and id patterns, followed by the optional command and
        value.

        Always returns a content-type and response; virtually all
        failures involving problems with the device, PLC or
        communications are expected to return a successful 200 response,
        with a JSON payload describing the command success state, and a
        message describing any failure mode.  This includes
        communication failures (eg. LAN disruptions, PLC failures,
        etc.), incorrect commands to devices (eg. writing to a read-only
        attribute, etc.)

        If an exception is raised (due to some other internal failure),
        it should be an appropriate one from the supplied framework to
        carry a meaningful HTTP status code.  Otherwise, a generic 500
        Server Error will be produced.  We expect that non-200 response
        failures are due to some unexpected failure, and should
        eventually lead to a system restart.
        """
        environ		= web.ctx.environ
        queries		= web.input()

        # Ensure these are set, regardless of result
        web.header( "Cache-Control", "no-cache" )
        web.header( "Access-Control-Allow-Origin", "*" )

        # The last parameter may end with '.json', and forces accept to
        # "application/json".  Ensure every empty parameter is None.  If
        # exactly 4 args are not supplied, we'll produce a 500 Server
        # Error.  'command' defaults to the HTTP request if not set.
        def clean( a ):
            if a:
                if a.startswith( "/" ):
                    a		= a[1:]
                if a.endswith( ".json" ):
                    a		= a[:-5]
                    clean.accept= "application/json"
            else:
                a		= None
            return a
        clean.accept		= None

        try:
            group, match, command, value \
			= [ clean( a ) for a in args ]
        except:
            raise http_exception( web, 500, "/api requires 4 arguments" )
        if not value and command and '=' in command:
            # Treat a trailing command=value like command/value, for convenience
            command, value	= command.split( '=', 1)
            if not value:
                value		= None

        log.detail( "group: %s, match: %s, command: %s, value: %s, accept: %s",
                    group, match, command, value, clean.accept )
            
        content, response = api_request( group=group, match=match,
                                            command=command, value=value,
                                            queries=queries, environ=environ,
                                            accept=clean.accept, framework=web )
        web.header( "Content-Type", content )
        return response


urls				= (
    "(/.*)/",					"trailing_slash",
    "/favicon.ico",				"favicon",
    "/api(/[^/]*)?(/[^/]*)?(/[^/]*)?(/.*)?",	"api",
    "/?",					"home",
)


def web_api( http=None):
    """Get the required web.py classes from the global namespace.  The iface:port must always passed on
    argv[1] to use app.run(), so use lower-level web.httpserver.runsimple interface, so we can bind
    to the supplied http address."""
    try:
        app			= web.application( urls, globals() )
        web.httpserver.runsimple( app.wsgifunc(), http )
        log.normal( "Web API started on %s:%s", http[0], http[1] )
    except socket.error:
        log.error( "Could not bind to %s:%s for web API", http[0], http[1] )
    except Exception as exc:
        log.error( "Web API server on %s:%s failed: %s", http[0], http[1], exc )


# 
# The EtherNet/IP CIP Main and Server Thread
# 
# stats_for	-- Finds/creates the stats entry for a specified peer (if any)
# enip_srv	-- This function runs in a Thread for each active connection.
# enip_srv_udp	-- Service multiple UDP/IP peers (limited web interface control)
# enip_srv_tcp	-- Service one TCP/IP peer
# 
def stats_for( peer ):
    """If no peer address provided, we won't have a stats entry 'til first data received."""
    global connections
    if peer is None:
        return None,None
    connkey			= "%s_%d" % ( peer[0].replace( '.', '_' ), peer[1] )
    stats			= connections.get( connkey )
    if stats is not None:
        return stats,connkey
    stats			= cpppo.apidict( timeout=defaults.timeout )
    connections[connkey]	= stats
    stats['requests']		= 0
    stats['received']		= 0
    stats['eof']		= False
    stats['interface']		= peer[0]
    stats['port']		= peer[1]
    return stats,connkey


def enip_srv( conn, addr, enip_process=None, delay=None, **kwds ):
    """Serve one Ethernet/IP client 'til EOF; then close the socket.  Parses headers and encapsulated
    EtherNet/IP request data 'til either the parser fails (the Client has submitted an un-parsable
    request), or the request handler fails.  Otherwise, encodes the data.response in an EtherNet/IP
    packet and sends it back to the client.

    Use the supplied enip_process function to process each parsed EtherNet/IP frame, returning True
    if a data.response is formulated, False if the session has ended cleanly, or raise an Exception
    if there is a processing failure (eg. an unparsable request, indicating that the Client is
    speaking an unknown dialect and the session must close catastrophically.)

    If a partial EtherNet/IP header is parsed and an EOF is received, the enip_header parser will
    raise an AssertionError, and we'll simply drop the connection.  If we receive a valid header and
    request, the supplied enip_process function is expected to formulate an appropriate error
    response, and we'll continue processing requests.

    An option numeric delay value (or any delay object with a .value attribute evaluating to a
    numeric value) may be specified; every response will be delayed by the specified number of
    seconds.  We assume that such a value may be altered over time, so we access it afresh for each
    use.

    All remaining keywords are passed along to the supplied enip_process function.

    For UDP a socket 'conn', there is no 'addr' (it is None).  For each incoming request, we'll use
    socket.recvfrom to gain a source address, and create (if necessary) a connections[<connkey>]
    stats entry.  The 'eof' entry doesn't have the same meaning as for a TCP connection, of course.

    """
    global latency
    global timeout

    name			= "enip_%s" % ( addr[1] if addr else "UDP" )
    log.normal( "EtherNet/IP Server %s begins serving peer %s", name, addr )

    assert enip_process is not None, \
        "Must specify an EtherNet/IP processing function via 'enip_process'"

    # We can handle TCP/IP or UDP/IP sockets, and expect not have an addr for UDP/IP
    tcp				= ( conn.family == socket.AF_INET and conn.type == socket.SOCK_STREAM )
    udp				= ( conn.family == socket.AF_INET and conn.type == socket.SOCK_DGRAM )
    assert tcp ^ udp, \
        "Unknown socket family %s (should be AF_INET == %s) or type %s (should be SOCK_STREAM/DGRAM %s/%s)" % (
            conn.family, socket.AF_INET, conn.type, socket.SOCK_STREAM, socket.SOCK_DGRAM )
    assert tcp and addr or udp and not addr, \
        (( "TCP connections must have address" if tcp else "UDP must not" ) + ": %s" ) % ( addr )

    # For TCP/IP sockets, configure TCP_NODELAY (for no NAGLE delay in transmitting response data)
    # and SO_KEEPALIVE (to ensure that we eventually detect half-open connections -- connections
    # where we are listening only, and where the peer has closed by the FIN or RST has been lost.
    if tcp:
        try:
            conn.setsockopt( socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 )
        except Exception as exc:
            log.warning( "%s unable to set TCP_NODELAY for client %r: %s",
                         name, addr, exc )
        try:
            conn.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1 )
        except Exception as exc:
            log.warning( "%s unable to set SO_KEEPALIVE for client %r: %s",
                         name, addr, exc )
        enip_srv_tcp( conn, addr, name=name, enip_process=enip_process, delay=delay, **kwds )
    elif udp:
        enip_srv_udp( conn, name=name, enip_process=enip_process, **kwds )
    else:
        raise NotImplemented( "Unknown socket protocol for EtherNet/IP CIP" )


def enip_srv_udp( conn, name, enip_process, **kwds ):
    """Processes UDP packets from multiple clients, as they arrive.  No concept of EOF, but we'll
    respect the setting of 'eof' in stats, and ignore requests from that client.

    """
    with parser.enip_machine( name=name, context='enip' ) as machine:
        while not kwds['server']['control']['done'] and not kwds['server']['control']['disable']:
            try:
                source		= cpppo.rememberable()
                data		= cpppo.dotdict()

                # If no/partial EtherNet/IP header received, parsing will fail with a NonTerminal
                # Exception (dfa exits in non-terminal state).  Build data.request.enip:
                begun		= cpppo.timer() # waiting for next transaction
                addr,stats	= None,None
                with contextlib.closing( machine.run(
                        path='request', source=source, data=data )) as engine:
                    # PyPy compatibility; avoid deferred destruction of generators
                    for mch,sta in engine:
                        if sta is not None:
                            # No more transitions available.  Wait for input.  
                            continue
                        assert not addr, "Incomplete UDP request from client %r" % ( addr )
                        msg	= None
                        while msg is None:
                            # For UDP, we'll allow no input only at the start of a new request parse
                            # (addr is None); anything else will be considered a failed request Back
                            # to the trough for more symbols, after having already received a packet
                            # from a peer?  No go!
                            wait	= ( kwds['server']['control']['latency']
                                            if source.peek() is None else 0 )
                            brx		= cpppo.timer()
                            msg,frm	= network.recvfrom( conn, timeout=wait )
                            now		= cpppo.timer()
                            ( log.detail if msg else log.debug )(
                                "Transaction receive after %7.3fs (%5s bytes in %7.3f/%7.3fs): %r",
                                        now - begun, len( msg ) if msg is not None else "None",
                                        now - brx, wait, stats_for( frm )[0] )
                            # If we're at a None (can't proceed), and we haven't yet received input,
                            # then this is where we implement "Blocking"; we just loop for input.

                        # We have received exactly one packet from an identified peer!
                        begun	= now
                        addr	= frm
                        stats,_	= stats_for( addr )
                        # For UDP, we don't ever receive incoming EOF, or set stats['eof'].
                        # However, we can respond to a manual eof (eg. from web interface) by
                        # ignoring the peer's packets.
                        assert stats and not stats.get( 'eof' ), \
                            "Ignoring UDP request from client %r: %r" % ( addr, msg )
                        stats['received']+= len( msg )
                        if log.getEffectiveLevel() <= logging.DETAIL:
                            log.detail( "%s recv: %5d: %s", machine.name_centered(),
                                        len( msg ), cpppo.reprlib.repr( msg ))
                        source.chain( msg )

                # Terminal state and EtherNet/IP header recognized; process and return response
                assert stats
                if 'request' in data:
                    stats['requests'] += 1
                # enip_process must be able to handle no request (empty data), indicating the
                # clean termination of the session if closed from this end (not required if
                # enip_process returned False, indicating the connection was terminated by
                # request.)
                if enip_process( addr, data=data, **kwds ):
                    # Produce an EtherNet/IP response carrying the encapsulated response data.
                    # If no encapsulated data, ensure we also return a non-zero EtherNet/IP
                    # status.  A non-zero status indicates the end of the session.
                    assert 'response.enip' in data, "Expected EtherNet/IP response; none found"
                    if 'input' not in data.response.enip or not data.response.enip.input:
                        log.warning( "Expected EtherNet/IP response encapsulated message; none found" )
                        assert data.response.enip.status, "If no/empty response payload, expected non-zero EtherNet/IP status"

                    rpy		= parser.enip_encode( data.response.enip )
                    if log.getEffectiveLevel() <= logging.DETAIL:
                        log.detail( "%s send: %5d: %s", machine.name_centered(),
                                    len( rpy ), cpppo.reprlib.repr( rpy ))
                    conn.sendto( rpy, addr )

                log.detail( "Transaction complete after %7.3fs", cpppo.timer() - begun )

                stats['processed']	= source.sent
            except:
                # Parsing failure.  Suck out some remaining input to give us some context, but don't re-raise
                if stats:
                    stats['processed']= source.sent
                memory		= bytes( bytearray( source.memory ))
                pos		= len( source.memory )
                future		= bytes( bytearray( b for b in source ))
                where		= "at %d total bytes:\n%s\n%s (byte %d)" % (
                    stats.get( 'processed', 0 ) if stats else 0,
                    repr( memory+future ), '-' * ( len( repr( memory ))-1 ) + '^', pos )
                log.error( "Client %r EtherNet/IP error %s\n\nFailed with exception:\n%s\n", addr, where,
                             ''.join( traceback.format_exception( *sys.exc_info() )))


def enip_srv_tcp( conn, addr, name, enip_process, delay=None, **kwds ):
    source			= cpppo.rememberable()
    with parser.enip_machine( name=name, context='enip' ) as machine:
        # We can be provided a dotdict() to contain our stats.  If one has been passed in, then this
        # means that our stats for this connection will be available to the web API; it may set
        # stats.eof to True at any time, terminating the connection!  The web API will try to coerce
        # its input into the same type as the variable, so we'll keep it an int (type bool doesn't
        # handle coercion from strings).  We'll use an apidict, to ensure that attribute values set
        # via the web API thread (eg. stats.eof) are blocking 'til this thread wakes up and reads
        # them.  Thus, the web API will block setting .eof, and won't return to the caller until the
        # thread is actually in the process of shutting down.  Internally, we'll use __setitem__
        # indexing to change stats values, so we don't block ourself!
        try:
            assert addr, "EtherNet/IP CIP server for TCP/IP must be provided a peer address"
            stats,connkey	= stats_for( addr )
            while not stats.eof:
                data		= cpppo.dotdict()

                source.forget()
                # If no/partial EtherNet/IP header received, parsing will fail with a NonTerminal
                # Exception (dfa exits in non-terminal state).  Build data.request.enip:
                begun		= cpppo.timer()
                with contextlib.closing( machine.run(
                        path='request', source=source, data=data )) as engine:
                    # PyPy compatibility; avoid deferred destruction of generators
                    for mch,sta in engine:
                        if sta is not None:
                            continue
                        # No more transitions available.  Wait for input.  EOF (b'') will lead to
                        # termination.  We will simulate non-blocking by looping on None (so we can
                        # check our options, in case they've been changed).  If we still have input
                        # available to process right now in 'source', we'll just check (0 timeout);
                        # otherwise, use the specified server.control.latency.
                        msg	= None
                        while msg is None and not stats.eof:
                            wait=( kwds['server']['control']['latency']
                                   if source.peek() is None else 0 )
                            brx = cpppo.timer()
                            msg	= network.recv( conn, timeout=wait )
                            now = cpppo.timer()
                            ( log.detail if msg else log.debug )(
                                "Transaction receive after %7.3fs (%5s bytes in %7.3f/%7.3fs)",
                                now - begun, len( msg ) if msg is not None else "None",
                                now - brx, wait )

                            # After each block of input (or None), check if the server is being
                            # signalled done/disabled; we need to shut down so signal eof.  Assumes
                            # that (shared) server.control.{done,disable} dotdict be in kwds.  We do
                            # *not* read using attributes here, to avoid reporting completion to
                            # external APIs (eg. web) awaiting reception of these signals.
                            if kwds['server']['control']['done'] or kwds['server']['control']['disable']:
                                log.detail( "%s done, due to server done/disable", 
                                            machine.name_centered() )
                                stats['eof']	= True
                            if msg is not None:
                                stats['received']+= len( msg )
                                stats['eof']	= stats['eof'] or not len( msg )
                                if log.getEffectiveLevel() <= logging.DETAIL:
                                    log.detail( "%s recv: %5d: %s", machine.name_centered(),
                                                len( msg ), cpppo.reprlib.repr( msg ))
                                source.chain( msg )
                            else:
                                # No input.  If we have symbols available, no problem; continue.
                                # This can occur if the state machine cannot make a transition on
                                # the input symbol, indicating an unacceptable sentence for the
                                # grammar.  If it cannot make progress, the machine will terminate
                                # in a non-terminal state, rejecting the sentence.
                                if source.peek() is not None:
                                    break
                                # We're at a None (can't proceed), and no input is available.  This
                                # is where we implement "Blocking"; just loop.

                log.detail( "Transaction parsed  after %7.3fs", cpppo.timer() - begun )
                # Terminal state and EtherNet/IP header recognized, or clean EOF (no partial
                # message); process and return response
                if 'request' in data:
                    stats['requests'] += 1
                try:
                    # enip_process must be able to handle no request (empty data), indicating the
                    # clean termination of the session if closed from this end (not required if
                    # enip_process returned False, indicating the connection was terminated by
                    # request.)
                    delayseconds= 0	# response delay (if any)
                    if enip_process( addr, data=data, **kwds ):
                        # Produce an EtherNet/IP response carrying the encapsulated response data.
                        # If no encapsulated data, ensure we also return a non-zero EtherNet/IP
                        # status.  A non-zero status indicates the end of the session.
                        assert 'response.enip' in data, "Expected EtherNet/IP response; none found"
                        if 'input' not in data.response.enip or not data.response.enip.input:
                            log.warning( "Expected EtherNet/IP response encapsulated message; none found" )
                            assert data.response.enip.status, "If no/empty response payload, expected non-zero EtherNet/IP status"

                        rpy	= parser.enip_encode( data.response.enip )
                        if log.getEffectiveLevel() <= logging.DETAIL:
                            log.detail( "%s send: %5d: %s %s", machine.name_centered(),
                                        len( rpy ), cpppo.reprlib.repr( rpy ),
                                        ("delay: %r" % delay) if delay else "" )
                        if delay:
                            # A delay (anything with a delay.value attribute) == #[.#] (converible
                            # to float) is ok; may be changed via web interface.
                            try:
                                delayseconds = float( delay.value if hasattr( delay, 'value' ) else delay )
                                if delayseconds > 0:
                                    time.sleep( delayseconds )
                            except Exception as exc:
                                log.detail( "Unable to delay; invalid seconds: %r", delay )
                        try:
                            conn.send( rpy )
                        except socket.error as exc:
                            log.detail( "Session ended (client abandoned): %s", exc )
                            stats['eof'] = True
                        if data.response.enip.status:
                            log.warning( "Session ended (server EtherNet/IP status: 0x%02x == %d)",
                                        data.response.enip.status, data.response.enip.status )
                            stats['eof'] = True
                    else:
                        # Session terminated.  No response, just drop connection.
                        if log.getEffectiveLevel() <= logging.DETAIL:
                            log.detail( "Session ended (client initiated): %s",
                                        parser.enip_format( data ))
                        stats['eof'] = True
                    log.detail( "Transaction complete after %7.3fs (w/ %7.3fs delay)",
                        cpppo.timer() - begun, delayseconds )
                except:
                    log.error( "Failed request: %s", parser.enip_format( data ))
                    enip_process( addr, data=cpppo.dotdict() ) # Terminate.
                    raise

            stats['processed']	= source.sent
        except:
            # Parsing failure.  We're done.  Suck out some remaining input to give us some context.
            stats['processed']	= source.sent
            memory		= bytes( bytearray( source.memory ))
            pos			= len( source.memory )
            future		= bytes( bytearray( b for b in source ))
            where		= "at %d total bytes:\n%s\n%s (byte %d)" % (
                stats.processed, repr( memory+future ), '-' * ( len( repr( memory ))-1) + '^', pos )
            log.error( "EtherNet/IP error %s\n\nFailed with exception:\n%s\n", where,
                         ''.join( traceback.format_exception( *sys.exc_info() )))
            raise
        finally:
            # Not strictly necessary to close (network.server_main will discard the socket,
            # implicitly closing it), but we'll do it explicitly here in case the thread doesn't die
            # for some other reason.  Clean up the connections entry for this connection address.
            connections.pop( connkey, None )
            log.normal( "%s done; processed %3d request%s over %5d byte%s/%5d received (%d connections remain)", name,
                        stats.requests,  " " if stats.requests == 1  else "s",
                        stats.processed, " " if stats.processed == 1 else "s", stats.received,
                        len( connections ))
            sys.stdout.flush()
            conn.close()


# To support re-opening a log file from within a signal handler, we need an atomic method to safely
# close a FileHandler's self.stream (an open file), while it is certain to not be in use.  Under
# Python2/3, FileHandler.close acquires locks preventing a race condition with FileHandler.emit.

# There is an opportunity for race conditions while traversing logging.root.handlers here, iff the
# root Logger's handlers are being added or deleted by this (or another) Thread, which we don't do.

# More importantly, however, since logging uses threading.RLock, this procedure must be run in a
# separate thread, or by the main thread but NOT inside the signal handler!  Since the main thread
# could hold the lock when it arrives here as a result of the signal, then the locks will be
# ineffective -- which is perhaps a good thing, otherwise we would deadlock, instead of just
# crash...  So, set a flag when the signal occurs, and arrange to check the flag from time to time
# when the incoming socket is idle.

logrotate_signalled		= False

def logrotate_request( signum, frame ):
    global logrotate_signalled
    logrotate_signalled		= True	

def logrotate_perform():
    global logrotate_signalled
    if logrotate_signalled:
        logrotate_signalled	= False
        logging.warning( "Rotating log files due to signal" )
        for hdlr in logging.root.handlers:
            if isinstance( hdlr, logging.FileHandler ):
                hdlr.close()

# 
# main		-- Run the EtherNet/IP Controller Simulation
# 
def main( argv=None, attribute_class=device.Attribute, idle_service=None, identity_class=None,
          UCMM_class=None, message_router_class=None, connection_manager_class=None, **kwds ):
    """Pass the desired argv (excluding the program name in sys.arg[0]; typically pass argv=None, which
    is equivalent to argv=sys.argv[1:], the default for argparse.  Requires at least one tag to be
    defined.

    If a cpppo.apidict() is passed for kwds['server']['control'], we'll use it to transmit server
    control signals via its .done, .disable, .timeout and .latency attributes.

    Uses the provided attribute_class (default: device.Attribute) to process all EtherNet/IP
    attribute I/O (eg. Read/Write Tag [Fragmented]) requests.  By default, device.Attribute stores
    and retrieves the supplied data.  To perform other actions (ie. forward the data to your own
    application), derive from device.Attribute, and override the __getitem__ and __setitem__
    methods.

    If an idle_service function is provided, it will be called after a period of latency between
    incoming requests.

    """
    global address
    global options
    global tags
    global srv_ctl
    global latency
    global timeout

    ap				= argparse.ArgumentParser(
        description = "Provide an EtherNet/IP Server",
        epilog = "" )

    ap.add_argument( '-v', '--verbose', action="count",
                     default=0, 
                     help="Display logging information." )
    ap.add_argument( '-c', '--config', action='append',
                     help="Add another (higher priority) config file path." )
    ap.add_argument( '--no-config', action='store_true',
                     default=False, 
                     help="Disable loading of config files (default: False)" )
    ap.add_argument( '-a', '--address',
                     default=( "%s:%d" % defaults.address ),
                     help="EtherNet/IP interface[:port] to bind to (default: %s:%d)" % (
                         defaults.address[0], defaults.address[1] ))
    ap.add_argument( '-u', '--udp', action='store_true',
                     default=True, 
                     help="Enable UDP/IP server (default: True)" )
    ap.add_argument( '-U', '--no-udp', dest="udp", action='store_false',
                     help="Disable UDP/IP server" )
    ap.add_argument( '-t', '--tcp', action='store_true',
                     default=True, 
                     help="Enable TCP/IP server (default: True)" )
    ap.add_argument( '-T', '--no-tcp', dest="tcp", action='store_false',
                     help="Disable TCP/IP server" )
    ap.add_argument( '--no-print', action='store_false', dest='print',
                     help="Disable printing of summary of operations to stdout" )
    ap.add_argument( '-p', '--print', action='store_true',
                     default=False,
                     help="Print a summary of operations to stdout (default: False)" )
    ap.add_argument( '-l', '--log',
                     help="Log file, if desired" )
    ap.add_argument( '-w', '--web',
                     default="",
                     help="Web API [interface]:[port] to bind to (default: %s, port 80)" % (
                         defaults.address[0] ))
    ap.add_argument( '-d', '--delay',
                     default="0.0" ,
                     help="Delay response to each request by a certain number of seconds (default: 0.0)")
    ap.add_argument( '-s', '--size',
                     help="Limit EtherNet/IP encapsulated request size to the specified number of bytes (default: None)",
                     default=None )
    ap.add_argument( '--route-path',
                     default=None,
                     help="Route Path, in JSON, eg. %r (default: None); 0/false to accept only empty route_path" % (
                         str( json.dumps( defaults.route_path_default ))))
    ap.add_argument( '-S', '--simple', action='store_true',
                     default=False,
                     help="Simulate a simple (non-routing) EtherNet/IP CIP device (eg. MicroLogix)")
    ap.add_argument( '-P', '--profile',
                     default=None,
                     help="Output profiling data to a file (default: None)" )
    ap.add_argument( 'tags', nargs="*",
                     help="Any tags, their type (default: INT), and number (default: 1), eg: tag=INT[1000]")

    args			= ap.parse_args( argv )

    # Deduce interface:port address to bind, and correct types (default is address, above)
    bind			= args.address.split(':')
    assert 1 <= len( bind ) <= 2, "Invalid --address [<interface>]:[<port>}: %s" % args.address
    bind			= ( str( bind[0] ) if bind[0] else defaults.address[0],
                                    int( bind[1] ) if len( bind ) > 1 and bind[1] else defaults.address[1] )

    # Set up logging level (-v...) and --log <file>
    levelmap 			= {
        0: logging.WARNING,
        1: logging.NORMAL,
        2: logging.DETAIL,
        3: logging.INFO,
        4: logging.DEBUG,
        }
    cpppo.log_cfg['level']	= ( levelmap[args.verbose] 
                                    if args.verbose in levelmap
                                    else logging.DEBUG )

    # Chain any provided idle_service function with log rotation; these may (also) consult global
    # signal flags such as logrotate_request, so execute supplied functions before logrotate_perform
    idle_service		= [ idle_service ] if idle_service else []
    if args.log:
        # Output logging to a file, and handle UNIX-y log file rotation via 'logrotate', which sends
        # signals to indicate that a service's log file has been moved/renamed and it should re-open
        cpppo.log_cfg['filename']= args.log
        signal.signal( signal.SIGHUP, logrotate_request )
        idle_service.append( logrotate_perform )

    logging.basicConfig( **cpppo.log_cfg )

    # Load config file(s), if not disabled, into the device.Object class-level 'config_loader'.
    if not args.no_config:
        loaded			= device.Object.config_loader.read( defaults.config_files + ( args.config or [] ) )
        logging.normal( "Loaded config files: %r", loaded )

    # Pull out a 'server.control...' supplied in the keywords, and make certain it's a
    # cpppo.apidict.  We'll use this to transmit control signals to the server thread.  Set the
    # current values to sane initial defaults/conditions.
    if 'server' in kwds:
        assert 'control' in kwds['server'], "A 'server' keyword provided without a 'control' attribute"
        srv_ctl			= cpppo.dotdict( kwds.pop( 'server' ))
        assert isinstance( srv_ctl['control'], cpppo.apidict ), "The server.control... must be a cpppo.apidict"
        log.detail( "External server.control in object %s", id( srv_ctl['control'] ))
    else:
        srv_ctl.control		= cpppo.apidict( timeout=defaults.timeout )
        log.detail( "Internal server.control in object %s", id( srv_ctl['control'] ))

    srv_ctl.control['done']	= False
    srv_ctl.control['disable']	= False
    srv_ctl.control.setdefault( 'latency', defaults.latency )

    # Global options data.  Copy any remaining keyword args supplied to main().  This could
    # include an alternative enip_process, for example, instead of defaulting to logix.process.
    options.update( kwds )

    # Specify a response delay.  The options.delay is another dotdict() layer, so it's attributes
    # (eg. .value, .range) are available to the web API for manipulation.  Therefore, they can be
    # set to arbitrary values at random times!  However, the type will be retained.
    def delay_range( *args, **kwds ):
        """If a delay.range like ".1-.9" is specified, then change the delay.value every second to something
        in that range."""
        assert 'delay' in kwds and 'range' in kwds['delay'] and '-' in kwds['delay']['range'], \
            "No delay=#-# specified"
        log.normal( "Delaying all responses by %s seconds", kwds['delay']['range'] )
        while True:
            # Once we start, changes to delay.range will be re-evaluated each loop
            time.sleep( 1 )
            try:
                lo,hi		= map( float, kwds['delay']['range'].split( '-' ))
                kwds['delay']['value'] = random.uniform( lo, hi )
                log.info( "Mutated delay == %g", kwds['delay']['value'] )
            except Exception as exc:
                log.warning( "No delay=#[.#]-#[.#] range specified: %s", exc )

    options.delay		= cpppo.dotdict()
    try:
        options.delay.value	= float( args.delay )
        log.normal( "Delaying all responses by %r seconds" , options.delay.value )
    except:
        assert '-' in args.delay, \
            "Unrecognized --delay=%r option" % args.delay
        # A range #-#; set up a thread to mutate the option.delay.value over the .range
        options.delay.range	= args.delay
        options.delay.value	= 0.0
        mutator			= threading.Thread( target=delay_range, kwargs=options )
        mutator.daemon		= True
        mutator.start()

    # Create all the specified tags/Attributes.  The enip_process function will (somehow) assign the
    # given tag name to reference the specified Attribute.  We'll define an Attribute to print
    # I/O if args.print is specified; reads will only be logged at logging.NORMAL and above.
    class Attribute_print( attribute_class ):
        def __getitem__( self, key ):
            value		= super( Attribute_print, self ).__getitem__( key )
            if log.isEnabledFor( logging.NORMAL ):
                print( "%20s[%5s-%-5s] == %s" % (
                    self.name, 
                    key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                    key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
                    value ))
            return value

        def __setitem__( self, key, value ):
            super( Attribute_print, self ).__setitem__( key, value )
            print( "%20s[%5s-%-5s] <= %s" % (
                self.name, 
                key.indices( len( self ))[0]   if isinstance( key, slice ) else key,
                key.indices( len( self ))[1]-1 if isinstance( key, slice ) else key,
                value ))

    for t in args.tags:
        tag_name, rest		= t, ''
        if '=' in tag_name:
            tag_name, rest	= tag_name.split( '=', 1 )
        tag_type, rest		= rest or 'INT', ''
        tag_size		= 1
        if '[' in tag_type:
            tag_type, rest	= tag_type.split( '[', 1 )
            assert ']' in rest, "Invalid tag; mis-matched [...]"
            tag_size, rest	= rest.split( ']', 1 )
        assert not rest, "Invalid tag specified; expected tag=<type>[<size>]: %r" % t
        tag_type		= str( tag_type ).upper()
        typenames		= {
            "BOOL":	( parser.BOOL,	0 ),
            "INT":	( parser.INT,	0 ),
            "DINT":	( parser.DINT,	0 ),
            "SINT":	( parser.SINT,	0 ),
            "REAL":	( parser.REAL,  0.0 ),
            "SSTRING":	( parser.SSTRING, '' ),
            "STRING":	( parser.STRING, '' ),
        }
        assert tag_type in typenames, "Invalid tag type; must be one of %r" % list( typenames )
        tag_class,tag_default	= typenames[tag_type]
        try:
            tag_size		= int( tag_size )
        except:
            raise AssertionError( "Invalid tag size: %r" % tag_size )

        # Detect specific CIP Class, Instance and Attribute addressing pre-defined for a Tag.  If it
        # exists, this Class, Instance and Attribute will be used. Otherwise, we'll create it.
        # Allow tags to specify down to an element.  Historically, we always created and sent the
        # Attribute instance, and expected the enip_srv --> enip_process complex to assign it an
        # (arbitrary) address.  However, we can now specify Tag@cls/ins/att[elm], so each Tag may
        # actually indicate an existing Attribute.  So, create and send an Attribute for plain Tag,
        # but send address, type and size info for each addressed tag, and let the back-end find
        # and/or create the appropriate Attribute(s).
        tag_address		= None
        if '@' in tag_name:
            tag_name,tag_address= tag_name.split( '@', 1 )

        # If a specific CIP address was specified for this Tag, find it and/or create it; otherwise,
        # just pass it thru, and let the underlying enip_srv --> enip_process deal with it.  We'll
        # let a Tag to be specified down to an attribute, or a single element; allows either
        # @c/i/a/e or @c/i/a[e] format.  We always find/create the Attribute.
        path,attribute		= None,None
        if tag_address:
            # Resolve the @cls/ins/att, and optionally [elm] or /elm
            segments,elm,cnt	= device.parse_path_elements( '@'+tag_address )
            assert not cnt or cnt == 1, \
                "A Tag may be specified to indicate a single element: %s" % ( tag_address )
            path		= {'segment': segments}
            cls,ins,att		= device.resolve( path, attribute=True )
            assert ins > 0, "Cannot specify the Class' instance for a tag's address"
            #elm		= device.resolve_element( path ) # TODO: support element-level tags
            # Look thru defined tags for one assigned to same cls/ins/att (maybe different elm);
            # must be same type/size.
            for tn,te in dict.items( tags ):
                if not te['path']:
                    continue		# Ignore tags w/o pre-defined path...
                if device.resolve( te['path'], attribute=True ) == (cls,ins,att):
                    assert te.attribute.parser.__class__ is tag_class and len( te.attribute ) == tag_size, \
                        "Incompatible Attribute types for tags %r and %r" % ( tn, tag_name )
                    attribute	= te.attribute
                    break
            '''
            instance		= device.lookup( cls, ins )
            if not instance:
                # Create an Object-derived class w/ the appropriate class_id.  Find the existing
                # meta-class for this class number, and use it's class; otherwise, whip one up
                class_ins_0	= device.lookup( cls, 0 )
                if class_ins_0:
                    class_type	= class_ins_0.__class__
                else:
                    class_type	= type( 'Class 0x%04X' % cls, (device.Object,), {'class_id': cls} )
                instance	= class_type( instance_id=ins )
            attribute		= device.lookup( cls, ins, att )
            '''
        if not attribute:
            # No Attribute found
            attribute		= ( Attribute_print if args.print else attribute_class )(
                tag_name, tag_class, default=( tag_default if tag_size == 1 else [tag_default] * tag_size ))
            '''
            if tag_address:
                # We're doing the Tag --> cls/ins/att assignment, and it didn't exist.  Place it in
                # the Instance.
                instance.attribute[str(att)] \
				= attribute
            '''
        '''
        if tag_address:
            # A Tag@1/2/3 address was specified, and we have an Instance (perhaps just freshly
            # created), and (now) have an Attribute.  Point this tag at this address.
            device.redirect_tag( tag_name, {'class': cls, 'instance': ins, 'attribute': att })
        '''

        # Ready to create the tag and its Attribute (and error code to return, if any).  If tag_size
        # is 1, it will be a scalar Attribute.  Since the tag_name may contain '.', we don't want
        # the normal dotdict.__setitem__ resolution to parse it; use plain dict.__setitem__.
        log.normal( "Creating tag: %-14s%-10s %10s[%4d]", tag_name, '@'+tag_address if tag_address else '',
                    attribute.parser.__class__.__name__, len( attribute ) )
        tag_entry		= cpppo.dotdict()
        tag_entry.attribute	= attribute	# The Attribute (may be shared by multiple tags)
        tag_entry.path		= path		# Desired Attribute path (may include element), or None
        tag_entry.error		= 0x00
        dict.__setitem__( tags, tag_name, tag_entry )


    # Use the Logix simulator and all the basic required default CIP message processing classes by
    # default (unless some other one was supplied as a keyword options to main(), loaded above into
    # 'options').  This key indexes an immutable value (not another dotdict layer), so is not
    # available for the web API to report/manipulate.  By default, we'll specify no route_path, so
    # any request route_path will be accepted.  Otherwise, we'll create a UCMM-derived class with
    # the specified route_path, which will filter only requests w/ the correct route_path.
    # 
    # It is also logix.process that calls logix.setup, to automatically create non-existent tags.  If
    # using some other dialect, it may be necessary to set up all required CIP Objects, and any
    # Object/instance/attributes required by any defined tags, before starting the
    # network.server_main --> enip_srv --> enip_process complex.  If we detect explicit CIP
    # Object/instance/attribute addressing for a tag, we'll do that here.  This prevents the Logix
    # setup from just allocating new Attributes in the Logix Message Router object by default.
    options.setdefault( 'enip_process', logix.process )
    if identity_class:
        options.setdefault( 'identity_class', identity_class )
    assert not UCMM_class or not ( args.route_path or args.simple ), \
        "Specify either -S/--simple/--route-path, or a custom UCMM_class; not both"
    if args.route_path is not None or args.simple:
        # Must be JSON, eg. '[{,"port":<int>,"link":<int>/"<ip>"}]', or 'null'/'0'/'false' to
        # explicitly specify no route_path accepted (must be empty in request).  Can only get in
        # here with a --route-path=0/false/[], or -S|--simple, which implies a --route-path=false
        # (no routing Unconnected Send accepted, eg. as for a non-routing CIP device such as
        # MicroLogix, AB PowerFlex AC drive controller, ...).
        class UCMM( ucmm.UCMM ): # class name defines config section: [UCMM]
            route_path		= device.parse_route_path( args.route_path ) if args.route_path else False
        if UCMM.route_path:
            assert len( UCMM.route_path ) == 1, \
                "route_path: must be JSON null/0/false, or a single [port/link], not: %r" % (
                    UCMM.route_path )
        UCMM_class		= UCMM
    if UCMM_class:
        options.setdefault( 'UCMM_class', UCMM_class )
    if message_router_class:
        options.setdefault( 'message_router_class', message_router_class )
    if connection_manager_class:
        options.setdefault( 'connection_manager_class', connection_manager_class )

    # The Web API

    # Deduce web interface:port address to bind, and correct types (default is address, above).
    # Default to the same interface as we're bound to, port 80.  We'll only start if non-empty --web
    # was provided, though (even if it's just ':', to get all defaults).  Usually you'll want to
    # specify at least --web :[<port>].
    http			= args.web.split( ':', 1 )
    assert 1 <= len( http ) <= 2, "Invalid --web [<interface>][:<port>]: %s" % args.web
    http			= ( str( http[0] ) if http[0] else bind[0],
                                    int( http[1] ) if len( http ) > 1 and http[1] else 80 )


    if args.web:
        assert 'web' in sys.modules, "Failed to import web API module; --web option not available.  Run 'pip install web.py'"
        logging.normal( "EtherNet/IP Simulator Web API Server: %r" % ( http, ))
        webserver		= threading.Thread( target=web_api, kwargs={'http': http} )
        webserver.daemon	= True
        webserver.start()

        
    # The EtherNet/IP Simulator.  Pass all the top-level options keys/values as keywords, and pass
    # the entire tags dotdict as a tags=... keyword.  The server_main server.control signals (.done,
    # .disable) are also passed as the server= keyword.  We are using an cpppo.apidict with a long
    # timeout; this will block the web API for several seconds to allow all threads to respond to
    # the signals delivered via the web API.
    logging.normal( "EtherNet/IP Simulator: %r" % ( bind, ))
    kwargs			= dict( options, latency=defaults.latency, size=args.size, tags=tags, server=srv_ctl )

    tf				= network.server_thread
    tf_kwds			= dict()
    if args.profile:
        tf			= network.server_thread_profiling
        tf_kwds['filename']	= args.profile

    disabled			= False	# Recognize toggling between en/disabled
    while not srv_ctl.control.done:
        if not srv_ctl.control.disable:
            if disabled:
                logging.detail( "EtherNet/IP Server enabled" )
                disabled= False
            network.server_main( address=bind, target=enip_srv, kwargs=kwargs,
                                 idle_service=lambda: map( lambda f: f(), idle_service ),
                                 udp=args.udp, tcp=args.tcp, thread_factory=tf, **tf_kwds )
        else:
            if not disabled:
                logging.detail( "EtherNet/IP Server disabled" )
                disabled= True
            time.sleep( defaults.latency )            # Still disabled; wait a bit

    return 0
