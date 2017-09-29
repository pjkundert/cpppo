
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
# cpppo.server.enip.weather
# 
# Access a Tag-named location's current temperature via EtherNet/IP.
# 
#     $ python -m cpppo.server.enip.weather London=REAL &
#     $ python -m cpppo.server.enip.client --print London
#               London              == [15.319999694824219]: 'OK'
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

import sys, logging, json
try: # Python2
    from urllib2 import urlopen
    from urllib import urlencode
except ImportError: # Python3
    from urllib.request import urlopen
    from urllib.parse import urlencode

from cpppo.server.enip import device, REAL
from cpppo.server.enip.main import main

class Attribute_weather( device.Attribute ):
    OPT 			= {
        "appid": "078b5bd46e99c890482fc1252e9208d5",
        "units": "metric",
        "mode":	 "json",
    }
    URI				= "http://api.openweathermap.org/data/2.5/weather"

    def url( self, **kwds ):
        """Produce a url by joining the class' URI and OPTs with any keyword parameters"""
        return self.URI + "?" + urlencode( dict( self.OPT, **kwds ))

    def __getitem__( self, key ):
        """Obtain the temperature of the city's matching our Attribute's name, convert
        it to an appropriate type; return a value appropriate to the request."""
        try:
            # eg. "http://api.openweathermap.org/...?...&q=City Name"
            data		= urlopen( self.url( q=self.name )).read()
            if type( data ) is not str: # Python3 urlopen.read returns bytes
                data		= data.decode( 'utf-8' )
            weather		= json.loads( data )
            assert weather.get( 'cod' ) == 200 and 'main' in weather, \
                weather.get( 'message', "Unknown error obtaining weather data" )
            cast		= float if isinstance( self.parser, REAL ) else int
            temperature		= cast( weather['main']['temp'] )
        except Exception as exc:
            logging.warning( "Couldn't get temperature for %s via %r: %s",
                             self.name, self.url( q=self.name ), exc )
            raise
        return [ temperature ] if self._validate_key( key ) is slice else temperature

    def __setitem__( self, key, value ):
        raise Exception( "Changing the weather isn't that easy..." )

sys.exit( main( attribute_class=Attribute_weather ))
