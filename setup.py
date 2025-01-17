from setuptools import setup, find_packages

import os
import sys
import glob
import fnmatch

HERE				= os.path.dirname( os.path.abspath( __file__ ))

__version__			= None
__version_info__		= None
exec( open( 'version.py', 'r' ).read() )

# Presently the pymodbus-based Modbus/TCP scripts are only compatible with Python2, as is web.py.
# So, make web.py and pymodbus requirements optional.  The argparse module wasn't included 'til
# Python 2.7, but is available for installation in prior versions.
console_scripts			= [
    'enip_server	= cpppo.server.enip.main:main',
    'enip_client	= cpppo.server.enip.client:main',
    'enip_get_attribute	= cpppo.server.enip.get_attribute:main',
]
if sys.version_info[0:2] < (3,0):
    console_scripts	       += [
        'modbus_sim	= cpppo.bin.modbus_sim:main',
        'modbus_poll	= cpppo.bin.modbus_poll:main',
    ]

entry_points			= {
    'console_scripts': 		console_scripts,
}

# Build the install options.  By default, only support EtherNet/IP CIP via IP networking

install_requires		= open( os.path.join( HERE, "requirements.txt" )).readlines()
if sys.version_info[0:2] < (2,7):
    install_requires.append( "argparse" )
if sys.version_info[0:2] < (3,0):
    install_requires.append( "configparser" )
    install_requires.append( "ipaddress" )
tests_require			= open( os.path.join( HERE, "requirements-tests.txt" )).readlines()
options_require			= [
    'modbus',		# Modbus TCP/RTU via pymodbus
    'logix',		# Alt. Logix I/O via pylogix
    'serial',
    'dev',
    'timestamp',
]
extras_require			= {
    option: list(
        # Remove whitespace, elide blank lines and comments
        ''.join( r.split() )
        for r in open( os.path.join( HERE, f"requirements-{option}.txt" )).readlines()
        if r.strip() and not r.strip().startswith( '#' )
    )
    for option in options_require
}
# Make python-slip39[all] install all extra (non-tests) requirements, excluding duplicates
extras_require['all']		= list( set( sum( extras_require.values(), [] )))

# Since setuptools is retiring tests_require, add it as another option (but not included in 'all')
extras_require['tests']		= tests_require


package_dir			= {
    "cpppo":			".",
    "cpppo/server":		"./server",
    "cpppo/server/enip":	"./server/enip",
    "cpppo/remote":		"./remote",
    "cpppo/history":		"./history",
    "cpppo/tools":		"./tools",
    "cpppo/bin":		"./bin",
}

long_description		= """\
Cpppo is used to create event-driven state machines which consume a stream
of input and generate a series of state changes, or an indication that no
progress is possible due to (for example) exhaustion of input symbols.

This is useful for creating parsers for complex grammars describing
languages, including binary computer protocols.

An example included with cpppo is an implementation of a subset of the
EtherNet/IP CIP language used by some industrial control equipment, such as
Rockwell's ControlLogix Controllers.  The cpppo.server.enip package can be used
to create Python programs which can parse requests in this protocol (eg. as a
server, to implement something like a simulated Controller) or originate
requests in this protocol (eg. as a client, sending commands to a Controller).

In addition, the ability to read, write and poll remote PLCs of
various types including Modbus/TCP is provided.
"""

classifiers			= [
    "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    "License :: Other/Proprietary License",
    "Programming Language :: Python :: 2",
    "Programming Language :: Python :: 3",
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Environment :: Console",
    "Environment :: Web Environment",
    "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
    "Topic :: Text Processing :: Filters"
]

setup(
    name			= "cpppo",
    version			= __version__,
    install_requires		= install_requires,
    tests_require		= tests_require,
    extras_require		= extras_require,
    packages			= package_dir.keys(),
    package_dir			= package_dir,
    zip_safe			= False,
    entry_points		= entry_points,
    author			= "Perry Kundert",
    author_email		= "perry@hardconsulting.com",
    description			= "Cpppo is a Communication Protocol Python Parser and Originator",
    long_description		= long_description,
    license			= "Dual License; GPLv3 and Proprietary",
    keywords			= "cpppo protocol parser DFA EtherNet/IP CIP",
    url				= "https://github.com/pjkundert/cpppo",
    classifiers			= classifiers,
)
