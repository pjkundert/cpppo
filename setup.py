from setuptools import setup
import os, sys

here = os.path.abspath( os.path.dirname( __file__ ))

__version__			= None
__version_info__		= None
exec( open( 'version.py', 'r' ).read() )

# Presently the pymodbus-based Modbus/TCP scripts are only compatible with Python2, as is web.py.
# So, make web.py and pymodbus requirements optional.  The argparse module wasn't included 'til
# Python 2.7, but is available for installation in prior versions.
console_scripts			= [
    'enip_server	= cpppo.server.enip.main:main',
    'enip_client	= cpppo.server.enip.client:main',
    'enip_getattr	= cpppo.server.enip.getattr:main',	# pending deprecation
    'enip_get_attribute	= cpppo.server.enip.get_attribute:main',
]
if sys.version_info[0:2] < (3,0):
    console_scripts	       += [
        'modbus_sim	= cpppo.bin.modbus_sim:main',
        'modbus_poll	= cpppo.bin.modbus_poll:main',
    ]

install_requires		= open( os.path.join( here, "requirements.txt" )).readlines()
if sys.version_info[0:2] < (2,7):
    install_requires.append( "argparse" )
if sys.version_info[0:2] < (3,0):
    install_requires.append( "configparser" )
    install_requires.append( "ipaddress" )
tests_require			= open( os.path.join( here, "requirements-optional.txt" )).readlines()

setup(
    name			= "cpppo",
    version			= __version__,
    tests_require		= tests_require,
    install_requires		= install_requires,
    packages			= [ 
        "cpppo",
        "cpppo/server",
        "cpppo/server/enip",
        "cpppo/remote",
        "cpppo/history",
        "cpppo/tools",
        "cpppo/bin",
    ],
    package_dir			= {
        "cpppo":		".", 
        "cpppo/server":		"./server",
        "cpppo/server/enip":	"./server/enip",
        "cpppo/remote":		"./remote",
        "cpppo/history":	"./history",
        "cpppo/tools":		"./tools",
        "cpppo/bin":		"./bin",
    },
    entry_points		= {
        'console_scripts': 	console_scripts,
    },
    include_package_data	= True,
    author			= "Perry Kundert",
    author_email		= "perry@hardconsulting.com",
    description			= "Cpppo is a Communication Protocol Python Parser and Originator",
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
""",
    license			= "Dual License; GPLv3 and Proprietary",
    keywords			= "cpppo protocol parser DFA EtherNet/IP CIP",
    url				= "https://github.com/pjkundert/cpppo",
    classifiers			= [
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Text Processing :: Filters"
    ],
)
