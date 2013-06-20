from distutils.core import setup

from misc import __version__

setup(
    name = "cpppo",
    version = __version__,
    requires = ['greenery', 'web'],
    packages = ['', 'server', 'server/enip'],
    package_dir = {'': '.'},
    extra_path = 'cpppo',
    author = "Perry Kundert",
    description = "Cpppo is a Communication Protocol Python Parser and Originator",
    license = "Dual License; GPLv3 and Proprietary",
    keywords = "cpppo protocol parser DFA",
    url = "https://github.com/pkundert/cpppo",
    classifiers = [
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator",
        "Topic :: Text Processing :: Filters"
    ],
)
