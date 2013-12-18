# -*- mode: conf -*-
# cpppo/mongrel2 Dockerfile.
#
# DESCRIPTION
#     Support for EtherNet/IP (via cpppo) and Modbus/TCP (via pymodbus) PLC simulation, using
# Mongrel2's ZeroMQ WebSockets protocol as the underlying transport.
#
FROM		cpppo/cpppo
MAINTAINER	Perry Kundert "perry@hardconsulting.com"

RUN		apt-get install -y git libtool autoconf automake python-dev uuid-dev sqlite3 libsqlite3-dev build-essential; apt-get clean
RUN		pip install pymodbus

RUN		mkdir -p src
RUN		git clone --branch master   git://github.com/zeromq/zeromq3-x.git  src/zeromq3-x
RUN		git clone --branch 0.18     git://github.com/cython/cython.git     src/cython
RUN		git clone --branch v13.1.0  git://github.com/zeromq/pyzmq.git      src/pyzmq
RUN		git clone --branch develop  git://github.com/zedshaw/mongrel2.git  src/mongrel2

RUN		cd src/zeromq3-x; ./autogen.sh; ./configure; make V=1; make install; ldconfig
RUN		cd src/cython; python setup.py install
RUN		cd src/pyzmq; python setup.py configure --zmq=/usr/local; python setup.py install
RUN		cd src/mongrel2; make; make install
RUN		cd src/mongrel2/examples/python; python setup.py install

# Typically supports applications providing remote access via HTTP, Modbus/TCP and EtherNet/IP, eg:
#EXPOSE		80 502 44818
