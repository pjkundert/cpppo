# -*- mode: conf -*-
# cpppo/mongrel2 Dockerfile.
#
# DESCRIPTION
#     Support for EtherNet/IP (via cpppo) and Modbus/TCP (via pymodbus) PLC simulation, using
# Mongrel2's ZeroMQ WebSockets protocol as the underlying transport.
#
FROM		cpppo/cpppo
MAINTAINER	Perry Kundert "perry@hardconsulting.com"

RUN		apt-get install -y git libtool autoconf automake python-dev uuid-dev \
				sqlite3 libsqlite3-dev build-essential	\
		    && apt-get clean

RUN		git clone --branch master   https://github.com/zeromq/zeromq3-x.git  src/zeromq3-x \
		    && cd src/zeromq3-x					\
		    && ./autogen.sh					\
		    && ./configure					\
		    && make V=1						\
		    && make install					\
		    && ldconfig						\
		    && cd / && rm -rf src/zeromq3-x
RUN		git clone --branch 0.18     https://github.com/cython/cython.git     src/cython \
		    && cd src/cython					\
		    && python setup.py install				\
		    && cd / && rm -rf src/cython
RUN		git clone --branch v13.1.0  https://github.com/zeromq/pyzmq.git      src/pyzmq \
		    && cd src/pyzmq					\
		    && python setup.py configure --zmq=/usr/local	\
		    && python setup.py install				\
		    && cd / && rm -rf src/pyzmq
RUN		git clone --branch develop  https://github.com/zedshaw/mongrel2.git  src/mongrel2 \
		    && cd src/mongrel2					\
		    && make						\
		    && make install					\
		    && cd examples/python				\
		    && python setup.py install				\
		    && cd / && rm -rf src/mongrel2

# Typically supports applications providing remote access via HTTP, Modbus/TCP and EtherNet/IP, eg:
#EXPOSE		80 502 44818
