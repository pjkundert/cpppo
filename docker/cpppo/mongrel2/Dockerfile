# -*- mode: conf -*-
# cpppo/mongrel2 Dockerfile.
#
# DESCRIPTION
#     Support for EtherNet/IP (via cpppo) and Modbus/TCP (via pymodbus) PLC simulation, using
# Mongrel2's ZeroMQ WebSockets protocol as the underlying transport.
#
FROM		cpppo/cpppo
MAINTAINER	Perry Kundert "perry@hardconsulting.com"

RUN		apt-get -y install git libtool libtool-bin autoconf	\
			automake python-dev pypy uuid-dev ragel		\
			sqlite3 libsqlite3-dev build-essential		\
		  && apt-get clean
RUN		git clone --branch master				\
			https://github.com/zeromq/zeromq4-x.git		\
			src/zeromq4-x					\
		  && cd src/zeromq4-x					\
		  && ./autogen.sh					\
		  && ./configure					\
		  && make V=1						\
		  && make install					\
		  && ldconfig						\
		  && cd / && rm -rf src/zeromq4-x
RUN		git clone --branch 0.18					\
			https://github.com/cython/cython.git		\
			src/cython					\
		  && cd src/cython					\
		  && python setup.py install				\
		  && cd / && rm -rf src/cython
RUN		git clone --branch v14.1.1				\
			https://github.com/zeromq/pyzmq.git		\
			src/pyzmq					\
		  && cd src/pyzmq					\
		  && python setup.py configure --zmq=/usr/local		\
		  && python setup.py install				\
		  && cd / && rm -rf src/pyzmq
RUN		git clone --branch feature-max-sockets			\
			https://github.com/pjkundert/mongrel2.git	\
			src/mongrel2					\
		  && cd src/mongrel2					\
		  && sed -i -e 's/url = git:/url = http:/' .gitmodules	\
		  && make all install					\
		  && cd examples/python					\
		  && python setup.py install				\
		  && pypy setup.py install				\
		  && cd / && rm -rf src/mongrel2

# Ensure that alternative Pythons (eg. pypy) have access to all packages (not specifically installed for pypy)
ENV		PYTHONPATH /usr/local/lib/python2.7/dist-packages

# Typically supports applications providing remote access via HTTP, Modbus/TCP and EtherNet/IP, eg:
#EXPOSE		80 502 44818
