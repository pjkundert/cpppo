# -*- mode: conf -*-
FROM		cpppo/cpppo
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
RUN		apt-get install -y git
RUN		mkdir src
RUN		cd src; git clone git://github.com/zeromq/zeromq3-x.git;	cd zeromq3-x;	git checkout master
RUN		cd src; git clone git://github.com/cython/cython.git;		cd cython;	git checkout 0.18
RUN		cd src; git clone git://github.com/zeromq/pyzmq.git;		cd pyzmq;	git checkout v13.1.0
RUN		cd src; git clone git://github.com/zedshaw/mongrel2.git;	cd mongrel2;	git checkout develop
RUN		apt-get install -y libtool autoconf automake python-dev uuid-dev sqlite3 libsqlite3-dev build-essential
RUN		cd src/zeromq3-x; ./autogen.sh; ./configure; make V=1; make install; ldconfig
RUN		cd src/cython; python setup.py install
RUN		cd src/pyzmq; python setup.py configure --zmq=/usr/local; python setup.py install
RUN		cd src/mongrel2; make; make install
RUN		cd src/mongrel2/examples/python; python setup.py install

#EXPOSE		44818
#ENTRYPOINT	[ "python", "-m", "cpppo.server.enip" ]
#CMD		[ "SCADA=dint[1000]" ]
