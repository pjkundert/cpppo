# cpppo/cpppo Dockerfile.
#
# DESCRIPTION
#     Base image for cpppo Dockerfiles.  Use this Docker image in a 'FROM cpppo/cpppo' line
# when building other Dockerfiles based on cpppo.
#
# EXAMPLE
#
#     Come on in and look around:
#
#   $ docker -i -t run /bin/bash
#
#     Manually run any cpppo-based service; a simple simulated Logix controller for example:
#
#   $ docker run -p 44818:44818 -d cpppo/cpppo python3 -m cpppo.server.enip SCADA=dint[1000]
#
FROM		cpppo/base
LABEL		maintainer="perry@dominionrnd.com"
RUN		apt-get -y install python3 python3-pip		\
		    && apt-get clean			# 2015-01-26
RUN		pip3 install cpppo
