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
#   $ docker run /bin/bash
#
#     Manually run any cpppo-based service; a simple simulated Logix controller for example:
#
#   $ docker run -p 44818:44818 -d cpppo/cpppo python -m cpppo.server.enip SCADA=dint[1000]
#
#     Build a new image (or, better yet, use the index.docker.io automatic build facilities):
#
#   $ docker build -t cpppo/cpppo .			# or: 'make update' in ../..
#   $ docker push
#
FROM		cpppo/base
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
RUN		apt-get -y install python python-pip; apt-get clean
RUN		pip install cpppo
