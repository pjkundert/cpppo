# cpppo/base Dockerfile.
#
# DESCRIPTION
#     Base image for all cpppo/* images.
#
# EXAMPLE
#
#     Build a new image.  Using the GNUmakefile 'update' target updates any '#
# YYYY-MM-DD' dated lines in the Dockerfile so that out-of-date cached images
# won't be used:
#
#   $ docker build -t cpppo/base cpppo/base		# or: 'make update' in ../..
#
FROM		stackbrew/debian:jessie
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
# Redirect http://.../debian to mirrors.kernel.org, but leave http://security.debian.org/
RUN		sed -e "s|http://[^[:space:]]*/debian|http://mirrors.kernel.org/debian|" -e "s|main$|main contrib non-free|" -i /etc/apt/sources.list
ENV		DEBIAN_FRONTEND noninteractive
RUN		apt-get update 				# 2014-02-19
RUN		apt-get -yu dist-upgrade; apt-get clean
