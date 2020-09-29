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
FROM		debian:buster
MAINTAINER	Perry Kundert "perry@hardconsulting.com"
# Redirect http://.../debian to CA mirror, but leave http://security.debian.org/
RUN		sed -e "s|http://[^[:space:]]*/debian|http://ftp.ca.debian.org/debian|" \
                    -e "s|main$|main contrib non-free|" -i /etc/apt/sources.list
ENV		DEBIAN_FRONTEND noninteractive
RUN		echo 'Dir::Cache { srcpkgcache ""; pkgcache ""; }'	\
                    > /etc/apt/apt.conf.d/02nocache			\
                  && (							\
                      for dir in doc man groff info lintian linda; do	\
                          echo "path-exclude /usr/share/$dir/*";	\
                      done;						\
                      echo "path-exclude /usr/share/locale/*";		\
                      echo "path-include /usr/share/locale/en*";	\
                  ) > /etc/dpkg/dpkg.cfg.d/01nodoc
RUN		apt-get update						\
                    && apt-get -yu dist-upgrade				\
                    && apt-get clean			# 2015-02-20
