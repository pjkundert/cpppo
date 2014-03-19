# Set the docker daemon's open file limit to the system maximum
ulimit -n $( sysctl --values fs.file-max )
