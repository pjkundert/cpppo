# GNUmakefile for maintaining the cpppo Docker images

IMAGES		= cpppo/base	\
		  cpppo/cpppo	\
		  cpppo/scada

UPDATE		= 

all:
	@echo "Docker image updater"
	@echo "  update         Update the images from the Dockerfiles; any date comments are advanced"
	@echo "  push           Push the images up to index.docker.io"

# Update this Docker image.  Force any lines ending in "# YYYY-MM-DD" to be
# change, to prevent re-use of cached Docker images.
update:
	@for image in $(IMAGES); do			\
	    sed -e "s/# [0-9Y][0-9Y][0-9Y][0-9Y]-[0-9M][0-9M]-[0-9D][0-9D]$$/# $$( date +%Y-%m-%d )/" \
		-i~ $$image/Dockerfile;			\
	    docker build -t $$image $$image;		\
	done

# Push the Docker images up to docker.io
push:		update
	@for image in $(IMAGES); do			\
	    docker push $$image;			\
	done
