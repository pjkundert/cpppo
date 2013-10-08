# GNUmakefile for maintaining Docker images

all:
	@echo "Docker image updater"
	@echo "  update		Update the image from the Dockerfile; any date comments are advanced"
	@echo "  push		Push the image up to docker.io"

# Update this Docker image.  Force any lines ending in "# YYYY-MM-DD" to be
# change, to prevent re-use of cached Docker images.
update:
	sed -e "s/# [0-9Y][0-9Y][0-9Y][0-9Y]-[0-9M][0-9M]-[0-9D][0-9D]$$/# $$( date +%Y-%m-%d )/" -i~ Dockerfile
	docker build -t cpppo/scada .

# Push the Docker image up to docker.io
push:		update
	docker push cpppo/scada
