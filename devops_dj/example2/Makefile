.PHONY: docker-image build install build-image clean
ifeq ($(VER),)
        VER=latest
endif


docker-image: build-image nginx-image
	@echo ">>-> Compiling and building an image"

nginx-image:
	make -C nginx docker-image VER=$(VER)
build:
	@echo ">>->Running a go build in this directory"
install:
	@echo ">>-> Running a GO install in this directory"

build-image:
	@echo ">>-> This TARGET will build on docker and create a docker image"
	docker build -t brandsecure-backend:$(VER) .

