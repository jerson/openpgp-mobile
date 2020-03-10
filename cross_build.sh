#!/usr/bin/env sh

GOOS=${GOOS:-linux}
GOARCH=${GOARCH:-amd64}
GOVERSION=${GOVERSION:-1.14.0}
BINDING_FILE=${BINDING_FILE:-shared.so}
TAG=${TAG:-main}
DOCKER_IMAGE_CROSS=docker.elastic.co/beats-dev/golang-crossbuild:${GOVERSION}

docker run -it --rm -v $PWD:/app -w /app \
	-e CGO_ENABLED=1 -e BINDING_FILE=${GOOS}_${GOARCH}_${BINDING_FILE} \
	${DOCKER_IMAGE_CROSS}-${TAG} \
	--build-cmd "make binding" -p "${GOOS}/${GOARCH}"