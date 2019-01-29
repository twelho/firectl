DISTRO="bionic"
REVISION="1"
TAG="18.04.${REVISION}"
REGISTRY=luxas

all: build
build:
	# Ideally, this could be done in the multi-stage Dockerfile. However, there is no support for privileged builds, and
	# debootstrap does a chroot syscall which requires root privileges :/
	# Install a new Ubuntu root filesystem for the desired distro in a temp directory (here /mnt) and create a tar file
	[ -f ubuntu.tar ] || docker run -it --privileged -v $(shell pwd):/out ubuntu:${DISTRO} /bin/bash -c "\
		apt-get update -y && apt-get install debootstrap -y && \
		debootstrap --arch=amd64 ${DISTRO} /mnt http://archive.ubuntu.com/ubuntu/ && \
		cd /mnt && tar -cf /out/ubuntu.tar ."
	# Build the kernel and the rest of the VM base OS image
	docker build -t ${REGISTRY}/ubuntu-base:${TAG} .
