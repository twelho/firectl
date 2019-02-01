VERSION=18.04
REVISION=1
TAG=${VERSION}-${REVISION}
REGISTRY=luxas
KERNEL_VERSION=4.14.55
KERNEL_EXTRA=

all: build
build:
	# Ideally, this could be done in the multi-stage Dockerfile. However, there is no support for privileged builds, and
	# debootstrap does a chroot syscall which requires root privileges :/
	# Install a new Ubuntu root filesystem for the desired distro in a temp directory (here /mnt) and create a tar file
	[ -f rootfs-${VERSION}.tar ] || docker run -it --privileged -v $(shell pwd):/out ubuntu:${VERSION} /bin/bash -c "\
		source /etc/os-release && \
		apt-get update -y && apt-get install debootstrap -y && \
		debootstrap --arch=amd64 \$$UBUNTU_CODENAME /mnt http://archive.ubuntu.com/ubuntu/ && \
		cd /mnt && tar -cf /out/rootfs-${VERSION}.tar ."
	# Build the kernel and the rest of the VM base OS image
	docker build \
		--build-arg KERNEL_VERSION=${KERNEL_VERSION} \
		--build-arg KERNEL_EXTRA=${KERNEL_EXTRA} \
		--build-arg UBUNTU_VERSION=${VERSION} \
		-t ${REGISTRY}/ubuntu-base:${TAG} .
