VERSION=18.04
REVISION=1
TAG=${VERSION}-${REVISION}
REGISTRY=luxas
KERNEL_VERSION=4.14.55
KERNEL_EXTRA=
UID_GID=$(shell id -u):$(shell id -g)

all: build-rootfs build-image-kernel

build-rootfs:
	# Ideally, this could be done in the multi-stage Dockerfile. However, there is no support for privileged builds, and
	# debootstrap does a chroot syscall which requires root privileges :/
	# Install a new Ubuntu root filesystem for the desired distro in a temp directory (here /mnt) and create a tar file
	# Use gzip compression for the tarfile to save space, the servers don't have any excess
	[ -f "rootfs-${VERSION}.tar" ] || \
		docker run -it --rm --privileged -v "$(shell pwd):/out" "ubuntu:${VERSION}" /bin/bash -c "\
			source /etc/os-release && \
			apt-get update -y && apt-get install debootstrap -y && \
			debootstrap --arch=amd64 \$$UBUNTU_CODENAME /mnt http://fi.archive.ubuntu.com/ubuntu/ && \
			cd /mnt && tar -zcf /out/rootfs-${VERSION}.tar.gz . && \
			chown ${UID_GID} /out/rootfs-${VERSION}.tar.gz"

build-image-kernel:
	# Build the kernel and the rest of the VM base OS image
	docker build \
		--build-arg KERNEL_VERSION=${KERNEL_VERSION} \
		--build-arg KERNEL_EXTRA=${KERNEL_EXTRA} \
		--build-arg UBUNTU_VERSION=${VERSION} \
		-t ${REGISTRY}/ubuntu-base:${TAG} .

clean:
	rm -rf rootfs-*.tar.gz
