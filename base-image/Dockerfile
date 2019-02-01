# Compile the kernel and its modules for a specific version, with a specific configuration, and a special suffix
FROM moul/kernel-builder as kernel
ARG VERSION="4.14.55"
ARG EXTRA=""

# Fetch the latest changes and use the desired kernel version
RUN git fetch --tags && git checkout v${VERSION} && \
    make clean && make mrproper
# Get the desired config, and add the suffix
COPY Kconfig-${VERSION} .config

# Compile the kernel and install the modules to /lib/modules
RUN make EXTRAVERSION=${EXTRA} LOCALVERSION= oldconfig
RUN make EXTRAVERSION=${EXTRA} LOCALVERSION= -j16
RUN make EXTRAVERSION=${EXTRA} LOCALVERSION= modules_install

# As the kernel tree got "dirty" by the makefile change, rename the module path and create a tar file of it. Also copy over the kernel binary itself.
RUN mkdir -p /kernel && tar -cf /kernel/modules.tar /lib/modules
RUN cp vmlinux /kernel/vmlinux-${VERSION}${EXTRA}

# Copy over all artifacts from earlier builds, and extract them into the right places.
FROM scratch
# Add and extract this tar file to populate the whole rootfs of this container
ADD ubuntu.tar /
# Copy the /kernel directory which was present in the first stage of this multi-stage build and extract
COPY --from=0 /kernel /kernel
RUN tar -xf /kernel/modules.tar -C / --remove-files && \
    mv /kernel/vmlinux-* /boot/

# Set the root password and the default dns server
ARG DNS_SERVER="1.1.1.1"
RUN echo 'root:root' | chpasswd && \
    echo "nameserver ${DNS_SERVER}" > /etc/resolv.conf

# This is the same as "systemctl enable systemd-networkd"
RUN mkdir -p /etc/systemd/system/sockets.target.wants /etc/systemd/system/network-online.target.wants && \
    ln -sf /lib/systemd/system/systemd-networkd.service /etc/systemd/system/dbus-org.freedesktop.network1.service && \
    ln -sf /lib/systemd/system/systemd-networkd.service /etc/systemd/system/multi-user.target.wants/systemd-networkd.service && \
    ln -sf /lib/systemd/system/systemd-networkd.socket /etc/systemd/system/sockets.target.wants/systemd-networkd.socket && \
    ln -sf /lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service

# Add the sources.list file so that we can customize from where to get packages
COPY sources.list /etc/apt/
# Install some utilities, an ssh server and curl, which is needed in most installations
RUN apt-get update && \
    apt-get -y install --no-install-recommends \
        openssh-server \
        curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
