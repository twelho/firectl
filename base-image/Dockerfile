# Compile the kernel and its modules for a specific version, with a specific configuration, and a special suffix
FROM luxas/kernel-builder:2019-02-01
ARG KERNEL_VERSION=""
ARG KERNEL_EXTRA=""

# Fetch the latest changes and use the desired kernel version
RUN git fetch --tags && git checkout v${KERNEL_VERSION} && \
    make clean && make mrproper
# Get the desired config, and add the suffix
COPY Kconfig-${KERNEL_VERSION} .config

# Compile the kernel and install the modules to /lib/modules
RUN make EXTRAVERSION=${KERNEL_EXTRA} LOCALVERSION= oldconfig
RUN make EXTRAVERSION=${KERNEL_EXTRA} LOCALVERSION= -j16
RUN make EXTRAVERSION=${KERNEL_EXTRA} LOCALVERSION= modules_install

# Make a tar file of the modules and copy them and the kernel binary and config over to /kernel, which will be used in the next step
RUN mkdir -p /kernel && tar -cf /kernel/modules.tar /lib/modules
RUN cp vmlinux /kernel/vmlinux-${KERNEL_VERSION}${KERNEL_EXTRA} && cp .config /kernel/Kconfig-${KERNEL_VERSION}

# Copy over all artifacts from earlier builds, and extract them into the right places.
FROM scratch
ARG KERNEL_VERSION=""
ARG KERNEL_EXTRA=""
ARG UBUNTU_VERSION=""
# Add and extract this tar file to populate the whole rootfs of this container
#RUN ls -la /etc/resolv.conf
ADD rootfs-${UBUNTU_VERSION}.tar.gz /
# Copy the /kernel directory which was present in the first stage of this multi-stage build and extract the contents
COPY --from=0 /kernel /kernel
RUN tar -xf /kernel/modules.tar -C / --remove-files && \
    mv /kernel/vmlinux-${KERNEL_VERSION}${KERNEL_EXTRA} /boot/ && \
    ln -s /boot/vmlinux-${KERNEL_VERSION}${KERNEL_EXTRA} /boot/vmlinux && \
    mv /kernel/Kconfig-* /boot/

# Set the root password and the default dns server
#ARG DNS_SERVER="1.1.1.1"
RUN echo 'root:root' | chpasswd
# && \
#    echo "nameserver ${DNS_SERVER}" > /etc/resolv.conf

# This is the same as "systemctl enable systemd-networkd"
RUN mkdir -p /etc/systemd/system/sockets.target.wants /etc/systemd/system/network-online.target.wants && \
    ln -sf /lib/systemd/system/systemd-networkd.service /etc/systemd/system/dbus-org.freedesktop.network1.service && \
    ln -sf /lib/systemd/system/systemd-networkd.service /etc/systemd/system/multi-user.target.wants/systemd-networkd.service && \
    ln -sf /lib/systemd/system/systemd-networkd.socket /etc/systemd/system/sockets.target.wants/systemd-networkd.socket && \
    ln -sf /lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service

# This systemd service handles fixing the resolv.conf symlink after Docker removes it
COPY update-resolvconf.service /etc/systemd/system
RUN ln -sf /etc/systemd/system/update-resolvconf.service /etc/systemd/system/multi-user.target.wants/update-resolvconf.service

# Add the sources.list file so that we can customize from where to get packages
COPY sources.list /etc/apt/
RUN sed -e "s|UBUNTU_CODENAME|$(grep UBUNTU_CODENAME /etc/os-release | cut -d= -f2)|g" -i /etc/apt/sources.list
# Install some utilities such as an ssh server and curl which are needed in most installations
# The container itself is in a very ordered state, we need to get entropy from the HWRNG using rng-tools
RUN apt-get update && \
    apt-get -y install --no-install-recommends \
      bash-completion \
      command-not-found \
      openssh-server \
      rng-tools \
      nano \
      curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Generate an ssh key for root to be copied out with the improved firectl
RUN     mkdir -p ~/.ssh && cd ~/.ssh && \
        ssh-keygen -t ed25519 -N "" -f vm_ed25519 && \
        mv vm_ed25519.pub authorized_keys

# The handler in this .bash_profile rescans the terminal size after each
# command, so tools like less and htop are actually usable in the VM
COPY .bash_profile /root/
