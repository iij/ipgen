# ipgen

<img width="542" alt="ipgen-screenshot" src="https://github.com/iij/ipgen/assets/1812064/55bf0f31-e2e9-4682-b0af-2817cd57bb81">


ipgen is an Interactive Packet GENerator.

It is implemented using fast I/O frameworks like netmap and AF_XDP.
It can interactively output packets of various sizes and rates, and measure how many have been dropped.


## Features

- Packet generation utilizing fast I/O frameworks
  - netmap on FreeBSD
  - AF_XDP on Linux
- Benchmarking based on RFC 2544
- Curses based interactive UI
- Packet pacing based on H/W feature (kernel patch required)
- Scenario based packet generation via a script
- Web based traffic viewer
- Flow list based packet generation for RSS


## Supported OSes and drivers

- FreeBSD 13 and 14
  - Drivers that support netmap should work
  - em, igb, ixg and ixl are tested
- Ubuntu Linux 22.04 and Fedora Linux 39
  - Drivers that support AF_XDP should work
  - igb and ixgbe are tested

## Build

### FreeBSD

```
pkg install gmake perl libevent

git clone git@github.com:iij/ipgen.git
cd ipgen
gmake depend && gmake && sudo gmake install
```

### Linux

```
# Ubuntu
apt install libbsd-dev clang libssl-dev libevent-dev libbpf-dev bmake
# Fedora
dnf install bmake libevent-devel libxdp-devel libbpf-devel openssl-devel clang libbsd-devel ncurses-devel

git clone https://github.com/iij/ipgen.git
cd ipgen
make depend && make && sudo make install
```

### Packet Pacing and Kernel patches

ipgen can be used with stock kernels of FreeBSD and Linux.
However, it packet generation is bursty, i.e., it tries to send
packets at once as much as possible.
The behavior may be undesired for DUT.

Modern network interfaces support packet pacing features, e.g., IPG and PAP.
Unfortunately, the features are not available on stock kernels and
you need to patch a used driver if you want to use the feature.

The `patch/` directory contains some patches for the features.


## Caveat

On linux, ipgen with AF_XDP uses only the 1st hardware queue on a network
adapter, so if the network adapter uses multiple hardware queues
ipgen with AF_XDP doesn't work correctly.

You can check if your network adapter, say `eth0`, uses
multiple queues by `ethtool -l eth0`.
If so you can change the number of using queues to just one by:

```
ethtool -L eth0 combined 1
```

# Usage

Please refer to the following presentation materials.

ipgen: Interactive Packet Generator for performance measurement
- in English https://github.com/iij/ipgen/wiki/materials/ipgen.pdf
- in Japanese https://github.com/iij/ipgen/wiki/materials/ipgen_ja.pdf

