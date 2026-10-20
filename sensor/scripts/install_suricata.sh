#!/usr/bin/env bash
# Owner: Adam — Install and configure Suricata on the Raspberry Pi 5.

# dirtysocs@raspberrypi:~ $ sudo apt update && sudo apt upgrade -y
# # [sudo] password for dirtysocs: 
# # Hit:1 http://deb.debian.org/debian trixie InRelease
# # Hit:2 http://deb.debian.org/debian trixie-updates InRelease 
# # Hit:3 http://deb.debian.org/debian-security trixie-security InRelease          
# # Hit:4 http://archive.raspberrypi.com/debian trixie InRelease                   
# # All packages are up to date.                                
# # The following packages were automatically installed and are no longer required:
# #   libfuse2t64  libqt5x11extras5
# # Use 'sudo apt autoremove' to remove them.

# # Summary:
# #   Upgrading: 0, Installing: 0, Removing: 0, Not Upgrading: 0

# dirtysocs@raspberrypi:~ $ sudo apt update --allow-releaseinfo-change
# # Hit:1 http://deb.debian.org/debian trixie InRelease
# # Hit:2 http://deb.debian.org/debian trixie-updates InRelease
# # Hit:3 http://deb.debian.org/debian-security trixie-security InRelease          
# # Hit:4 http://archive.raspberrypi.com/debian trixie InRelease                   
# # All packages are up to date.    
                           
# dirtysocs@raspberrypi:~ $ sudo apt install -y jq tcpdump
# # The following packages were automatically installed and are no longer required:
# #   libfuse2t64  libqt5x11extras5
# # Use 'sudo apt autoremove' to remove them.

# # Installing:
# #   jq  tcpdump

# # Installing dependencies:
# #   libjq1  libonig5

# # Summary:
# #   Upgrading: 0, Installing: 4, Removing: 0, Not Upgrading: 0
# #   Download size: 851 kB
# #   Space needed: 2,727 kB / 110 GB available

# # Get:1 http://deb.debian.org/debian trixie/main arm64 libonig5 arm64 6.9.9-1+b1 [181 kB]
# # Get:2 http://deb.debian.org/debian-security trixie-security/main arm64 libjq1 arm64 1.7.1-6+deb13u4 [152 kB]
# # Get:3 http://deb.debian.org/debian-security trixie-security/main arm64 jq arm64 1.7.1-6+deb13u4 [78.4 kB]
# # Get:4 http://deb.debian.org/debian trixie/main arm64 tcpdump arm64 4.99.5-2 [440 kB]
# # Fetched 851 kB in 1s (1,381 kB/s)
# # Selecting previously unselected package libonig5:arm64.
# # (Reading database ... 121380 files and directories currently installed.)
# # Preparing to unpack .../libonig5_6.9.9-1+b1_arm64.deb ...
# # Unpacking libonig5:arm64 (6.9.9-1+b1) ...
# # Selecting previously unselected package libjq1:arm64.
# # Preparing to unpack .../libjq1_1.7.1-6+deb13u4_arm64.deb ...
# # Unpacking libjq1:arm64 (1.7.1-6+deb13u4) ...
# # Selecting previously unselected package jq.
# # Preparing to unpack .../jq_1.7.1-6+deb13u4_arm64.deb ...
# # Unpacking jq (1.7.1-6+deb13u4) ...
# # Selecting previously unselected package tcpdump.
# # Preparing to unpack .../tcpdump_4.99.5-2_arm64.deb ...
# # Unpacking tcpdump (4.99.5-2) ...
# # Setting up tcpdump (4.99.5-2) ...
# # Setting up libonig5:arm64 (6.9.9-1+b1) ...
# # Setting up libjq1:arm64 (1.7.1-6+deb13u4) ...
# # Setting up jq (1.7.1-6+deb13u4) ...
# # Processing triggers for man-db (2.13.1-1) ...
# # Processing triggers for libc-bin (2.41-12+rpt1+deb13u4) ...

# dirtysocs@raspberrypi:~ $ sudo apt update
# # Hit:1 http://deb.debian.org/debian trixie InRelease
# # Hit:2 http://deb.debian.org/debian trixie-updates InRelease
# # Hit:3 http://deb.debian.org/debian-security trixie-security InRelease          
# # Hit:4 http://archive.raspberrypi.com/debian trixie InRelease                   
# # All packages are up to date.

# dirtysocs@raspberrypi:~ $ sudo apt install -y suricata
# # The following packages were automatically installed and are no longer required:
# #   libfuse2t64  libqt5x11extras5
# # Use 'sudo apt autoremove' to remove them.

# # Installing:
# #   suricata

# # Installing dependencies:
# #   armv8crc-support            librte-bus-vdev25  librte-net-bond25
# #   isa-support                 librte-eal25       librte-net25
# #   libevent-pthreads-2.1-7t64  librte-ethdev25    librte-pci25
# #   libhiredis1.1.0             librte-hash25      librte-rcu25
# #   libhtp2                     librte-ip-frag25   librte-ring25
# #   libmaxminddb0               librte-kvargs25    librte-sched25
# #   libnet1                     librte-log25       librte-telemetry25
# #   libnetfilter-log1           librte-mbuf25      libxdp1
# #   libnetfilter-queue1         librte-mempool25   suricata-update
# #   librte-bus-pci25            librte-meter25

# # Suggested packages:
# #   mmdb-bin  libtcmalloc-minimal4

# # Recommended packages:
# #   snort-rules-default

# # Summary:
# #   Upgrading: 0, Installing: 30, Removing: 0, Not Upgrading: 0
# #   Download size: 3,739 kB
# #   Space needed: 13.9 MB / 110 GB available

# # Get:1 http://deb.debian.org/debian trixie/main arm64 isa-support arm64 27 [7,312 B]
# # Get:2 http://deb.debian.org/debian trixie/main arm64 armv8crc-support arm64 27 [3,620 B]
# # Get:3 http://deb.debian.org/debian-security trixie-security/main arm64 libevent-pthreads-2.1-7t64 arm64 2.1.13-stable-1~deb13u1 [55.2 kB]
# # Get:4 http://deb.debian.org/debian trixie/main arm64 libhiredis1.1.0 arm64 1.2.0-6+b3 [48.5 kB]
# # Get:5 http://deb.debian.org/debian trixie/main arm64 libhtp2 arm64 1:0.5.50-1+deb13u1 [67.6 kB]
# # Get:6 http://deb.debian.org/debian trixie/main arm64 libmaxminddb0 arm64 1.12.2-1 [25.9 kB]
# # Get:7 http://deb.debian.org/debian trixie/main arm64 libnet1 arm64 1.3+dfsg-2 [51.4 kB]
# # Get:8 http://deb.debian.org/debian trixie/main arm64 libnetfilter-log1 arm64 1.0.2-4+b1 [12.7 kB]
# # Get:9 http://deb.debian.org/debian trixie/main arm64 libnetfilter-queue1 arm64 1.0.5-4+b1 [13.9 kB]
# # Get:10 http://deb.debian.org/debian trixie/main arm64 librte-log25 arm64 24.11.4-0+deb13u1 [24.0 kB]
# # Get:11 http://deb.debian.org/debian trixie/main arm64 librte-kvargs25 arm64 24.11.4-0+deb13u1 [18.0 kB]
# # Get:12 http://deb.debian.org/debian trixie/main arm64 librte-telemetry25 arm64 24.11.4-0+deb13u1 [26.9 kB]
# # Get:13 http://deb.debian.org/debian trixie/main arm64 librte-eal25 arm64 24.11.4-0+deb13u1 [146 kB]
# # Get:14 http://deb.debian.org/debian trixie/main arm64 librte-ring25 arm64 24.11.4-0+deb13u1 [20.2 kB]
# # Get:15 http://deb.debian.org/debian trixie/main arm64 librte-mempool25 arm64 24.11.4-0+deb13u1 [31.4 kB]
# # Get:16 http://deb.debian.org/debian trixie/main arm64 librte-mbuf25 arm64 24.11.4-0+deb13u1 [29.0 kB]
# # Get:17 http://deb.debian.org/debian trixie/main arm64 librte-meter25 arm64 24.11.4-0+deb13u1 [17.4 kB]
# # Get:18 http://deb.debian.org/debian trixie/main arm64 librte-net25 arm64 24.11.4-0+deb13u1 [21.9 kB]
# # Get:19 http://deb.debian.org/debian trixie/main arm64 librte-ethdev25 arm64 24.11.4-0+deb13u1 [114 kB]
# # Get:20 http://deb.debian.org/debian trixie/main arm64 librte-pci25 arm64 24.11.4-0+deb13u1 [17.8 kB]
# # Get:21 http://deb.debian.org/debian trixie/main arm64 librte-bus-pci25 arm64 24.11.4-0+deb13u1 [34.5 kB]
# # Get:22 http://deb.debian.org/debian trixie/main arm64 librte-bus-vdev25 arm64 24.11.4-0+deb13u1 [21.9 kB]
# # Get:23 http://deb.debian.org/debian trixie/main arm64 librte-rcu25 arm64 24.11.4-0+deb13u1 [22.1 kB]
# # Get:24 http://deb.debian.org/debian trixie/main arm64 librte-hash25 arm64 24.11.4-0+deb13u1 [45.6 kB]
# # Get:25 http://deb.debian.org/debian trixie/main arm64 librte-ip-frag25 arm64 24.11.4-0+deb13u1 [33.5 kB]
# # Get:26 http://deb.debian.org/debian trixie/main arm64 librte-sched25 arm64 24.11.4-0+deb13u1 [32.5 kB]
# # Get:27 http://deb.debian.org/debian trixie/main arm64 librte-net-bond25 arm64 24.11.4-0+deb13u1 [59.4 kB]
# # Get:28 http://deb.debian.org/debian trixie/main arm64 libxdp1 arm64 1.5.4-1 [55.4 kB]
# # Get:29 http://deb.debian.org/debian trixie/main arm64 suricata arm64 1:7.0.10-1+deb13u4 [2,617 kB]
# # Get:30 http://deb.debian.org/debian trixie/main arm64 suricata-update arm64 1.3.4-1+deb13u1 [64.7 kB]
# # Fetched 3,739 kB in 1s (2,853 kB/s)         
# # Preconfiguring packages ...
# # Selecting previously unselected package isa-support:arm64.
# # (Reading database ... 121418 files and directories currently installed.)
# # Preparing to unpack .../isa-support_27_arm64.deb ...
# # Unpacking isa-support:arm64 (27) ...
# # Setting up isa-support:arm64 (27) ...
# # Selecting previously unselected package armv8crc-support.
# # (Reading database ... 121424 files and directories currently installed.)
# # Preparing to unpack .../00-armv8crc-support_27_arm64.deb ...
# # Unpacking armv8crc-support (27) ...
# # Selecting previously unselected package libevent-pthreads-2.1-7t64:arm64.
# # Preparing to unpack .../01-libevent-pthreads-2.1-7t64_2.1.13-stable-1~deb13u1_ar
# # m64.deb ...
# # Unpacking libevent-pthreads-2.1-7t64:arm64 (2.1.13-stable-1~deb13u1) ...
# # Selecting previously unselected package libhiredis1.1.0:arm64.
# # Preparing to unpack .../02-libhiredis1.1.0_1.2.0-6+b3_arm64.deb ...
# # Unpacking libhiredis1.1.0:arm64 (1.2.0-6+b3) ...
# # Selecting previously unselected package libhtp2.
# # Preparing to unpack .../03-libhtp2_1%3a0.5.50-1+deb13u1_arm64.deb ...
# # Unpacking libhtp2 (1:0.5.50-1+deb13u1) ...
# # Selecting previously unselected package libmaxminddb0:arm64.
# # Preparing to unpack .../04-libmaxminddb0_1.12.2-1_arm64.deb ...
# # Unpacking libmaxminddb0:arm64 (1.12.2-1) ...
# # Selecting previously unselected package libnet1:arm64.
# # Preparing to unpack .../05-libnet1_1.3+dfsg-2_arm64.deb ...
# # Unpacking libnet1:arm64 (1.3+dfsg-2) ...
# # Selecting previously unselected package libnetfilter-log1:arm64.
# # Preparing to unpack .../06-libnetfilter-log1_1.0.2-4+b1_arm64.deb ...
# # Unpacking libnetfilter-log1:arm64 (1.0.2-4+b1) ...
# # Selecting previously unselected package libnetfilter-queue1:arm64.
# # Preparing to unpack .../07-libnetfilter-queue1_1.0.5-4+b1_arm64.deb ...
# # Unpacking libnetfilter-queue1:arm64 (1.0.5-4+b1) ...
# # Selecting previously unselected package librte-log25:arm64.
# # Preparing to unpack .../08-librte-log25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-log25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-kvargs25:arm64.
# # Preparing to unpack .../09-librte-kvargs25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-kvargs25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-telemetry25:arm64.
# # Preparing to unpack .../10-librte-telemetry25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-telemetry25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-eal25:arm64.
# # Preparing to unpack .../11-librte-eal25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-eal25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-ring25:arm64.
# # Preparing to unpack .../12-librte-ring25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-ring25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-mempool25:arm64.
# # Preparing to unpack .../13-librte-mempool25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-mempool25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-mbuf25:arm64.
# # Preparing to unpack .../14-librte-mbuf25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-mbuf25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-meter25:arm64.
# # Preparing to unpack .../15-librte-meter25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-meter25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-net25:arm64.
# # Preparing to unpack .../16-librte-net25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-net25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-ethdev25:arm64.
# # Preparing to unpack .../17-librte-ethdev25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-ethdev25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-pci25:arm64.
# # Preparing to unpack .../18-librte-pci25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-pci25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-bus-pci25:arm64.
# # Preparing to unpack .../19-librte-bus-pci25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-bus-pci25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-bus-vdev25:arm64.
# # Preparing to unpack .../20-librte-bus-vdev25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-bus-vdev25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-rcu25:arm64.
# # Preparing to unpack .../21-librte-rcu25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-rcu25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-hash25:arm64.
# # Preparing to unpack .../22-librte-hash25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-hash25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-ip-frag25:arm64.
# # Preparing to unpack .../23-librte-ip-frag25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-ip-frag25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-sched25:arm64.
# # Preparing to unpack .../24-librte-sched25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-sched25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package librte-net-bond25:arm64.
# # Preparing to unpack .../25-librte-net-bond25_24.11.4-0+deb13u1_arm64.deb ...
# # Unpacking librte-net-bond25:arm64 (24.11.4-0+deb13u1) ...
# # Selecting previously unselected package libxdp1:arm64.
# # Preparing to unpack .../26-libxdp1_1.5.4-1_arm64.deb ...
# # Unpacking libxdp1:arm64 (1.5.4-1) ...
# # Selecting previously unselected package suricata.
# # Preparing to unpack .../27-suricata_1%3a7.0.10-1+deb13u4_arm64.deb ...
# # Unpacking suricata (1:7.0.10-1+deb13u4) ...
# # Selecting previously unselected package suricata-update.
# # Preparing to unpack .../28-suricata-update_1.3.4-1+deb13u1_arm64.deb ...
# # Unpacking suricata-update (1.3.4-1+deb13u1) ...
# # Setting up libnetfilter-log1:arm64 (1.0.2-4+b1) ...
# # Setting up libhtp2 (1:0.5.50-1+deb13u1) ...
# # Setting up libevent-pthreads-2.1-7t64:arm64 (2.1.13-stable-1~deb13u1) ...
# # Setting up libmaxminddb0:arm64 (1.12.2-1) ...
# # Setting up libnet1:arm64 (1.3+dfsg-2) ...
# # Setting up libxdp1:arm64 (1.5.4-1) ...
# # Setting up suricata-update (1.3.4-1+deb13u1) ...
# # Setting up libnetfilter-queue1:arm64 (1.0.5-4+b1) ...
# # Setting up armv8crc-support (27) ...
# # Setting up libhiredis1.1.0:arm64 (1.2.0-6+b3) ...
# # Setting up librte-log25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-telemetry25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-kvargs25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-eal25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-meter25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-ring25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-mempool25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-pci25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-bus-pci25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-mbuf25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-sched25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-bus-vdev25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-rcu25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-net25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-hash25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-ethdev25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-ip-frag25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up librte-net-bond25:arm64 (24.11.4-0+deb13u1) ...
# # Setting up suricata (1:7.0.10-1+deb13u4) ...
# # Created symlink '/etc/systemd/system/multi-user.target.wants/suricata.service' →
# #  '/usr/lib/systemd/system/suricata.service'.
# # Processing triggers for man-db (2.13.1-1) ...
# # Processing triggers for libc-bin (2.41-12+rpt1+deb13u4) ...

# dirtysocs@raspberrypi:~ $ suricata -y
# # suricata: invalid option -- 'y'
# # Suricata 7.0.10
# # USAGE: suricata [OPTIONS] [BPF FILTER]

# #     -c <path>                            : path to configuration file
# #     -T                                   : test configuration file (use with -c)
# #     -i <dev or ip>                       : run in pcap live mode
# #     -F <bpf filter file>                 : bpf filter file
# #     -r <path>                            : run in pcap file/offline mode
# #     -q <qid[:qid]>                       : run in inline nfqueue mode (use colon to specify a range of queues)
# #     -s <path>                            : path to signature file loaded in addition to suricata.yaml settings (optional)
# #     -S <path>                            : path to signature file loaded exclusively (optional)
# #     -l <dir>                             : default log directory
# #     -D                                   : run as daemon
# #     -k [all|none]                        : force checksum check (all) or disabled it (none)
# #     -V                                   : display Suricata version
# #     -v                                   : be more verbose (use multiple times to increase verbosity)
# #     --list-app-layer-protos              : list supported app layer protocols
# #     --list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine
# #     --list-runmodes                      : list supported runmodes
# #     --runmode <runmode_id>               : specific runmode modification the engine should run.  The argument
# #                                            supplied should be the id for the runmode obtained by running
# #                                            --list-runmodes
# #     --engine-analysis                    : print reports on analysis of different sections in the engine and exit.
# #                                            Please have a look at the conf parameter engine-analysis on what reports
# #                                            can be printed
# #     --pidfile <file>                     : write pid to this file
# #     --init-errors-fatal                  : enable fatal failure on signature init error
# #     --disable-detection                  : disable detection engine
# #     --dump-config                        : show the running configuration
# #     --dump-features                      : display provided features
# #     --build-info                         : display build information
# #     --pcap[=<dev>]                       : run in pcap mode, no value select interfaces from suricata.yaml
# #     --pcap-file-continuous               : when running in pcap mode with a directory, continue checking directory for pcaps until interrupted
# #     --pcap-file-delete                   : when running in replay mode (-r with directory or file), will delete pcap files that have been processed when done
# #     --pcap-file-recursive                : will descend into subdirectories when running in replay mode (-r)
# #     --pcap-buffer-size                   : size of the pcap buffer value from 0 - 2147483647
# #     --dpdk                               : run in dpdk mode, uses interfaces from suricata.yaml
# #     --af-packet[=<dev>]                  : run in af-packet mode, no value select interfaces from suricata.yaml
# #     --af-xdp[=<dev>]                     : run in af-xdp mode, no value select interfaces from suricata.yaml
# #     --simulate-ips                       : force engine into IPS mode. Useful for QA
# #     --user <user>                        : run suricata as this user after init
# #     --group <group>                      : run suricata as this group after init
# #     --erf-in <path>                      : process an ERF file
# #     --unix-socket[=<file>]               : use unix socket to control suricata work
# #     --reject-dev <dev>                   : send reject packets from this interface
# #     --include <path>                     : additional configuration file
# #     --set name=value                     : set a configuration value


# # To run the engine with default configuration on interface eth0 with signature file "signatures.rules", run the command as:

# # suricata -c suricata.yaml -s signatures.rules -i eth0 



# Builds Suricata 8.0.7 from source with Lua enabled (needed by plaintext_creds.lua) 
set -euo pipefail

require_root() {
    if 
        [ "$(id -u)" -ne 0 ]; 
    then 
        echo "Run with sudo: sudo $0" >&2
        exit 1
    fi
}

install_dependencies() {
    apt-get update
    apt-get install -y \
        build-essential autoconf automake libtool pkg-config \
        curl ca-certificates python3 python3-yaml rustc cargo \
        libpcre2-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev \
        libjansson-dev libpcap-dev libnet1-dev liblz4-dev \
        libnetfilter-queue-dev libnfnetlink-dev libnetfilter-log-dev \
        liblua5.1-0-dev
}

build_suricata() {
    local version="$1"
    local workdir
    workdir="$(mktemp -d)"

    cd "$workdir"
    curl -fsSLO "https://www.openinfosecfoundation.org/download/suricata-${version}.tar.gz"
    tar xzf "suricata-${version}.tar.gz"
    cd "suricata-${version}"

    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --enable-nfqueue \
        --enable-lua

    make -j"$(nproc)"
    make install
    make install-conf
    ldconfig

    cd /
    rm -rf "$workdir"
}

verify_lua () {
    # Suricata 8 has Lua built in
    if 
        suricata --build-info | grep q "HAVE_LUA";
    then
        echo "OK: Lua support is enabled."
    else
        echo "Fail: Lua support is still disabled. Check the configure output." >&2
        exit 1
    fi
}

update_rules () {
    # FIX and UPDATE
    # suricata-update owns every suricata ruleset: ET Open + URLhaus, merged into
    # /var/lib/suricata/rules/suricata.rules (already listed in suricata.yaml).
    # Adding any source turns off "ET Open by default" behavior, this enables it explicity.
    suricata-update update-sources
    suricata-update enable-source et/open

    # add-source fails if the source already exist, so this only adds it once
    if ! suricata-update list-sources --enabled | grep -q "urlhaus";
    then
        suricata-update add-source urlhaus https://urlhaus.abuse.ch/downloads/urlhaus_suricata.rules
    fi

    suricata-update
}

main() {
    require_root
    install_dependencies
    build_suricata "8.0.7"
    verify_lua
    update_rules
    suricata -V
}

main "$@"