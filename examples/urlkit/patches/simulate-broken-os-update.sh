#!/bin/sh
# SIMULATION ONLY: behaves like a badly built OS update so you can see what
# PatchLab Internal reports when an update breaks the operating system underneath an
# application. It is only ever run inside a throw-away sandbox.
#
# Roll back with:  apt-get install -y zlib1g && sed -i '/PATCHLAB_INTERNAL_SIMULATED/d' /etc/environment
set -e

echo "Removing zlib1g without its dependants (simulates a botched library update)"
dpkg --remove --force-depends --force-remove-essential --force-remove-protected zlib1g

echo "Overwriting a local configuration file (simulates a package clobbering config)"
echo 'PATCHLAB_INTERNAL_SIMULATED="1"' >> /etc/environment
