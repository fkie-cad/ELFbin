# ELF - based code injection and execution techniques with LIEF

## Automated setup

Note that you will need root for both operations. root will be used for building and removing [\_rawelf_injection](injection/elf_injection/\_rawelf_injection).

### Installation
Run
```
./setup.sh install
```

### Deinstallation
Run
```
./setup.sh uninstall
```

## Manual setup
It is possible to install the package without using the helper script.

### Setup
In order to properly use this package, please maneuver to 
```
./injection/elf_injection/_rawelf_injection
```
and run the following command
```
sudo python3 setup.py install
```
This will compile and install a python module that is used for techniques, for which LIEF is not suited. Notice that the module [\_rawelf_injection](injection/elf_injection/\_rawelf_injection) is now globally available aswell.

### Installing the package
After compiling and installing `_rawelf_injection`, the whole package needs to be installed. As of writing this, this package is NOT uploaded to PyPI. Thus, maneuver to
```
./injection
```
and run
```
pip3 install -e .
```
This will install the whole package it make it accessible for use in python.

### Uninstalling the package
In order to uninstall the package, run
```
pip3 uninstall elf_injection
```
On an Ubuntu 20.04.1 with a standard installation, `_rawelf_injection` will be installed to
```
/usr/local/lib/python3.8/dist-packages/_rawelf_injection.cpython-38-x86_64-linux-gnu.so
```