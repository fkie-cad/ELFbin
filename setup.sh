#!/bin/bash

function install_rawelf_injection () {
	current=$PWD
	echo "Compiling and install \"_rawelf_injection\""
	cd "./injection/ElfInjection/_rawelf_injection/"
	sudo python3 setup.py install # --prefix ~/.local
	result=$?
	cd "${current}"

	if [ ${result} != 0 ]
	then
		echo "Failed to setup \"_rawelf_injection\"..."
		return 1
	fi

	return 0
}

function uninstall_rawelf_injection () {
	echo "Uninstalling \"rawelf_injection\""

	# Find installation of _rawelf_injection
	installation=$(python3 -c 'import _rawelf_injection; print(_rawelf_injection.__file__)')
	if [ $? != 0 ]
	then
		echo "Failed to uninstall \"_rawelf_injection\""
		return 1
	fi

	if [ -e "${installation}" ]
	then
		dir="$(dirname "${installation}")"
		sudo rm ${dir}/_rawelf_injection*
	fi

	return 0
}

function install_elf_injection () {
	current=$PWD
	echo "Installing \"ElfInjection\""
	cd ./injection/
	pip3 install -e .
	result=$?
	cd "${current}"

	if [ $result != 0 ]
	then
		echo "Failed to setup \"ElfInjection\""
		uninstall_rawelf_injection
		return 2
	fi

	return 0
}

function uninstall_elf_injection () {
	echo "Uninstalling \"ElfInjection\""

	pip3 uninstall "ElfInjection"
	if [ $? != 0 ]
	then
		echo "Failed to uninstall \"ElfInjection\""
		return 2
	fi

	return 0
}

if [ $# -lt 1 ]
then
	echo "Invalid usage!"
	echo "    setup.sh <install/uninstall>"
	exit 3
fi


if [ $1 == 'install' ]
then
	install_rawelf_injection
	if [ $? != 0 ]
	then
		exit 1
	fi

	install_elf_injection
	if [ $? != 0 ]
	then
		exit 2
	fi

	echo "Successfully installed \"ElfInjection\""
	exit 0

elif [ $1 == 'uninstall' ]
then
	uninstall_elf_injection
	uninstall_rawelf_injection
	exit 0

else
	echo "Unknown command"
	echo "Either use \"install\" or \"uninstall\""
	exit 3
fi