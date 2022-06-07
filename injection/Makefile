PackageName := ElfInjection
rawelf_module := _rawelf_injection
rawelf_file := rawelf_injection

build:
	python3 setup.py sdist bdist_wheel

clean:
	rm -rf './build' './dist' './src/$(PackageName).egg-info'
	rm -f './src/$(PackageName)/$(rawelf_module)/$(rawelf_file).cpython-38-x86_64-linux-gnu.so'
	py3clean .

locinstall:
	pip3 install --force-reinstall -e .