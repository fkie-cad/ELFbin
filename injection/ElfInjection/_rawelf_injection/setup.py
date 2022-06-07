from distutils.core import setup, Extension

import glob

def main():

	sources = []
	for f in glob.glob("./**/*.c", recursive=True):
		sources.append(f)

	include_dirs = []
	for i in glob.glob("./**/include", recursive=True):
		include_dirs.append(i)

	rawelf_module = Extension(
		"_rawelf_injection", include_dirs=include_dirs, sources=sources
	)

	setup(name="_rawelf_injection",
		  version="1.0",
		  description="Description",
		  author="Me",
		  author_email="me@me.me",
		  ext_modules=[ rawelf_module ])

if __name__ == '__main__':
	main()

#from setuptools import setup, Extension, find_packages
#import glob
#
#def main():
#
#	sources = []
#	for f in glob.glob("./**/*.c", recursive=True):
#		sources.append(f)
#
#	include_dirs = []
#	for i in glob.glob("./**/include", recursive=True):
#		include_dirs.append(i)
#
#	rawelf_module = Extension(
#		'_rawelf_injection',
#		include_dirs=include_dirs,
#		sources=sources
#	)
#
#	setup(
#		name='rawelf_injection',
#		version='1.0.0',
#		license='GNU GPLv3',
#		ext_modules=[rawelf_module],
#		packages=find_packages()
#	)
#
#if (__name__ == '__main__'):
#	main()