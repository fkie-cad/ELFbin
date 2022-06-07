import setuptools
import os

# Setup rest
setuptools.setup(
	name='ElfInjection',
	version='1.0.0',
	author='Me',
	author_email='me@me.me',
	description='ELF - based code injection.',
	packages=setuptools.find_packages(),
	classifiers=[
		'Programming Language :: Python :: 3',
		'Operating System :: Linux',
	],
	python_requires='>=3.8.10'
)