import setuptools
import glob
import os

rawelf_module_base = 'src/ElfInjection/_rawelf_injection/'
def main():

	sources = []
	for f in glob.glob(
			rawelf_module_base + '**/*.c',
			recursive=True
		):
		sources.append(f)

	include_dirs = []
	for i in glob.glob(
			rawelf_module_base + '**/include/',
			recursive=True
		):
		include_dirs.append(i)

	headers = []
	for i in glob.glob(
			rawelf_module_base + '**/*.h',
			recursive=True
		):
		headers.append(i)

	rawelf_module = setuptools.Extension(
		'ElfInjection._rawelf_injection.rawelf_injection',
		include_dirs=include_dirs,
		sources=sources,
		language='c'
	)

	# Setup rest
	setuptools.setup(
		name='ElfInjection',
		version='1.0.0',
		author='Pascal Kühnemann',
		author_email='pascal.kuehnemann@gmail.com',
		license='GPLv3',
		description='ELF - based code injection.',
		#long_description=long_description,
		long_description_content_type='text/markdown',
		url='',
		project_urls={
			'Blog Post': 'https://lolcads.github.io/posts/2022/05/make_frida_great_again'
		},
		packages=setuptools.find_packages('src'),
		package_dir={
			'': 'src'
		},
		ext_modules=[
			rawelf_module
		],
		classifiers=[
			'Programming Language :: Python :: 3',
			'License :: OSI Approved :: GPLv3',
			'Operating System :: OS Independent',
		],
		python_requires='>=3.8.10'
	)

if (__name__ == '__main__'):
	main()