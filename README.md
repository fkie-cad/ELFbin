# elfbin

*elfbin* is a python library that enables ELF - based code injection and execution. To that end, LIEF, an ELF - parser, is partially used to parse an ELF - file and perform code injections. On the other hand, a custom parser is used to do all the operations LIEF does not want to do.

This library aims to support analysis of ELF - files using [Frida](https://frida.re/). It specifically targets ELF - files that are created for AARCH64 - architectures with Android OS.

## Installation

There are two ways to install this package.

### pip

In the best case, you can just run
```
pip3 install elfbin
```

### locally

In every other case, just clone this repository and run the following:
```bash
$ cd injection/
$ make build
$ make locinstall
```

## Detailed information on theory and usage

Please see my [blog post](https://lolcads.github.io/posts/2022/05/make_frida_great_again) for detailed information.