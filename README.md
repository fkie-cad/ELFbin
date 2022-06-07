# ELFbin

*elfbin* is a python library that enables ELF - based code injection and execution. To that end, LIEF, an ELF - parser, is partially used to parse an ELF - file and perform code injections. On the other hand, a custom parser is used to do all the operations LIEF does not want to do.

This library aims to support analysis of ELF - files using [Frida](https://frida.re/). It can e.g. be used to analyse ELF - files that are the result of the *Ahead-of-Time Compilation* on Android systems.

## Examples and Technical Details

Please see the blog post [Make Frida great again](https://lolcads.github.io/) for further details.
