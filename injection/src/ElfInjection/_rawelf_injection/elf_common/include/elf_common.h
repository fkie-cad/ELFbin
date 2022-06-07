/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_COMMON_H_
#define _ELF_COMMON_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// System
#include <elf.h>

// Standard
#include <stdint.h>

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
enum elf_result
{
	/*elf_success = 0,
	elf_error_invalid_parameters,
	elf_error_syscall_stat,
	elf_error_syscall_open,
	elf_error_syscall_mmap,
	elf_error_syscall_munmap,
	elf_error_std_calloc,
	elf_error_std_realloc,
	elf_framework_invalid_format,
	elf_framework_no_sht,
	elf_framework_no_pht,
	elf_framework_no_section,
	elf_framework_not_dynamic_section,
	elf_framework_not_symbol_table,
	elf_max,*/

	// common
	ELF_COMMON_SUCCESS = 0,
	ELF_COMMON_INVALID_PARAMETERS,

	// binary
	ELF_BINARY_INVALID_FORMAT,
	ELF_BINARY_NOT_LOADED,
	ELF_BINARY_PHT_NOT_FOUND,
	ELF_BINARY_SHT_NOT_FOUND,
	ELF_BINARY_SECTION_NOT_FOUND,
	ELF_BINARY_SEGMENT_NOT_FOUND,

	// section
	ELF_SECTION_INVALID_TYPE,
	ELF_SECTION_INVALID_ENTRY_LIST,	// applies to all sections that hold tables
	ELF_SECTION_ENTRY_NOT_FOUND,

	// segment
	ELF_SEGMENT_INVALID_TYPE,	// = elf_segment_not_mappable,

	// std
	ELF_STD_CALLOC,
	ELF_STD_REALLOCARRAY,

	// syscall
	ELF_SYSCALL_STAT,
	ELF_SYSCALL_OPEN,
	ELF_SYSCALL_MMAP,
	ELF_SYSCALL_WRITE,
	ELF_SYSCALL_FTRUNCATE,
	ELF_SYSCALL_DUP,

	// object
	ELF_OBJECT_FAILED_INIT,	// TODO: create additional info enum

	// file
	// elf_file_failed_copy,	// additional

	// atomic techniques
	// elf_atomic_invalid_string_table,

	// platform / architecture
	ELF_PLATFORM_NOT_SUPPORTED,

	// relocation
	ELF_RELOC_TYPE_NOT_SUPPORTED,

	// Code - Cave
	ELF_CODE_CAVE_NOT_FOUND,

	// translator
	ELF_TRANSLATOR_VADDR_OUT_OF_BOUNDS,

	// console
	ELF_CONSOLE_UNKNOWN_COMMAND,

	// for error checking purposes only
	ELF_MAX_VALUE
};

enum elf_callback_retval
{
	ELF_CALLBACK_CONTINUE = 0,
	ELF_CALLBACK_BREAK,
};

#endif