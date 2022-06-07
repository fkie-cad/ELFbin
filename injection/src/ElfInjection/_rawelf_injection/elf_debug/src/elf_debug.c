/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework Includes
#include "elf_debug.h"

// Standard Includes
#include <stdio.h>
#include <errno.h>
#include <string.h>

/*------------------------------------------------------------------------*/
/* Local Constants                                                        */
/*------------------------------------------------------------------------*/
#define LOG_INFO_COLOR "\033[1;33m"
#define LOG_ERROR_COLOR "\033[0;31m"
#define LOG_SOFTERROR_COLOR "\033[0;33m"
#define LOG_DEFAULT_COLOR "\033[0m"

static const char* error_messages[] = {
	// common
	"Success.",
	"Invalid parameter(s).",

	// binary
	"Given binary does not meet prerequisites. Binary must:\n    1. Be an ELF file\n    2. Be either executable or shared object file\n    3. Use little endian\n    4. Be of class 64",
	"Given binary object is not loaded. It currently does not represent any existing binary file.",
	"Given binary does not have a Program Header Table (PHT).",
	"Given binary does not have a Section Header Table (SHT).",
	"Given binary does not contain the requested section.",
	"Given binary does not contain the requested segment.",

	// section
	"Type of given section is invalid.",
	"List of entries in given section is invalid. Check whether the list has been initialised successfully.",
	"Given section does not contain the requested entry.",
	
	// segment
	"Given segment cannot be mapped to requested section.",

	// std
	"Failed to allocate memory with \'calloc\'.",
	"Failed to reallocate memory with \'realloc\'.",

	// syscall
	"Failed to acquire file information with \'stat\'.",
	"Failed to open file with \'open\'.",
	"Failed to map file to memory with \'mmap\'.",
	"Failed to write to given fd with \'write\'.",
	"Failed to truncate file wit \'ftruncate\'.",
	"Failed to duplicate file descriptor with \'dup\'.",

	// object
	"Failed to initialize an object.",

	// atomic techniques
	// "Given .dynamic section references a string table that is invalid.",

	// platform / architecture
	"Platform not supported.",

	// relocation
	"Relocation type not supported.",

	// Code - Cave
	"Failed to find code - cave.",

	// translator
	"Given virtual address cannot be properly converted to a file offset as '.p_filesz' < '.p_memsz'.",

	// Console
	"Unknown command.",
};

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
void _elf_log_to_console(
	enum elf_loglevel level,
	enum elf_result result,
	const char *causing_file,
	uint32_t causing_line,
	const char *causing_function,
	enum elf_printtype print_type,
	const char *custom_message)
{
	if (level >= 0 &&
	    level < ELF_LOGLEVEL_MAX &&
	    result >= 0 &&
	    result < ELF_MAX_VALUE) {

		switch (level) {
		case ELF_LOGLEVEL_INFO:
			printf(LOG_INFO_COLOR "[Info]\n");
			break;
		case ELF_LOGLEVEL_ERROR:
			printf(LOG_ERROR_COLOR "[Error]\n");
			break;
		case ELF_LOGLEVEL_SOFTERROR:
			printf(LOG_SOFTERROR_COLOR "[Softerror]\n");
			break;
		default:
			return;
		}

		if (custom_message != NULL)
			printf("Message:   %s\n", custom_message);
		else
			printf("Message:   %s\n", error_messages[(uint32_t)result]);
		printf("File:      %s\n", causing_file);
		printf("Function:  %s\n", causing_function);
		printf("Line:      %d\n", causing_line);

		if (print_type == ELF_PRINTTYPE_ERRNO)
			printf("errno msg: %s\n", strerror(errno));

		printf("" LOG_DEFAULT_COLOR);
	}

	return;
}