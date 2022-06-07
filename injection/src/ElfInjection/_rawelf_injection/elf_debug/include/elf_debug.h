/*------------------------------------------------------------------------*/
/* NOTES                                                                  */
/*------------------------------------------------------------------------*/
// (1) __ELF_DEBUG has to be defined in order to use this logging
// 	functionality!
// (2) Use __ELF_LOGLEVEL to configure the degree of logging. A log level of
// 	loglevel_max indicates no logging. If that is the case, prefer
//	undefining __ELF_DEBUG instead!

/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELFDEBUG_H_
#define _ELFDEBUG_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Macros                                                                 */
/*------------------------------------------------------------------------*/
#ifndef __ELF_LOGLEVEL
	#define __ELF_LOGLEVEL ELF_LOGLEVEL_INFO
#endif

#ifdef __ELF_DEBUG
	#define log_return(log_level, result, print_type)		\
	do {								\
		if (log_level >= __ELF_LOGLEVEL)			\
			_elf_log_to_console(log_level, result, __FILE__,\
				__LINE__, __func__, print_type, NULL);	\
		return result;						\
	} while (0)

	#define log_forward_return(log_level, result, custom_message)	\
	do {								\
		if (log_level >= __ELF_LOGLEVEL)			\
			_elf_log_to_console(log_level, result, __FILE__,\
				__LINE__, __func__, ELF_PRINTTYPE_NONE,	\
				custom_message);			\
		return result;						\
	} while (0)

	#define log(log_level, result, print_type)			\
	do {								\
		if (log_level >= __ELF_LOGLEVEL)			\
			_elf_log_to_console(log_level, result, __FILE__,\
				__LINE__, __func__, print_type, NULL);	\
	} while (0)

	#define log_forward(log_level, custom_message)				\
	do {									\
		if (log_level >= __ELF_LOGLEVEL)				\
			_elf_log_to_console(log_level, 0, __FILE__, __LINE__,	\
				__func__, ELF_PRINTTYPE_NONE, custom_message);	\
	} while (0)
#else
	#define log_return(log_level, result, print_type)\
		do { return result; } while (0)
	#define log_forward_return(log_level, result, custom_message)\
		do { return result; } while (0)
	#define log(log_level, result, print_type) do {} while (0)
	#define log_forward(log_level, custom_message) do {} while (0)
#endif

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
enum elf_loglevel {
	ELF_LOGLEVEL_INFO = 0,
	ELF_LOGLEVEL_SOFTERROR,
	ELF_LOGLEVEL_ERROR,
	ELF_LOGLEVEL_MAX
};

enum elf_printtype {
	ELF_PRINTTYPE_NONE = 0,
	ELF_PRINTTYPE_ERRNO,
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
void _elf_log_to_console(
	enum elf_loglevel level,
	enum elf_result result,
	const char *causing_file,
	uint32_t causing_line,
	const char *causing_function,
	enum elf_printtype print_type,
	const char *custom_message);

#endif