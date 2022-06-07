/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_binary.h"
#include "elf_section.h"
#include "elf_segment.h"

// System
#include <sys/stat.h>	// stat
#include <sys/mman.h>	// mmap
#include <sys/fcntl.h>	// open
#include <unistd.h>	// Syscalls

/*------------------------------------------------------------------------*/
/* Macros                                                                 */
/*------------------------------------------------------------------------*/
// NOTE: A binary in this state is considered "unloaded".
// This macro is more for reference than usage, as used
// design pattern implies heap - based/dynamic usage, not static init.
#define ELF_BINARY_INIT_NULL {	\
	elf_header: NULL,	\
	num_sections: 0,	\
	sections: NULL,		\
	num_segments: 0,	\
	segments: NULL,		\
	size: 0,		\
	fd: -1			\
}

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct _elf_binary {
	// Pointer to the ELF header. This is also the base
	// pointer of the mapped file.
	Elf64_Ehdr *elf_header;

	// Amount of sections available in this binary.
	uint64_t num_sections;

	// List of sections. This needs to be freed after use.
	elf_section **sections;

	// Amount of segments available in this binary.
	uint32_t num_segments;

	// List of segments. This needs to be freed after use.
	elf_segment **segments;

	// Size of binary in bytes.
	uint64_t size;

	// Open file descriptor of the mapped binary.
	int64_t fd;
};

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
static uint8_t _elf_check_binary_format(elf_binary *bin);
static enum elf_result _elf_load_sections(elf_binary *bin);
static enum elf_result _elf_unload_sections(elf_binary *bin);
static enum elf_result _elf_load_segments(elf_binary *bin);
static enum elf_result _elf_unload_segments(elf_binary *bin);

static inline void _elf_init_null(elf_binary *bin);
/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_binary *elf_binary_init(void)
{
	elf_binary *new = calloc(1, sizeof(elf_binary));
	if (new == NULL)
		log(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC, ELF_PRINTTYPE_ERRNO);
	else
		new->fd = -1;
	return new;
}

void elf_binary_free(elf_binary *bin)
{
	if (bin != NULL) {
		if (elf_binary_unload(bin) != ELF_COMMON_SUCCESS)
			log_forward(ELF_LOGLEVEL_SOFTERROR,
					"Unloading binary failed.");
		free(bin);
	}
}

// Getter
Elf64_Ehdr *elf_binary_get_elf_header(elf_binary *bin)
{
	return bin->elf_header;
}

uint64_t elf_binary_get_amount_sections(elf_binary *bin)
{
	return bin->num_sections;
}

elf_section **elf_binary_get_sections(elf_binary *bin)
{
	return bin->sections;
}

uint32_t elf_binary_get_amount_segments(elf_binary *bin)
{
	return bin->num_segments;
}

elf_segment **elf_binary_get_segments(elf_binary *bin)
{
	return bin->segments;
}

uint64_t elf_binary_get_size(elf_binary *bin)
{
	return bin->size;
}

int64_t	elf_binary_get_fd(elf_binary *bin)
{
	return bin->fd;
}

// Setter
void elf_binary_set_elf_header(elf_binary *bin, Elf64_Ehdr *elf_header)
{
	bin->elf_header = elf_header;
}

void elf_binary_set_amount_sections(elf_binary *bin, uint64_t num_sections)
{
	bin->num_sections = num_sections;
}

void elf_binary_set_sections(elf_binary *bin, elf_section **list_sections)
{
	bin->sections = list_sections;
}

void elf_binary_set_amount_segments(elf_binary *bin, uint32_t num_segments)
{
	bin->num_segments = num_segments;
}

void elf_binary_set_segments(elf_binary *bin, elf_segment **list_segments)
{
	bin->segments = list_segments;
}

void elf_binary_set_size(elf_binary *bin, uint64_t file_size)
{
	bin->size = file_size;
}

void elf_binary_set_fd(elf_binary *bin, int64_t fd)
{
	bin->fd = fd;
}

// Utility
enum elf_result elf_binary_load_by_name(elf_binary *bin, const char *abs_bin_path)
{
	enum elf_result result;
	int fd;

	if (bin == NULL || abs_bin_path == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Open target binary
	fd = open(abs_bin_path, O_RDWR, 0);
	if (fd == -1)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SYSCALL_OPEN,
				ELF_PRINTTYPE_ERRNO);
	
	result = elf_binary_load_by_fd(bin, fd);
	if (result != ELF_COMMON_SUCCESS)
		close(fd);

	return result;
}

enum elf_result elf_binary_load_by_fd(elf_binary *bin, int fd)
{
	__label__ label_error_unmap;
	enum elf_result result;
	uint8_t is_loaded;
	struct stat file_info;

	if (bin == NULL || fd == -1)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_is_loaded(bin, &is_loaded);
	if (result != ELF_COMMON_SUCCESS) {
		return result;
	}
	else if (is_loaded == 1) {
		log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Binary is already loaded.");
		result = elf_binary_unload(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	bin->fd = fd;
	if (fstat(bin->fd, &file_info) != 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SYSCALL_STAT,
				ELF_PRINTTYPE_ERRNO);
	bin->size = file_info.st_size;

	// Create a file mapping
	bin->elf_header = (Elf64_Ehdr*)mmap(NULL, bin->size,
			PROT_READ | PROT_WRITE, MAP_SHARED, bin->fd, 0);
	if (bin->elf_header == MAP_FAILED)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SYSCALL_MMAP,
				ELF_PRINTTYPE_ERRNO);

	// Check if mapped file is a valid elf64 binary.
	if (_elf_check_binary_format(bin) == 0) {
		result = ELF_BINARY_INVALID_FORMAT;
		log(ELF_LOGLEVEL_ERROR, result,
			ELF_PRINTTYPE_NONE);
		goto label_error_unmap;
	}

	// Load sections and segments.
	if (_elf_load_sections(bin) != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Loading list of sections failed.");
	if (_elf_load_segments(bin) != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Loading list of segments failed.");
	
	return ELF_COMMON_SUCCESS;

label_error_unmap:
	munmap(bin->elf_header, bin->size);

	return result;
}

enum elf_result elf_binary_unload(elf_binary *bin)
{
	if (bin == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Unload lists of sections and segments.
	if (_elf_unload_sections(bin) != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Failed to unload sections.");
	if (_elf_unload_segments(bin) != ELF_COMMON_SUCCESS)
		log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Failed to unload segments.");

	// Unmap binary.
	munmap(bin->elf_header, bin->size);

	// Finally close open file descriptor.
	close(bin->fd);

	// Reset state of the binary.
	_elf_init_null(bin);

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_binary_is_loaded(elf_binary *bin, uint8_t *is_loaded)
{
	if (bin == NULL || is_loaded == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Not efficient but resistent to changes.
	elf_binary null = ELF_BINARY_INIT_NULL;
	if (bin->elf_header == null.elf_header &&
		bin->num_sections == null.num_sections &&
		bin->sections == null.sections &&
		bin->num_segments == null.num_segments &&
		bin->segments == null.segments &&
		bin->size == null.size &&
		bin->fd == null.fd)
		*is_loaded = 0;
	else
		*is_loaded = 1;
	return ELF_COMMON_SUCCESS;
}

/*
* 'elf_binary_reload' tries to reload specified part of the binary.
* @bin: Binary, on which to perform partial reloading.
* @type: Type of reloading (e.g. reload sections, segments...).
* @return: Either success or one of the following:
*	- invalid parameters
*	- binary not loaded
*/
enum elf_result elf_binary_reload(elf_binary *bin, enum elf_reload_type type)
{
	enum elf_result result;
	uint8_t is_loaded;
	int copy_fd;

	if (bin == NULL || type < 0 || type > ELF_RELOAD_MAX)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_binary_is_loaded(bin, &is_loaded);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (is_loaded == 0)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_NOT_LOADED,
				ELF_PRINTTYPE_NONE);

	if ((type & ELF_RELOAD_ALL) != 0) {

		copy_fd = dup(elf_binary_get_fd(bin));
		if (copy_fd == -1)
			log_return(ELF_LOGLEVEL_ERROR, ELF_SYSCALL_DUP,
					ELF_PRINTTYPE_ERRNO);

		result = elf_binary_unload(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;

		result = elf_binary_load_by_fd(bin, copy_fd);
		if (result != ELF_COMMON_SUCCESS)
			close(copy_fd);
		return result;
	}

	if ((type & ELF_RELOAD_SECTIONS) != 0) {
		result = _elf_unload_sections(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;
		
		result = _elf_load_sections(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}
	if ((type & ELF_RELOAD_SEGMENTS) != 0) {
		result = _elf_unload_segments(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;
		result = _elf_load_segments(bin);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	return ELF_COMMON_SUCCESS;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/* NOTE: As these are internal functions, we assume correct parameters.   */
/*------------------------------------------------------------------------*/
uint8_t _elf_check_binary_format(elf_binary *bin)
{
	if (bin->elf_header->e_ident[EI_MAG0] == 0x7f &&
		bin->elf_header->e_ident[EI_MAG1] == 'E' &&
		bin->elf_header->e_ident[EI_MAG2] == 'L' &&
		bin->elf_header->e_ident[EI_MAG3] == 'F' &&
		bin->elf_header->e_ident[EI_CLASS] == ELFCLASS64 &&
		bin->elf_header->e_ident[EI_DATA] == ELFDATA2LSB &&
		(bin->elf_header->e_type == ET_EXEC ||
		bin->elf_header->e_type == ET_DYN) &&
		bin->elf_header->e_phentsize == sizeof(Elf64_Phdr))
		return 1;
	return 0;
}

enum elf_result _elf_load_sections(elf_binary *bin)
{
	Elf64_Shdr *current_section_header;
	uint32_t string_table_index;
	uint8_t *section_string_table;
	uint64_t i;
	elf_section *current;

	// Check if there is a section header table.
	if (bin->elf_header->e_shoff == 0)
		log_return(ELF_LOGLEVEL_SOFTERROR, ELF_BINARY_SHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Calculate the base address of the section header table.
	current_section_header = SECTION_ADDRESS_BY_INDEX(bin, 0);

	// Query the string table index that contains all section names.
	// Also get the address of the corresponding section header.
	if (bin->elf_header->e_shstrndx != SHN_XINDEX)
		string_table_index = bin->elf_header->e_shstrndx;
	else
		string_table_index = current_section_header->sh_link;

	section_string_table = OFFSET(bin->elf_header, 
		((Elf64_Shdr*)SECTION_ADDRESS_BY_INDEX(bin, string_table_index))->sh_offset);

	// Query the amount of section headers available.
	// 'e_shnum' can also be 0 if there is no sht. In
	// this case 'sh_size' will also be 0.
	if (bin->elf_header->e_shnum != 0)
		bin->num_sections = bin->elf_header->e_shnum;
	else
		bin->num_sections = current_section_header->sh_size;
	
	// Finally allocate memory for every section header table entry.
	bin->sections = (elf_section**)calloc(bin->num_sections,
		sizeof(elf_section*));
	if (bin->sections == NULL) {
		bin->num_sections = 0;
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);
	}

	// Create section objects.
	for (i = 0; i < bin->num_sections; i++)
		bin->sections[i] = elf_section_init();

	// Iterate through section header table and set pointers.
	for (i = 0; i < bin->num_sections; i++, current_section_header++) {
		current = bin->sections[i];

		// Set pointer to section header table entry.
		elf_section_set_section_header(current,
			current_section_header);

		// Set pointer to section name, if name section exists.
		if (string_table_index != SHN_UNDEF)
			elf_section_set_name(current, (char*)OFFSET(
				section_string_table,
				elf_section_get_section_header(current)->sh_name));

		// Finally set pointer to parent binary.
		elf_section_set_binary(current, bin);
	}
	
	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_unload_sections(elf_binary *bin)
{
	uint64_t i;

	// Check if there is a list of sections to free.
	if (bin->sections != NULL) {
		// Free all section objects.
		for (i = 0; i < bin->num_sections; i++)
			elf_section_free(bin->sections[i]);

		// If so free allocated memory.
		free(bin->sections);
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_load_segments(elf_binary *bin)
{
	Elf64_Phdr *current_program_header;
	uint32_t i;
	elf_segment *current;
	
	// Check if there is a program header table.
	if (bin->elf_header->e_phoff == 0)
		log_return(ELF_LOGLEVEL_SOFTERROR, ELF_BINARY_PHT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Calculate base address of the program header table.
	current_program_header = SEGMENT_ADDRESS_BY_INDEX(bin, 0);

	// Get amount of program header table entries.
	if (bin->elf_header->e_phnum != PN_XNUM)
		bin->num_segments = bin->elf_header->e_phnum;
	else
		bin->num_segments = ((Elf64_Shdr*)SECTION_ADDRESS_BY_INDEX(bin, 0))->sh_info;
	
	// Allocate memory for every segment header table entry.
	bin->segments = (elf_segment**)calloc(bin->num_segments,
		sizeof(elf_segment*));
	if (bin->segments == NULL) {
		bin->num_segments = 0;
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);
	}

	// Create segment objects.
	for (i = 0; i < bin->num_segments; i++)
		bin->segments[i] = elf_segment_init();

	// Iterate through program header table.
	for (i = 0; i < bin->num_segments; i++, current_program_header++) {
		current = bin->segments[i];

		// Set pointer to program header table entry.
		elf_segment_set_program_header(current,
			current_program_header);

		// Finally set pointer to parent binary.
		elf_segment_set_binary(current, bin);
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_unload_segments(elf_binary *bin)
{
	uint64_t i;

	// Check if there is a list of segments to free.
	if (bin->segments != NULL) {
		// Free all segment objects.
		for (i = 0; i < bin->num_segments; i++)
			elf_segment_free(bin->segments[i]);

		// If so free allocated memory.
		free(bin->segments);
	}

	return ELF_COMMON_SUCCESS;
}

void _elf_init_null(elf_binary *bin)
{
	elf_binary temp = ELF_BINARY_INIT_NULL;
	bin->elf_header = temp.elf_header;
	bin->num_sections = temp.num_sections;
	bin->sections = temp.sections;
	bin->num_segments = temp.num_segments;
	bin->segments = temp.segments;
	bin->size = temp.size;
	bin->fd = temp.fd;
}