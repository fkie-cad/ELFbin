/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_BINARY_UTIL_H_
#define _ELF_BINARY_UTIL_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_binary elf_binary;
typedef struct _elf_section elf_section;
typedef struct _elf_segment elf_segment;
typedef struct _elf_section_string_table elf_section_string_table;
typedef struct _elf_section_relocation_table elf_section_relocation_table;
typedef struct _elf_section_symbol_table elf_section_symbol_table;

typedef enum elf_callback_retval(*lpfn_elf_section_callback)
	(elf_section *current, void *user_data);
typedef enum elf_callback_retval(*lpfn_elf_segment_callback)
	(elf_segment *current, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
/*
* Describes the target to reload.
* @ELF_RELOAD_NONE: Does not reload anything.
* @ELF_RELOAD_ALL: Attempts to reload whole binary.
* @ELF_RELOAD_SECTIONS: Attempts to reload sections.
* @ELF_RELOAD_SEGMENTS: Attempts to reload segments.
*/
enum elf_reload_type {
	ELF_RELOAD_NONE = 0,
	ELF_RELOAD_ALL = 1,
	ELF_RELOAD_SECTIONS = 2,
	ELF_RELOAD_SEGMENTS = 4,
	ELF_RELOAD_MAX = ELF_RELOAD_ALL      |
			 ELF_RELOAD_SEGMENTS |
			 ELF_RELOAD_SECTIONS,
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_binary *elf_binary_init(void);
void elf_binary_free(elf_binary *bin);

// Getter / Setter
Elf64_Ehdr *elf_binary_get_elf_header(elf_binary *bin);
uint64_t elf_binary_get_amount_sections(elf_binary *bin);
elf_section **elf_binary_get_sections(elf_binary *bin);
uint32_t elf_binary_get_amount_segments(elf_binary *bin);
elf_segment **elf_binary_get_segments(elf_binary *bin);
uint64_t elf_binary_get_size(elf_binary *bin);
int64_t	elf_binary_get_fd(elf_binary *bin);

void elf_binary_set_elf_header(elf_binary *bin, Elf64_Ehdr *elf_header);
void elf_binary_set_amount_sections(elf_binary *bin, uint64_t num_sections);
void elf_binary_set_sections(elf_binary *bin, elf_section **list_sections);
void elf_binary_set_amount_segments(elf_binary *bin, uint32_t num_segments);
void elf_binary_set_segments(elf_binary *bin, elf_segment **list_segments);
void elf_binary_set_size(elf_binary *bin, uint64_t file_size);
void elf_binary_set_fd(elf_binary *bin, int64_t fd);

// Loading / Unloading
enum elf_result elf_binary_load_by_name(elf_binary *bin, const char *abs_bin_path);
enum elf_result elf_binary_load_by_fd(elf_binary *bin, int fd);
enum elf_result elf_binary_unload(elf_binary *bin);
enum elf_result elf_binary_is_loaded(elf_binary *bin, uint8_t *is_loaded);
enum elf_result elf_binary_reload(elf_binary *bin, enum elf_reload_type type);

// Utility

enum elf_result elf_binary_iterate_sections(elf_binary *bin,
			lpfn_elf_section_callback callback, void *user_data);
enum elf_result elf_binary_iterate_segments(elf_binary *bin,
			lpfn_elf_segment_callback callback, void *user_data);

enum elf_result elf_binary_has_section_header_table(elf_binary *bin,
						uint8_t *has_table);
enum elf_result elf_binary_has_segment_header_table(elf_binary *bin,
						uint8_t *has_table);

enum elf_result elf_binary_find_section_by_name(elf_binary *bin,
			const char *section_name, elf_section **section);
enum elf_result elf_binary_find_segment_by_type(elf_binary *bin, uint32_t type,
						elf_segment **segment);

enum elf_result elf_binary_memblock_as_string_table(elf_binary *bin,
	uint64_t offset, uint64_t size, elf_section_string_table **strtab);
enum elf_result elf_binary_memblock_as_reloc_table(elf_binary *bin,
	uint64_t offset, uint64_t size, uint32_t type,
	elf_section_relocation_table **rtab);
enum elf_result elf_binary_memblock_as_symbol_table(elf_binary *bin,
			uint64_t offset, uint64_t size, uint64_t off_strtab,
			elf_section_symbol_table **symtab);

enum elf_result elf_binary_resize(elf_binary *bin, uint64_t new_size);

enum elf_result elf_binary_add_section_to_list(elf_binary *bin,
						elf_section *section);

#endif