/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_patcher.h"
#include "elf_misc.h"
#include "elf_platform.h"

#include "elf_binary.h"
#include "elf_segment.h"
#include "elf_section.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"
#include "elf_section_symbol_table.h"
#include "elf_section_symbol_table_entry.h"
#include "elf_section_relocation_table.h"
#include "elf_section_relocation_table_entry.h"

// Standard
#include <string.h>

/*------------------------------------------------------------------------*/
/* Local Constants                                                        */
/*------------------------------------------------------------------------*/
static int64_t type_matrix[][3] = {
	{ DT_PLTGOT, DT_NULL, DT_NULL },
	{ DT_HASH, DT_NULL, DT_NULL },
	{ DT_STRTAB, DT_STRSZ, DT_NULL },
	{ DT_SYMTAB, DT_NULL, DT_SYMENT },
	{ DT_RELA, DT_RELASZ, DT_RELAENT },
	{ DT_INIT, DT_NULL, DT_NULL },
	{ DT_FINI, DT_NULL, DT_NULL },
	{ DT_REL, DT_RELSZ, DT_RELENT },
	{ DT_JMPREL, DT_PLTRELSZ, DT_NULL },
	{ DT_INIT_ARRAY, DT_INIT_ARRAYSZ, DT_NULL },
	{ DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_NULL },
	{ DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, DT_NULL },
	{ DT_SYMTAB_SHNDX, DT_NULL, DT_NULL },

	// These types do not conform to System V gABI, but are often used
	// regardless. They should conform to LSB.
	{ DT_VERSYM, DT_NULL, DT_NULL },
	{ DT_VERDEF, DT_NULL, DT_NULL },
	{ DT_VERNEED, DT_NULL, DT_NULL },

	// System V gABI Linux extension implicitly requires the following:
	{ DT_GNU_HASH, DT_NULL, DT_NULL },
};
#define SEC_AMOUNT_NDX (sizeof(type_matrix) / (3 * sizeof(int64_t)))

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
// Copy old list of segments/sections
static enum elf_result _elf_copy_segments(elf_patcher *patcher,
				elf_binary *bin, elf_segment ***segments);
static enum elf_result _elf_copy_sections(elf_patcher *patcher,
				elf_binary *bin, elf_section ***sections);

// Override / adjust offsets and sizes
static void _elf_patch_segment(elf_segment *current, //elf_segment *affected,
			uint64_t data, uint64_t data_size,
			enum elf_injected_data_affiliation affiliation);
static void _elf_patch_section(elf_section *current, elf_section *affected,
			uint64_t data, uint64_t data_size,
			enum elf_injected_data_affiliation affiliation);

// Check affiliation of an offset.
static enum elf_result _elf_is_affected_segment(uint64_t data,
				elf_segment *affected, uint8_t *is_affected);
static enum elf_result _elf_get_affected_section(elf_binary *bin,
					uint64_t data, elf_section **affected);

// .dynamic - patching functions
static enum elf_result _elf_get_list_sections(elf_section_dynamic *dynamic,
		struct elf_abs_section **sections, uint64_t *num_sections);
static enum elf_result _elf_patch_sections(struct elf_abs_section *sections,
	uint64_t num_sections, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data,
	enum elf_injected_data_affiliation affiliation);
static void _elf_patch_dynamic_entry(struct elf_abs_section *current,
			uint64_t data, uint64_t data_size, Elf64_Phdr *raw,
			enum elf_injected_data_affiliation affiliation);

// init_array, fini_array and preinit_array patching
static void _elf_patch_func_ptr(uint64_t *vaddr, Elf64_Phdr *raw,
				uint64_t off_data, uint64_t sz_data);

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_patcher_patch_ehdr(elf_patcher *patcher, elf_binary *bin,
					uint64_t off_data, uint64_t sz_data)
{
	enum elf_result result;
	elf_segment *container;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *raw;
	uint64_t off;
	uint16_t string_index;

	if (patcher == NULL || bin == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	ehdr = elf_binary_get_elf_header(bin);
	if (ehdr->e_phoff >= off_data) {
		ehdr->e_phoff += sz_data;
		result = elf_binary_reload(bin, ELF_RELOAD_SEGMENTS);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	// If SHT does not exist, we dont want to set 'e_shoff' != 0
	if (ehdr->e_shoff != 0 && ehdr->e_shoff >= off_data) {
		ehdr->e_shoff += sz_data;

		string_index = ehdr->e_shstrndx;
		ehdr->e_shstrndx = SHN_UNDEF;	// temporarly disabled
		result = elf_binary_reload(bin, ELF_RELOAD_SECTIONS);
		ehdr->e_shstrndx = string_index;
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), ehdr->e_entry, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	raw = elf_segment_get_program_header(container);
	off = ehdr->e_entry - raw->p_vaddr + raw->p_offset;
	if (off >= off_data)
		ehdr->e_entry += sz_data;

	return result;
}

enum elf_result elf_patcher_patch_pht(elf_patcher *patcher, elf_binary *bin,
	uint64_t off_data, uint64_t sz_data, elf_segment ***old_segments,
	enum elf_injected_data_affiliation affiliation)
{
	__label__ label_return;
	enum elf_result result;
	elf_segment **segments;
	uint32_t num_segments;
	uint32_t i;

	if (patcher == NULL || bin == NULL || affiliation < 0 ||
	    affiliation >= ELF_AFFILIATION_MAX)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	if (old_segments != NULL) {
		result = _elf_copy_segments(patcher, bin, old_segments);
		if (result != ELF_COMMON_SUCCESS)
			log_forward_return(ELF_LOGLEVEL_ERROR, result,
					"Failed to copy list of segments.");
	}

	segments = elf_binary_get_segments(bin);
	num_segments = elf_binary_get_amount_segments(bin);
	for (i = 0; i < num_segments; i++) {
		_elf_patch_segment(segments[i], off_data, sz_data,
					affiliation);
	}

	result = elf_binary_reload(bin, ELF_RELOAD_SEGMENTS);
	if (result == ELF_COMMON_SUCCESS)
		goto label_return;

	elf_patcher_free_segments(patcher, *old_segments, num_segments);

label_return:
	return result;
}

enum elf_result elf_patcher_patch_sht(elf_patcher *patcher, elf_binary *bin,
	uint64_t off_data, uint64_t sz_data, elf_section ***old_sections,
	enum elf_injected_data_affiliation affiliation)
{
	__label__ label_return;
	enum elf_result result;
	elf_section *affected;
	elf_section **sections;
	uint32_t num_sections;
	uint32_t i;

	if (patcher == NULL || bin == NULL || affiliation < 0 ||
	    affiliation >= ELF_AFFILIATION_MAX)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	result = _elf_get_affected_section(bin, off_data, &affected);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	if (old_sections != NULL) {
		result = _elf_copy_sections(patcher, bin, old_sections);
		if (result != ELF_COMMON_SUCCESS)
			log_forward_return(ELF_LOGLEVEL_ERROR, result,
					"Failed to copy list of sections.");
	}

	sections = elf_binary_get_sections(bin);
	num_sections = elf_binary_get_amount_sections(bin);
	for (i = 0; i < num_sections; i++) {
		_elf_patch_section(sections[i], affected, off_data, sz_data,
				affiliation);
	}

	result = elf_binary_reload(bin, ELF_RELOAD_SECTIONS);
	if (result == ELF_COMMON_SUCCESS)
		goto label_return;

	elf_patcher_free_sections(patcher, *old_sections, num_sections);

label_return:
	return result;
}

enum elf_result elf_patcher_patch_dynamic(elf_patcher *patcher,
	elf_binary *bin, elf_section_dynamic *dynamic, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data,
	enum elf_injected_data_affiliation affiliation)
{
	__label__ label_free_sections;
	enum elf_result result;
	struct elf_abs_section *sections;
	uint64_t num_sections;

	if (patcher == NULL || bin == NULL || dynamic == NULL ||
	    old_segments == NULL || affiliation < 0 ||
	    affiliation >= ELF_AFFILIATION_MAX)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = _elf_get_list_sections(dynamic, &sections, &num_sections);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
			"Failed to get list of sections from .dynamic.");

	result = _elf_patch_sections(sections, num_sections, old_segments,
			num_old_segments, off_data, sz_data, affiliation);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to patch sections in .dynamic.");
		goto label_free_sections;
	}

label_free_sections:
	free(sections);

	return result;
}

enum elf_result elf_patcher_patch_func_array(elf_patcher *patcher,
	elf_binary *bin, elf_section_dynamic *dynamic,
	elf_segment **old_segments, uint32_t num_old_segments,
	uint64_t off_data, uint64_t sz_data, int64_t type)
{
	enum elf_result result;
	struct elf_abs_section abs;
	int64_t sz_type;
	elf_segment *container;
	Elf64_Phdr *raw;
	uint64_t *func_ptrs;
	uint64_t num_func_ptrs;
	uint64_t i;

	// Check parameters
	if (patcher == NULL || dynamic == NULL || old_segments == NULL ||
	    (type != DT_INIT_ARRAY && type != DT_FINI_ARRAY && type != DT_PREINIT_ARRAY))
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	
	// Initialise search criteria and search for respective array
	if (type == DT_INIT_ARRAY)
		sz_type = DT_INIT_ARRAYSZ;
	else if (type == DT_FINI_ARRAY)
		sz_type = DT_FINI_ARRAYSZ;
	else
		sz_type = DT_PREINIT_ARRAYSZ;
	result = elf_extract_section(dynamic, type, sz_type, DT_NULL, &abs);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (abs.vaddr == NULL || abs.size == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Get segment that contains found array
	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), *abs.vaddr, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (container == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SEGMENT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Calculate file offset of array
	raw = elf_segment_get_program_header(container);
	func_ptrs = (uint64_t*)(*abs.vaddr - raw->p_vaddr + raw->p_offset
			       + (uint64_t)elf_binary_get_elf_header(bin));
	num_func_ptrs = *abs.size / sizeof(void*);	// assume 8-byte pointers

	// Iterate through array and apply patches if needed
	for (i = 0; i < num_func_ptrs; i++) {

		// Get segment that surrounds the current function pointer
		result = elf_get_containing_segment_vaddr(old_segments,
				num_old_segments, func_ptrs[i], 1, &container);
		if (result != ELF_COMMON_SUCCESS)
			return result;
		else if (container == NULL)
			log_return(ELF_LOGLEVEL_ERROR,
					ELF_BINARY_SEGMENT_NOT_FOUND,
					ELF_PRINTTYPE_NONE);
		raw = elf_segment_get_program_header(container);

		// Check if function pointer needs to be patched
		_elf_patch_func_ptr(&func_ptrs[i], raw, off_data, sz_data);
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_patcher_patch_dynsym(elf_patcher *patcher, elf_binary *bin,
	elf_section_dynamic *dynamic, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data)
{
	__label__ label_free_dynsym;
	enum elf_result result;
	elf_section_symbol_table *dynsym;
	elf_section_symbol_table_entry **list_entries;
	uint64_t amount_entries;
	elf_section_symbol_table_entry *current;
	Elf64_Sym *raw;
	elf_segment *container;
	uint64_t i;
	Elf64_Phdr *container_raw;

	if (patcher == NULL || bin == NULL || dynamic == NULL ||
	    old_segments == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_get_dynsym(bin, dynamic, old_segments, num_old_segments,
				&dynsym);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	list_entries = elf_section_symbol_table_get_list_entries(dynsym);
	amount_entries = elf_section_symbol_table_get_amount_entries(dynsym);

	for (i = 0; i < amount_entries; i++) {
		current = list_entries[i];
		raw = elf_section_symbol_table_entry_get_raw_entry(current);
		
		// Nothing to patch
		if (raw->st_value == 0 && raw->st_shndx == SHN_UNDEF)
			continue;

		result = elf_get_containing_segment_vaddr(old_segments,
					num_old_segments, raw->st_value, 1,
					&container);
		if (result != ELF_COMMON_SUCCESS) {
			log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to get containing segment of symbol's vaddr.");
			goto label_free_dynsym;
		}
		container_raw = elf_segment_get_program_header(container);
		if (raw->st_value - container_raw->p_vaddr + container_raw->p_offset >= off_data)
			raw->st_value += sz_data;
	}

label_free_dynsym:
	elf_section_symbol_table_free(dynsym);
	return result;
}

enum elf_result elf_patcher_patch_reloc(elf_patcher *patcher, elf_binary *bin,
	elf_section_dynamic *dynamic, elf_segment **new_segments,
	uint32_t num_new_segments, elf_segment **old_segments,
	uint32_t num_old_segments, int64_t type, uint64_t off_data,
	uint64_t sz_data)
{
	__label__ label_free_rtab;
	enum elf_result result;
	elf_section_relocation_table *rtab;
	elf_section_relocation_table_entry **list_entries;
	uint64_t amount_entries;
	elf_section_relocation_table_entry *current;
	Elf64_Rel *rel;
	Elf64_Rela *rela;
	uint64_t i;

	if (patcher == NULL || bin == NULL || dynamic == NULL ||
	    old_segments == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_get_rel(bin, dynamic, type, &rtab);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	list_entries = elf_section_relocation_table_get_list_entries(rtab);
	amount_entries = elf_section_relocation_table_get_amount_entries(rtab);
	type = elf_section_relocation_table_get_type(rtab);

	for (i = 0; i < amount_entries; i++) {
		current = list_entries[i];
		if (type == SHT_REL) {
			rel = elf_section_relocation_table_entry_get_rel(
								current);
			result = elf_platform_patch_rel(bin, new_segments,
						num_new_segments, old_segments,
						num_old_segments, rel,
						off_data, sz_data);
			if (result != ELF_COMMON_SUCCESS &&
			    result != ELF_RELOC_TYPE_NOT_SUPPORTED)
				goto label_free_rtab;
		} else {
			rela = elf_section_relocation_table_entry_get_rela(
								current);

			result = elf_platform_patch_rela(bin, new_segments,
						num_new_segments, old_segments,
						num_old_segments, rela,
						off_data, sz_data);
			if (result != ELF_COMMON_SUCCESS &&
			    result != ELF_RELOC_TYPE_NOT_SUPPORTED)
				goto label_free_rtab;
		}
	}


label_free_rtab:
	elf_section_relocation_table_free(rtab);

	return result;
}

enum elf_result elf_patcher_free_segments(elf_patcher *patcher,
				elf_segment **segments, uint32_t num_segments)
{
	uint32_t i;
	Elf64_Phdr *raw;

	if (patcher == NULL || segments == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	for (i = 0; i < num_segments; i++) {
		if (segments[i] == NULL)
			continue;
		raw = elf_segment_get_program_header(segments[i]);
		if (raw != NULL)
			free(raw);
		elf_segment_free(segments[i]);
	}

	free(segments);
	*segments = NULL;
	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_patcher_free_sections(elf_patcher *patcher,
				elf_section **sections, uint64_t num_sections)
{
	uint64_t i;
	Elf64_Shdr *raw;

	if (patcher == NULL || sections == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	for (i = 0; i < num_sections; i++) {
		if (sections[i] == NULL)
			continue;
		raw = elf_section_get_section_header(sections[i]);
		if (raw != NULL)
			free(raw);
		elf_section_free(sections[i]);
	}

	free(sections);
	*sections = NULL;
	return ELF_COMMON_SUCCESS;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
enum elf_result _elf_copy_segments(elf_patcher *patcher,
				elf_binary *bin, elf_segment ***segments)
{
	__label__ label_free_segments, label_return;
	enum elf_result result;
	elf_segment **list_segments;
	uint32_t amount_segments;
	uint32_t i;
	Elf64_Phdr *raw;

	*segments = NULL;

	amount_segments = elf_binary_get_amount_segments(bin);
	list_segments = calloc(amount_segments, sizeof(elf_segment*));
	if (list_segments == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);
	for (i = 0; i < amount_segments; i++) {
		list_segments[i] = elf_segment_init();
		if (list_segments[i] == NULL) {
			result = ELF_OBJECT_FAILED_INIT;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
			goto label_free_segments;
		}

		raw = calloc(1, sizeof(Elf64_Phdr));
		if (raw == NULL) {
			result = ELF_STD_CALLOC;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_free_segments;
		}

		*raw = *elf_segment_get_program_header(
					elf_binary_get_segments(bin)[i]);

		elf_segment_set_program_header(list_segments[i], raw);
		elf_segment_set_binary(list_segments[i], bin);
	}

	result = ELF_COMMON_SUCCESS;
	*segments = list_segments;
	goto label_return;

label_free_segments:
	elf_patcher_free_segments(patcher, list_segments, amount_segments);

label_return:
	return result;
}

enum elf_result _elf_copy_sections(elf_patcher *patcher,
				elf_binary *bin, elf_section ***sections)
{
	__label__ label_free_sections, label_return;
	enum elf_result result;
	elf_section **list_sections;
	uint64_t amount_sections;
	uint64_t i;
	Elf64_Shdr *raw;

	*sections = NULL;

	amount_sections = elf_binary_get_amount_sections(bin);
	list_sections = calloc(amount_sections, sizeof(elf_section*));
	if (list_sections == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);
	for (i = 0; i < amount_sections; i++) {
		list_sections[i] = elf_section_init();
		if (list_sections[i] == NULL) {
			result = ELF_OBJECT_FAILED_INIT;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
			goto label_free_sections;
		}

		raw = calloc(1, sizeof(Elf64_Shdr));
		if (raw == NULL) {
			result = ELF_STD_CALLOC;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_free_sections;
		}

		*raw = *elf_section_get_section_header(
					elf_binary_get_sections(bin)[i]);

		elf_section_set_section_header(list_sections[i], raw);
		elf_section_set_binary(list_sections[i], bin);
	}

	result = ELF_COMMON_SUCCESS;
	*sections = list_sections;
	goto label_return;

label_free_sections:
	elf_patcher_free_sections(patcher, list_sections, amount_sections);

label_return:
	return result;
}

void _elf_patch_segment(elf_segment *current, uint64_t data,
			uint64_t data_size,
			enum elf_injected_data_affiliation affiliation)
{
	Elf64_Phdr *raw = elf_segment_get_program_header(current);
	uint8_t is_affected;
	_elf_is_affected_segment(data, current, &is_affected);
	if (is_affected != 0) {
		// Data injected into 'current'.
		raw->p_filesz += data_size;
		raw->p_memsz += data_size;
	} else if (raw->p_offset == data) {
		// Data at beginning of 'current'.
		if (affiliation == ELF_AFFILIATION_LOWER) {
			// Associate data with 'current'.
			raw->p_filesz += data_size;
			raw->p_memsz += data_size;
		} else {
			// else
			raw->p_offset += data_size;
			raw->p_vaddr += data_size;
			raw->p_paddr += data_size;
		}
	} else if (raw->p_offset + raw->p_filesz == data) {
		// Data right after 'current'.
		if (affiliation == ELF_AFFILIATION_UPPER) {
			// Associate data with 'current'.
			raw->p_filesz += data_size;
			raw->p_memsz += data_size;
		}
	} else if (raw->p_offset > data) {
		// Data somewhere before 'current'.
		raw->p_offset += data_size;
		raw->p_vaddr += data_size;
		raw->p_paddr += data_size;
	}
}

void _elf_patch_section(elf_section *current, elf_section *affected,
			uint64_t data, uint64_t data_size,
			enum elf_injected_data_affiliation affiliation)
{
	Elf64_Shdr *raw = elf_section_get_section_header(current);

	if (current == affected) {
		raw->sh_size += data_size;
	} else if (raw->sh_offset == data) {
		if (affiliation == ELF_AFFILIATION_LOWER) {
			raw->sh_size += data_size;
		} else {
			raw->sh_offset += data_size;
			if (raw->sh_addr != 0)
				raw->sh_addr += data_size;
		}
	} else if (raw->sh_offset + raw->sh_size == data) {
		if (affiliation == ELF_AFFILIATION_UPPER) {
			raw->sh_size += data_size;
		}
	} else if (raw->sh_offset > data) {
		raw->sh_offset += data_size;

		if (raw->sh_addr != 0)
			raw->sh_addr += data_size;
	}
}

enum elf_result _elf_is_affected_segment(uint64_t data, elf_segment *affected,
						uint8_t *is_affected)
{
	Elf64_Phdr *raw = elf_segment_get_program_header(affected);
	if (raw->p_offset < data && raw->p_offset + raw->p_filesz > data)
		*is_affected = 1;
	else
		*is_affected = 0;
	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_get_affected_section(elf_binary *bin, uint64_t data,
						elf_section **affected)
{
	enum elf_result result;
	Elf64_Shdr *raw;

	result = elf_get_containing_section_off(elf_binary_get_sections(bin),
			elf_binary_get_amount_sections(bin), data, affected);
	if (result == ELF_BINARY_SECTION_NOT_FOUND) {
		*affected = NULL;
	} else if (result != ELF_COMMON_SUCCESS) {
		return result;
	} else {
		raw = elf_section_get_section_header(*affected);
		if (raw->sh_offset == data)
			*affected = NULL;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_get_list_sections(elf_section_dynamic *dynamic,
		struct elf_abs_section **sections, uint64_t *num_sections)
{
	__label__ label_free_list_sh, label_free_stripped;
	enum elf_result result;
	struct elf_abs_section *list_sh;
	uint64_t i;
	struct elf_abs_section *stripped;
	struct elf_abs_section *temp;
	uint64_t num_sh;

	list_sh = calloc(SEC_AMOUNT_NDX, sizeof(struct elf_abs_section));
	if (list_sh == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);

	for (i = 0; i < SEC_AMOUNT_NDX; i++) {
		result = elf_extract_section(dynamic, type_matrix[i][0],
					type_matrix[i][1], type_matrix[i][2],
					&list_sh[i]);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	stripped = NULL;
	for (i = 0, num_sh = 0; i < SEC_AMOUNT_NDX; i++) {

		if (list_sh[i].vaddr == NULL &&
		    list_sh[i].size == NULL &&
		    list_sh[i].entsize == NULL)
			continue;
		temp = reallocarray(stripped, num_sh + 1,
					sizeof(struct elf_abs_section));
		if (temp == NULL) {
			result = ELF_STD_REALLOCARRAY;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_free_stripped;
		}
		stripped = temp;
		memcpy(&stripped[num_sh], &list_sh[i],
				sizeof(struct elf_abs_section));
		num_sh++;
	}
	*sections = stripped;
	*num_sections = num_sh;
	goto label_free_list_sh;

label_free_stripped:
	free(stripped);

label_free_list_sh:
	free(list_sh);

	return result;
}

enum elf_result _elf_patch_sections(struct elf_abs_section *sections,
	uint64_t num_sections, elf_segment **old_segments,
	uint32_t num_old_segments, uint64_t off_data, uint64_t sz_data,
	enum elf_injected_data_affiliation affiliation)
{
	struct elf_abs_section *current;
	elf_segment *affected;
	Elf64_Phdr *raw;
	uint64_t i;

	for (i = 0; i < num_sections; i++) {
		current = &sections[i];
		if (current->vaddr == NULL)
			continue;

		elf_get_containing_segment_vaddr(old_segments,
			num_old_segments, *current->vaddr, 1, &affected);
		if (affected == NULL)
			continue;
		raw = elf_segment_get_program_header(affected);
		_elf_patch_dynamic_entry(current, off_data, sz_data, raw,
					affiliation);
	}
	return ELF_COMMON_SUCCESS;
}

void _elf_patch_dynamic_entry(struct elf_abs_section *current, uint64_t data,
			uint64_t data_size, Elf64_Phdr *raw,
			enum elf_injected_data_affiliation affiliation)
{
	uint64_t rel_addr;
	uint64_t rel_off;

	// Comparison on "segment level".
	if (data < raw->p_offset) {
		// 'data' points somewhere before segment
		*current->vaddr += data_size;
		return;
	} else if (data > raw->p_offset + raw->p_filesz) {
		// 'data' points somewhere behind segment
		return;
	}

	// Comparison on "section level".
	// 'data' points into 'affected_segment'.
	rel_addr = *current->vaddr - raw->p_vaddr;
	rel_off = data - raw->p_offset;
	if (current->size != NULL) {
		if (rel_addr < rel_off &&
		    rel_addr + *current->size > rel_off) {
			*current->size += data_size;
		} else if (rel_addr == rel_off) {
			if (affiliation == ELF_AFFILIATION_LOWER)
				*current->size += data_size;
			else
				*current->vaddr += data_size;
		} else if (rel_addr + *current->size == rel_off) {
			if (affiliation == ELF_AFFILIATION_UPPER)
				*current->size += data_size;
		} else if (rel_addr > rel_off) {
			*current->vaddr += data_size;
		}
	} else {
		// lonely pointer
		if (rel_addr == rel_off &&
		    affiliation != ELF_AFFILIATION_LOWER)
			*current->vaddr += data_size;
		else if (rel_addr > rel_off)
			*current->vaddr += data_size;
	}
}

void _elf_patch_func_ptr(uint64_t *vaddr, Elf64_Phdr *raw,
				uint64_t off_data, uint64_t sz_data)
{
	if (*vaddr - raw->p_vaddr + raw->p_offset >= off_data)
		*vaddr += sz_data;
}