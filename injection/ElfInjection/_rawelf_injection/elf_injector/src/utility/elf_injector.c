/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_injector.h"
#include "elf_code_injection.h"

#include "elf_binary.h"
#include "elf_section_dynamic.h"
#include "elf_section_string_table.h"
#include "elf_section_string_table_entry.h"

#include "elf_patcher.h"
#include "elf_misc.h"

// Standard
#include <string.h>

/*------------------------------------------------------------------------*/
/* Local Structure Definitions                                            */
/*------------------------------------------------------------------------*/
/*
* Represents code injected by a code - injection function.
* @offset: File offset of injected code.
* @size: Size of injected code in bytes.
*/
struct elf_injected_code {
	uint64_t offset;
	uint64_t size;
};

/*------------------------------------------------------------------------*/
/* Local Constants                                                        */
/*------------------------------------------------------------------------*/
/*static int64_t func_array_types[] = {
	DT_INIT_ARRAY,
	DT_FINI_ARRAY,
	DT_PREINIT_ARRAY,
};
#define FUNC_ARRAY_TYPES_SIZE (sizeof(func_array_types) / sizeof(int64_t))*/

static int64_t reloc_types[] = {
	DT_REL,
	DT_RELA,
	DT_JMPREL,
};
#define RELOC_TYPES_SIZE (sizeof(reloc_types) / sizeof(int64_t))

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
static enum elf_result _elf_inject_memory_patch(elf_binary *bin,
			uint64_t off_data, uint64_t sz_data,
			enum elf_injected_data_affiliation affiliation);

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_injector_inject_memory(elf_injector *injector,
	elf_binary *bin, const uint8_t *memory, uint64_t memory_size,
	uint64_t offset, enum elf_injected_data_affiliation affiliation)
{
	__label__ label_free_backup;

	enum elf_result result;
	uint8_t *backup;
	uint64_t old_bin_size;
	uint8_t *base;

	if (injector == NULL || bin == NULL || affiliation < 0 ||
	    affiliation >= ELF_AFFILIATION_MAX || memory == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Allocate backup memory:
	old_bin_size = elf_binary_get_size(bin);
	if (old_bin_size < offset)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	backup = calloc(1, old_bin_size - offset);
	if (backup == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
				ELF_PRINTTYPE_ERRNO);

	// 1. Resize file:
	result = elf_binary_resize(bin, old_bin_size + memory_size);
	if (result != ELF_COMMON_SUCCESS)
		goto label_free_backup;

	// 2. Move memory & 3. Insert injection data
	base = (uint8_t*)elf_binary_get_elf_header(bin);
	memcpy(backup, OFFSET(base, offset), old_bin_size - offset);
	memcpy(OFFSET(base, offset), memory, memory_size);
	memcpy(OFFSET(base, offset + memory_size), backup,
		old_bin_size - offset);

	// 4. Patch offsets and sizes.
	result = _elf_inject_memory_patch(bin, offset, memory_size,
						affiliation);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch binary.");
		goto label_free_backup;
	}

label_free_backup:
	free(backup);

	return result;
}


enum elf_result elf_injector_override_memory(elf_injector *injector,
	elf_binary *bin, const uint8_t *memory, uint64_t memory_size,
	uint64_t offset)
{
	uint8_t *vaddr;

	if (injector == NULL || bin == NULL || memory == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	vaddr = ((uint8_t*)elf_binary_get_elf_header(bin)) + offset;
	memcpy(vaddr, memory, memory_size);
	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_injector_inject_string(elf_injector *injector,
	elf_binary *bin, elf_section_string_table *strtab, const char *string,
	uint64_t *offset)
{
	enum elf_result result;
	elf_section_string_table_entry **list_entries;
	uint64_t amount_entries;
	uint64_t off_bin_strtab;
	uint64_t off_bin_new;
	elf_section_string_table_entry *last_entry;
	uint64_t strtab_size;
	uint64_t str_len;
	uint64_t max_align;
	uint8_t *buffer;
	uint64_t mem_size;

	if (injector == NULL || bin == NULL || strtab == NULL ||
	    string == NULL || offset == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	amount_entries = elf_section_string_table_get_amount_entries(strtab);
	if (amount_entries <= 1)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*offset = 0;

	list_entries = elf_section_string_table_get_list_entries(strtab);
	last_entry = list_entries[amount_entries - 1];
	off_bin_new = (uint64_t)elf_section_string_table_entry_get_string(last_entry) -
		      (uint64_t)elf_binary_get_elf_header(bin) +
		      elf_section_string_table_entry_get_length(last_entry) + 1;
	off_bin_strtab = (uint64_t)elf_section_string_table_entry_get_string(list_entries[0]) -
			 (uint64_t)elf_binary_get_elf_header(bin);

	result = elf_section_string_table_get_size(strtab, &strtab_size);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	str_len = strlen(string);
	if (strtab_size - (off_bin_new - off_bin_strtab) <= str_len) {
		// Need to use alignment...
		result = elf_get_max_align(elf_binary_get_segments(bin),
					elf_binary_get_amount_segments(bin),
					&max_align);
		if (result != ELF_COMMON_SUCCESS)
			return result;

		// If str_len > max_align => str_len = a * max_align + b
		// where b < max_align and str_len / max_align = a
		// => ((str_len / max_align) + 1) * max_alig = (a+1)*max_align
		// > str_len
		mem_size = ((str_len / max_align) + 1) * max_align;
		buffer = calloc(1, mem_size);
		if (buffer == NULL)
			log_return(ELF_LOGLEVEL_ERROR, ELF_STD_CALLOC,
					ELF_PRINTTYPE_ERRNO);
		memcpy(buffer, string, str_len);

		result = elf_injector_inject_memory(injector, bin, buffer,
				mem_size, off_bin_new,
				ELF_AFFILIATION_UPPER);
		free(buffer);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	} else {
		// Just override padding...
		result = elf_injector_override_memory(injector, bin,
			(const uint8_t*)string, str_len + 1, off_bin_new);
		if (result != ELF_COMMON_SUCCESS)
			return result;
	}

	*offset = off_bin_new - off_bin_strtab;

	return result;
}

enum elf_result elf_injector_inject_segment(elf_injector *injector,
	elf_binary *bin, Elf64_Phdr *phdr, uint8_t *memory)
{
	enum elf_result result;
	Elf64_Ehdr *ehdr;
	uint64_t offset;

	if (injector == NULL || bin == NULL || phdr == NULL || memory == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Inject new segment memory.
	ehdr = elf_binary_get_elf_header(bin);
	result = elf_injector_inject_memory(injector, bin, memory,
			phdr->p_filesz, phdr->p_offset, ELF_AFFILIATION_NONE);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
					"Failed to inject segment memory.");

	// Inject new PHT entry. Note that:
	// 	ehdr->e_phentsize = sizeof(Elf64_Phdr)
	ehdr = elf_binary_get_elf_header(bin);
	offset = ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr);

	// Recalculate offset and addresses of segment. Injection of pht entry
	// might influence the offset/addresses.
	if (phdr->p_offset >= offset) {
		phdr->p_offset += sizeof(Elf64_Phdr);
		phdr->p_vaddr += sizeof(Elf64_Phdr);
		phdr->p_paddr += sizeof(Elf64_Phdr);
	}

	result = elf_injector_inject_memory(injector, bin, (uint8_t*)phdr,
			sizeof(Elf64_Phdr), offset, ELF_AFFILIATION_UPPER);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
					"Failed to inject new PHT entry.");

	// Patch ELF - header
	ehdr->e_phnum += 1;

	return elf_binary_reload(bin, ELF_RELOAD_SEGMENTS);//result;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
enum elf_callback_retval _dyn_entry_callback(elf_section_dynamic_entry* entry, void* user_data);
enum elf_result _elf_inject_memory_patch(elf_binary *bin,
			uint64_t off_data, uint64_t sz_data,
			enum elf_injected_data_affiliation affiliation)
{
	__label__ label_free_patcher, label_free_segments, label_free_dynamic;
	enum elf_result result;
	elf_patcher *patcher;
	uint8_t has_sht;
	elf_segment **old_segments;
	uint32_t num_old_segments;
	elf_section_dynamic *dynamic;
	uint64_t i;

	patcher = elf_patcher_init();
	if (patcher == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	// Patch ELF - header
	result = elf_patcher_patch_ehdr(patcher, bin, off_data, sz_data);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch ELF - header.");
		goto label_free_patcher;
	}

	// Patch PHT
	num_old_segments = elf_binary_get_amount_segments(bin);
	result = elf_patcher_patch_pht(patcher, bin, off_data, sz_data,
					&old_segments, affiliation);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch PHT.");
		goto label_free_patcher;
	}

	// Patch SHT
	result = elf_binary_has_section_header_table(bin, &has_sht);
	if (result != ELF_COMMON_SUCCESS) {
		goto label_free_segments;
	} else if (has_sht == 0) {
		log(ELF_LOGLEVEL_INFO, ELF_BINARY_SHT_NOT_FOUND,
			ELF_PRINTTYPE_NONE);
	} else {
		result = elf_patcher_patch_sht(patcher, bin, off_data, sz_data,
						NULL, affiliation);
		if (result != ELF_COMMON_SUCCESS) {
			log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch SHT.");
			goto label_free_segments;
		}
	}

	// Patch .dynamic
	result = elf_get_dynamic(elf_binary_get_segments(bin), 
			elf_binary_get_amount_segments(bin), &dynamic);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to find .dynamic.");
		goto label_free_segments;
	}

	result = elf_patcher_patch_dynamic(patcher, bin, dynamic, old_segments,
						num_old_segments, off_data,
						sz_data, affiliation);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch .dynamic.");
		goto label_free_dynamic;
	}

	// Patch .init_array, .fini_array and .preinit_array
	/*for (i = 0; i < FUNC_ARRAY_TYPES_SIZE; i++) {
		result = elf_patcher_patch_func_array(patcher, bin, dynamic,
				old_segments, num_old_segments, off_data,
				sz_data, func_array_types[i]);
		if (result == ELF_SECTION_ENTRY_NOT_FOUND) {
			log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Failed to find function pointer array to patch.");
		} else if (result != ELF_COMMON_SUCCESS) {
			log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to patch function pointer array.");
			goto label_free_dynamic;
		}
	}*/

	// Patch .dynsym
	result = elf_patcher_patch_dynsym(patcher, bin, dynamic, old_segments,
						num_old_segments, off_data,
						sz_data);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to patch .dynsym.");
		goto label_free_dynamic;
	}

	// Patch DT_REL, DT_RELA and DT_JMPREL
	for (i = 0; i < RELOC_TYPES_SIZE; i++) {

		result = elf_patcher_patch_reloc(patcher, bin, dynamic,
				elf_binary_get_segments(bin),
				elf_binary_get_amount_segments(bin),
				old_segments, num_old_segments, reloc_types[i],
				off_data, sz_data);
		if (result == ELF_SECTION_ENTRY_NOT_FOUND) {
			log_forward(ELF_LOGLEVEL_SOFTERROR,
				"Failed to find relocation table to patch.");
		} else if (result != ELF_COMMON_SUCCESS) {
			log_forward(ELF_LOGLEVEL_ERROR,
				"Failed to patch relocation table.");
			goto label_free_dynamic;
		}
	}

	// Success
	result = ELF_COMMON_SUCCESS;

label_free_dynamic:
	elf_section_dynamic_free(dynamic);

label_free_segments:
	elf_patcher_free_segments(patcher, old_segments, num_old_segments);

label_free_patcher:
	elf_patcher_free(patcher);

	return result;
}