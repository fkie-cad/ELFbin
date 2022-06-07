/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "elf_misc.h"
#include "elf_translator.h"

#include "elf_binary.h"
#include "elf_segment.h"
#include "elf_section.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"
#include "elf_section_string_table.h"
#include "elf_section_string_table_entry.h"

// Standard
#include <string.h>
#include <stdlib.h>

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
static uint8_t _dynsym_check_name(uint32_t name,
					elf_section_string_table *dynstr);
static uint8_t _dynsym_check_value_info(elf_segment **segments,
	uint32_t num_segments, uint64_t value, uint8_t info);
static uint8_t _dynsym_check_other(uint8_t other);

static int _elf_find_file_code_cave_compare(const void *first,
						const void* second);

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_get_containing_segment_off(elf_segment **list_segments,
			uint32_t amount_segments, uint64_t off_bin_data,
			uint8_t loadable, elf_segment **container)
{
	enum elf_result result;
	elf_translator *translator;

	if (list_segments == NULL || container == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*container = NULL;

	// Construct translator
	translator = elf_translator_init();
	if (translator == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	result = elf_translator_get_surrounding_segment_offset(translator,
				list_segments, amount_segments, off_bin_data,
				loadable, container);

	elf_translator_free(translator);

	return result;
}

enum elf_result elf_get_containing_segment_vaddr(elf_segment **list_segments,
			uint32_t amount_segments, uint64_t vaddr_bin_data,
			uint8_t loadable, elf_segment **container)
{
	enum elf_result result;
	elf_translator *translator;

	if (list_segments == NULL || container == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*container = NULL;

	// Construct translator
	translator = elf_translator_init();
	if (translator == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_OBJECT_FAILED_INIT,
				ELF_PRINTTYPE_NONE);

	result = elf_translator_get_surrounding_segment_virtual(translator,
				list_segments, amount_segments, vaddr_bin_data,
				loadable, container);

	elf_translator_free(translator);

	return result;
}

enum elf_result elf_get_containing_section_off(elf_section **list_sections,
			uint32_t amount_sections, uint64_t off_bin_data,
			elf_section **container)
{
	uint64_t i;
	elf_section *current;
	Elf64_Shdr *raw;

	if (list_sections == NULL || amount_sections == 0 || container == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*container = NULL;

	for (i = 0; i < amount_sections; i++) {
		current = list_sections[i];
		raw = elf_section_get_section_header(current);

		if (raw->sh_offset <= off_bin_data &&
		    raw->sh_offset + raw->sh_size > off_bin_data)
			break;
	}

	if (i == amount_sections)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SECTION_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	*container = current;
	return ELF_COMMON_SUCCESS;

}

enum elf_result elf_get_max_align(elf_segment **list_segments,
				uint32_t amount_segments, uint64_t *max_align)
{
	elf_segment *current;
	Elf64_Phdr *raw;
	uint32_t i;

	if (list_segments == NULL || max_align == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	raw = elf_segment_get_program_header(
					list_segments[0]);
	*max_align = raw->p_align;
	for (i = 1; i < amount_segments; i++) {
		current = list_segments[i];
		raw = elf_segment_get_program_header(current);
		if (raw->p_align > *max_align)
			*max_align = raw->p_align;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_get_dynamic(elf_segment **list_segments,
		uint32_t amount_segments, elf_section_dynamic **dynamic)
{
	elf_segment *current;
	Elf64_Phdr *raw;
	uint32_t i;

	if (list_segments == NULL || dynamic == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*dynamic = NULL;
	for (i = 0; i < amount_segments; i++) {
		current = list_segments[i];
		raw = elf_segment_get_program_header(current);
		if (raw->p_type == PT_DYNAMIC)
			break;
	}

	if (i == amount_segments)
		log_return(ELF_LOGLEVEL_ERROR, ELF_BINARY_SEGMENT_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	return elf_segment_map_to_dynamic(current, dynamic);
}

enum elf_result elf_extract_section(elf_section_dynamic *dynamic,
	int64_t vaddr_type, int64_t size_type, int64_t entsize_type,
	struct elf_abs_section *abs)
{
	elf_section_dynamic_entry **list_entries;
	elf_section_dynamic_entry *current;
	Elf64_Dyn *raw;
	uint64_t amount_entries;
	uint64_t i;

	if (dynamic == NULL || abs == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	abs->vaddr = NULL;
	abs->size = NULL;
	abs->entsize = NULL;

	amount_entries = elf_section_dynamic_get_amount_entries(dynamic);
	if (amount_entries < 2)
		log_forward_return(ELF_LOGLEVEL_ERROR,
			ELF_COMMON_INVALID_PARAMETERS,
			"Given .dynamic section must contain at least 2 entries.");

	list_entries = elf_section_dynamic_get_list_entries(dynamic);
	for (i = 0; i < amount_entries; i++) {
		current = list_entries[i];
		raw = elf_section_dynamic_entry_get_raw_entry(current);
		if (vaddr_type != DT_NULL &&
		    raw->d_tag == vaddr_type &&
		    abs->vaddr == NULL)
		    	abs->vaddr = &raw->d_un.d_ptr;
		if (size_type != DT_NULL &&
		    raw->d_tag == size_type &&
		    abs->size == NULL)
			abs->size = &raw->d_un.d_val;
		if (entsize_type != DT_NULL &&
		    raw->d_tag == entsize_type &&
		    abs->entsize == NULL)
			abs->entsize = &raw->d_un.d_val;
	}

	return ELF_COMMON_SUCCESS;
}

enum elf_result elf_get_dynstr(elf_binary *bin, elf_section_dynamic *dynamic,
					elf_section_string_table **dynstr)
{
	enum elf_result result;
	struct elf_abs_section abs;
	elf_segment *container;
	Elf64_Phdr *raw;

	if (bin == NULL || dynamic == NULL || dynstr == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	result = elf_extract_section(dynamic, DT_STRTAB, DT_STRSZ, DT_NULL,
					&abs);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	if (abs.vaddr == NULL || abs.size == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), *abs.vaddr, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	raw = elf_segment_get_program_header(container);

	return elf_binary_memblock_as_string_table(bin,
		(*abs.vaddr - raw->p_vaddr) + raw->p_offset, *abs.size,
		dynstr);
}

enum elf_result elf_get_rel(elf_binary *bin, elf_section_dynamic *dynamic,
			int64_t type, elf_section_relocation_table **rel)
{
	enum elf_result result;
	int64_t sztype = 0;
	struct elf_abs_section abs;
	elf_segment *container;
	Elf64_Phdr *raw;
	uint32_t entry_type = DT_DEBUG;

	if (bin == NULL || dynamic == NULL || rel == NULL ||
	   (type != DT_REL && type != DT_RELA && type != DT_JMPREL))
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// For this procedure the type infers entsize!
	if (type == DT_REL) {
		entry_type = SHT_REL;
		sztype = DT_RELSZ;
	} else if (type == DT_RELA) {
		entry_type = SHT_RELA;
		sztype = DT_RELASZ;
	} else if (type == DT_JMPREL) {
		sztype = DT_PLTRELSZ;
	}

	result = elf_extract_section(dynamic, type, sztype, DT_PLTREL,
					&abs);

	if (result != ELF_COMMON_SUCCESS)
		return result;

	if (abs.vaddr == NULL || abs.size == NULL ||
	    (type == DT_JMPREL && abs.entsize == NULL))
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);
	if (type == DT_JMPREL)
		entry_type = ((uint32_t)*abs.entsize == DT_REL) ? SHT_REL
								: SHT_RELA;

	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), *abs.vaddr, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	raw = elf_segment_get_program_header(container);

	return elf_binary_memblock_as_reloc_table(bin,
		(*abs.vaddr - raw->p_vaddr) + raw->p_offset, *abs.size,
		entry_type, rel);
}

enum elf_result elf_get_dynsym(elf_binary *bin, elf_section_dynamic *dynamic,
				elf_segment **segments, uint32_t num_segments, 
				elf_section_symbol_table **dynsym)
{
	enum elf_result result;
	struct elf_abs_section abs;
	uint64_t num_symbols;
	elf_segment *container;
	Elf64_Phdr *raw;
	uint8_t is_valid;
	uint64_t off_sym;
	Elf64_Sym *sym;
	elf_section_string_table *dynstr;

	// Check parameters
	if (bin == NULL || dynamic == NULL || segments == NULL ||
	    dynsym == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Extract section that references relocations regarding .plt. This
	// gives an estimation of how many symbols exist.
	/*result = elf_extract_section(dynamic, DT_JMPREL, DT_PLTRELSZ,
					DT_PLTREL, &abs);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (abs.vaddr == NULL || abs.size == NULL || abs.entsize == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);
	if (*abs.entsize == DT_REL)
		num_symbols = *abs.size / sizeof(Elf64_Rel);
	else
		num_symbols = *abs.size / sizeof(Elf64_Rela);
	num_symbols++;	// First symbol is always empty!*/

	// Extract .dynsym
	result = elf_extract_section(dynamic, DT_SYMTAB, DT_NULL, DT_SYMENT,
					&abs);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	else if (abs.vaddr == NULL || abs.entsize == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Get segment that contains .dynsym
	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), *abs.vaddr, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
	raw = elf_segment_get_program_header(container);

	// Get corresponding string table .dynstr
	result = elf_get_dynstr(bin, dynamic, &dynstr);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Calculate file offset of .dynsym for iteration
	off_sym = *abs.vaddr - raw->p_vaddr + raw->p_offset;

	// Iterate through symbol table, starting at the very end of the
	// estimated amount of symbols. I.e. try to discover new symbols
	// until an invalid symbol entry is found.
	num_symbols = 1;
	do {
		sym = (Elf64_Sym*)OFFSET(elf_binary_get_elf_header(bin),
			off_sym + num_symbols * sizeof(Elf64_Sym));

		is_valid = 0;
		if (_dynsym_check_name(sym->st_name, dynstr) &&
		    _dynsym_check_value_info(segments, num_segments, sym->st_value, sym->st_info) &&
		    _dynsym_check_other(sym->st_other)) {
			is_valid = 1;
			num_symbols++;
		}
	} while(is_valid);

	elf_section_string_table_free(dynstr);

	// Get virtual address of .dynstr, because the final call requires
	// file offsets of .dynstr and .dynsym
	result = elf_extract_section(dynamic, DT_STRTAB, DT_NULL, DT_NULL,
					&abs);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
	else if (abs.vaddr == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_SECTION_ENTRY_NOT_FOUND,
				ELF_PRINTTYPE_NONE);

	// Get segment that contains .dynstr
	result = elf_get_containing_segment_vaddr(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), *abs.vaddr, 1,
			&container);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);
	raw = elf_segment_get_program_header(container);

	// Finally create symbol table from discovered symbols and .dynstr
	return elf_binary_memblock_as_symbol_table(bin,
		off_sym, num_symbols * sizeof(Elf64_Sym),
		(uint64_t)*abs.vaddr - raw->p_vaddr + raw->p_offset, dynsym);
}

enum elf_result elf_find_code_cave(elf_segment **segments,
	uint32_t num_segments, uint64_t sz_cave, enum elf_code_cave_type type,
	elf_segment **predecessor, elf_segment **successor,
	elf_code_cave_condition condition, void *user_data)
{
	__label__ label_free_loadables;
	enum elf_result result;
	elf_segment **list_loadables;
	elf_segment **temp;
	uint32_t num_loadables;
	Elf64_Phdr *cur;
	Elf64_Phdr *oth = NULL;
	uint32_t i;

	if (segments == NULL || num_segments == 0 ||
	    type >= ELF_CODE_CAVE_TYPE_MAX || predecessor == NULL ||
	    successor == NULL || condition == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	*predecessor = NULL;
	*successor = NULL;

	// Get list of loadable segments in ascending order, sorted by .p_vaddr
	list_loadables = NULL;
	num_loadables = 0;
	for (i = 0; i < num_segments; i++) {
		cur = elf_segment_get_program_header(segments[i]);
		if (cur->p_type != PT_LOAD)
			continue;

		temp = reallocarray(list_loadables, num_loadables + 1,
					sizeof(elf_segment*));
		if (temp == NULL) {
			result = ELF_STD_REALLOCARRAY;
			log(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_ERRNO);
			goto label_free_loadables;
		}
		list_loadables = temp;

		list_loadables[num_loadables] = segments[i];
		num_loadables += 1;
	}

	// Reorder list of loadable segments by .p_offset, if necessary
	if (type == ELF_CODE_CAVE_TYPE_FILE)
		qsort(list_loadables, num_loadables, sizeof(elf_segment*),
			_elf_find_file_code_cave_compare);

	// Seek code cave BETWEEN loadable segments
	for (i = 0; i < num_loadables - 1; i++) {

		cur = elf_segment_get_program_header(list_loadables[i]);
		oth = elf_segment_get_program_header(list_loadables[i + 1]);
		if (condition(cur, oth, sz_cave, user_data)
			== ELF_CALLBACK_BREAK) {
			*predecessor = list_loadables[i];
			*successor = list_loadables[i + 1];
			result = ELF_COMMON_SUCCESS;
			goto label_free_loadables;
		}
	}

	// Check for code cave after last loadable segment.
	if (condition(oth, NULL, sz_cave, user_data) == ELF_CALLBACK_BREAK) {
		*predecessor = list_loadables[i];
		*successor = list_loadables[i + 1];
	}
	result = ELF_COMMON_SUCCESS;

label_free_loadables:
	free(list_loadables);

	return result;
}

enum elf_result elf_pht_is_equal(Elf64_Phdr *first, Elf64_Phdr *second,
					uint8_t *equal)
{
	if (first == NULL || second == NULL || equal == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	if (memcmp((void*)first, (void*)second, sizeof(Elf64_Phdr)) == 0)
		*equal = 1;
	else
		*equal = 0;
	return ELF_COMMON_SUCCESS;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
/*
* NOTE: It is considered a valid name offset if 'name' points to a null
*	terminator of a string within the string table. I.e. ALL substrings
*	are possible, also empty substrings!
*/
uint8_t _dynsym_check_name(uint32_t name, elf_section_string_table *dynstr)
{
	elf_section_string_table_entry **list_entries;
	elf_section_string_table_entry *current;
	uint64_t amount_entries;
	uint64_t i;
	uint64_t off;
	uint64_t size;

	// Check if 'name' is a valid string offset
	list_entries = elf_section_string_table_get_list_entries(dynstr);
	amount_entries = elf_section_string_table_get_amount_entries(dynstr);
	for (i = 0; i < amount_entries; i++) {
		current = list_entries[i];
		off = elf_section_string_table_entry_get_offset(current);
		size = elf_section_string_table_entry_get_length(current);
		if (name >= off && name <= off + size)
			return 1;
	}

	return 0;
}

/*
* NOTE: This function assumes that functions only reside in executable segments.
*/
uint8_t _dynsym_check_value_info(elf_segment **segments, uint32_t num_segments,
					uint64_t value, uint8_t info)
{
	enum elf_result result;
	elf_segment *container;
	Elf64_Phdr *raw;
	uint8_t type;
	uint8_t bind;

	// Check program header and ensure that 'value' points into a loadable
	// segment
	result = elf_get_containing_segment_vaddr(segments, num_segments,
							value, 1, &container);
	if (result != ELF_COMMON_SUCCESS) {
		log(ELF_LOGLEVEL_SOFTERROR, result, ELF_PRINTTYPE_NONE);
		return 0;
	}
	raw = elf_segment_get_program_header(container);

	// Check type
	type = ELF64_ST_TYPE(info);
	if (!(type >= STT_LOOS && type <= STT_HIOS) &&
	    !(type >= STT_LOPROC && type <= STT_HIPROC)) {
		switch (type) {
		case STT_FUNC:
			// Function in non-executable segment!
			if ((raw->p_flags & PF_X) == 0 && value != 0)
				return 0;
		case STT_NOTYPE:
		case STT_OBJECT:
		case STT_SECTION:
		case STT_FILE:
		case STT_COMMON:
		case STT_TLS:
			break;
		default:
			return 0;
		}
	}

	// Check binding
	bind = ELF64_ST_BIND(info);
	if (!(bind >= STB_LOOS && bind <= STB_HIOS) &&
	    !(bind >= STB_LOPROC && bind <= STB_HIPROC)) {
		switch (bind) {
		case STB_LOCAL:
		case STB_GLOBAL:
		case STB_WEAK:
			break;
		default:
			return 0;
		}
	}

	return 1;
}

uint8_t _dynsym_check_other(uint8_t other)
{
	return ((other <= 3) ? 1 : 0);
}

int _elf_find_file_code_cave_compare(const void *first, const void* second)
{
	elf_segment *fir = (elf_segment*)first;
	elf_segment *sec = (elf_segment*)second;
	return (elf_segment_get_program_header(fir)->p_offset
		- elf_segment_get_program_header(sec)->p_offset);
}