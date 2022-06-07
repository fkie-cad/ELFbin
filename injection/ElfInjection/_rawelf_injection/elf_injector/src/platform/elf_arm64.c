/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "./internal/elf_internal.h"
#include "./platform/elf_arm64.h"

#include "elf_misc.h"

#include "elf_binary.h"
#include "elf_segment.h"
#include "elf_section_dynamic.h"
#include "elf_section_symbol_table.h"
#include "elf_section_symbol_table_entry.h"

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_arm64_patch_rel(elf_binary *bin, elf_segment **segments,
		uint32_t num_segments, elf_segment **old_segments,
		uint32_t num_old_segments, Elf64_Rel *rel, uint64_t data,
		uint64_t data_size)
{
	__label__ label_free_dynamic;

	enum elf_result result = ELF_COMMON_SUCCESS;
	elf_section_dynamic *dynamic;
	elf_section_symbol_table *dynsym;
	uint8_t sym_index;
	elf_section_symbol_table_entry *symbol;
	Elf64_Sym *raw_sym;
	elf_segment *container;
	Elf64_Phdr *raw_seg;
	Elf64_Ehdr *ehdr;
	uint64_t off_reloc;
	uint64_t delta;
	int64_t A;

	// Get container segment
	result = elf_get_containing_segment_vaddr(segments, num_segments,
									rel->r_offset, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	raw_seg = elf_segment_get_program_header(container);

	// Get symbol table. This is based on the constraint that
	// an ELF file may have only one .dynsym table (see System V gABI)
	result = elf_get_dynamic(segments, num_segments, &dynamic);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	result = elf_get_dynsym(bin, dynamic, segments, num_segments, &dynsym);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to get .dynsym.");
		goto label_free_dynamic;
	}

	// Symbol index
	sym_index = ELF64_R_SYM(rel->r_info);

	// Get symbol entry
	symbol = elf_section_symbol_table_get_list_entries(dynsym)[sym_index];
	raw_sym = elf_section_symbol_table_entry_get_raw_entry(symbol);

	// Get offset of relocation to make it comparable
	off_reloc = rel->r_offset - raw_seg->p_vaddr + raw_seg->p_offset;
	if (off_reloc >= data) {
		rel->r_offset += data_size;
		off_reloc += data_size;
	}

	// Get offset of symbol
	result = elf_get_containing_segment_vaddr(segments, num_segments,
					raw_sym->st_value, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		goto label_free_dynsym;

	raw_seg = elf_segment_get_program_header(container);
	ehdr = elf_binary_get_elf_header(bin);

	// Computing delta like this holds for both cases
	delta = raw_seg->p_vaddr - raw_seg->p_offset;

	// Addend is located at offset for Elf64_Rel (see System V gABI+ARM64).
	A = *(int64_t*)OFFSET(ehdr, off_reloc);

	switch (ELF64_R_TYPE(rel->r_info)) {
	case R_AARCH64_GLOB_DAT:
		// S + A
		// 8 - byte value is determined at load time, thus
		// we dont need to care about this type
		break;
	case R_AARCH64_JUMP_SLOT:
		// S + A
		// 8 - byte value of this type is initially an offset
		// to plt[0], i.e. dynamic linker stub
		if (*(uint64_t*)OFFSET(ehdr, off_reloc) >= data)
			*(uint64_t*)OFFSET(ehdr, off_reloc) += data_size;
		break;
	case R_AARCH64_RELATIVE:
		// Delta(S) + A
	case R_AARCH64_IRELATIVE:
		// Indirect(Delta(S) + A)
		if (delta + A >= data)
			*(int64_t*)OFFSET(ehdr, off_reloc) += data_size;
		break;
	case R_AARCH64_COPY:
		break;
	case R_AARCH64_TLS_DTPREL:
		// DTPREL(S + A)
	case R_AARCH64_TLS_DTPMOD:
		// LDM(S)
	case R_AARCH64_TLS_TPREL:
		// TPREL(S + A)
	case R_AARCH64_TLSDESC:
		// TLSDESC(S + A)
	default:
		result = ELF_RELOC_TYPE_NOT_SUPPORTED;
		log_forward(ELF_LOGLEVEL_SOFTERROR, "AARCH64 type not supported.");
	}

label_free_dynsym:
	elf_section_symbol_table_free(dynsym);

label_free_dynamic:
	elf_section_dynamic_free(dynamic);

	return result;
}

enum elf_result elf_arm64_patch_rela(elf_binary *bin, elf_segment **segments,
		uint32_t num_segments, elf_segment **old_segments,
		uint32_t num_old_segments, Elf64_Rela *rela, uint64_t data,
		uint64_t data_size)
{
	__label__ label_free_dynamic, label_free_dynsym;

	enum elf_result result = ELF_COMMON_SUCCESS;
	elf_section_dynamic *dynamic;
	elf_section_symbol_table *dynsym;
	uint8_t sym_index;
	elf_section_symbol_table_entry *symbol;
	Elf64_Sym *raw_sym;
	elf_segment *container;
	Elf64_Phdr *raw_seg;
	Elf64_Ehdr *ehdr;
	uint64_t off_reloc;
	uint64_t delta;
	int64_t A;

	// Get container segment
	result = elf_get_containing_segment_vaddr(old_segments,
					num_old_segments, rela->r_offset, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		return result;
	raw_seg = elf_segment_get_program_header(container);

	// Get symbol table. This is based on the constraint that
	// an ELF file may have only one .dynsym table (see System V gABI)
	result = elf_get_dynamic(segments, num_segments, &dynamic);
	if (result != ELF_COMMON_SUCCESS)
		return result;

	result = elf_get_dynsym(bin, dynamic, segments, num_segments, &dynsym);
	if (result != ELF_COMMON_SUCCESS) {
		log_forward(ELF_LOGLEVEL_ERROR, "Failed to get .dynsym.");
		goto label_free_dynamic;
	}

	// Symbol index
	sym_index = ELF64_R_SYM(rela->r_info);

	// Get symbol entry
	symbol = elf_section_symbol_table_get_list_entries(dynsym)[sym_index];
	raw_sym = elf_section_symbol_table_entry_get_raw_entry(symbol);

	// Get offset of relocation to make it comparable
	off_reloc = rela->r_offset - raw_seg->p_vaddr + raw_seg->p_offset;
	if (off_reloc >= data) {
		rela->r_offset += data_size;
		off_reloc += data_size;
	}

	// Get offset of symbol
	result = elf_get_containing_segment_vaddr(segments, num_segments,
					raw_sym->st_value, 1, &container);
	if (result != ELF_COMMON_SUCCESS)
		goto label_free_dynsym;

	raw_seg = elf_segment_get_program_header(container);
	ehdr = elf_binary_get_elf_header(bin);

	// Computing delta like this holds for both cases
	delta = raw_seg->p_vaddr - raw_seg->p_offset;
	A = rela->r_addend;

	switch (ELF64_R_TYPE(rela->r_info)) {
	case R_AARCH64_GLOB_DAT:
		// S + A
		// 8 - byte value is determined at load time, thus
		// we dont need to care about this type
		break;
	case R_AARCH64_JUMP_SLOT:
		// S + A
		// 8 - byte value of this type is initially an offset
		// to plt[0], i.e. dynamic linker stub
		if (*(uint64_t*)OFFSET(ehdr, off_reloc) >= data)
			*(uint64_t*)OFFSET(ehdr, off_reloc) += data_size;
		break;
	case R_AARCH64_RELATIVE:
		// Delta(S) + A
	case R_AARCH64_IRELATIVE:
		// Indirect(Delta(S) + A)
		if (delta + A >= data) {
			rela->r_addend += data_size;
		}
		break;
	case R_AARCH64_COPY:
		break;
	case R_AARCH64_TLS_DTPREL:
		// DTPREL(S + A)
	case R_AARCH64_TLS_DTPMOD:
		// LDM(S)
	case R_AARCH64_TLS_TPREL:
		// TPREL(S + A)
	case R_AARCH64_TLSDESC:
		// TLSDESC(S + A)
	default:
		result = ELF_RELOC_TYPE_NOT_SUPPORTED;
		log_forward(ELF_LOGLEVEL_SOFTERROR, "AARCH64 type not supported.");
	}

label_free_dynsym:
	elf_section_symbol_table_free(dynsym);

label_free_dynamic:
	elf_section_dynamic_free(dynamic);

	return result;
}