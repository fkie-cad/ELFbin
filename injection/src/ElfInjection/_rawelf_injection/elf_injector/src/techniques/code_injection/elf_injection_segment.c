/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Injection
#include "./internal/elf_internal.h"
#include "./techniques/code_injection/elf_injection_segment.h"

#include "elf_injector.h"
#include "elf_misc.h"

// Core
#include "elf_binary.h"
#include "elf_segment.h"

// Standard
#include <unistd.h>

/*------------------------------------------------------------------------*/
/* Local Function Declarations                                            */
/*------------------------------------------------------------------------*/
// Technique - specific funcs
static enum elf_result _elf_injection_segment_cave(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output);
static enum elf_result _elf_injection_segment_cave_override(
				elf_injector *injector, elf_binary *bin,
				struct elf_injection_segment_info *info,
				struct elf_injection_segment_output *output);
static enum elf_result _elf_injection_segment_insert(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output);
static enum elf_result _elf_injection_segment_insert_override(
				elf_injector *injector, elf_binary *bin,
				struct elf_injection_segment_info *info,
				struct elf_injection_segment_output *output);

// Helper
static enum elf_result _elf_forge_phdr_from_cave(elf_binary *bin,
				uint64_t sz_cave, Elf64_Phdr *new_phdr);
static enum elf_callback_retval _elf_forge_phdr_from_cave_condition_virtual(
	Elf64_Phdr *cur, Elf64_Phdr *fol, uint64_t sz_cave, void *user_data);
static enum elf_callback_retval _elf_forge_phdr_from_cave_condition_file(
	Elf64_Phdr *cur, Elf64_Phdr *fol, uint64_t sz_cave, void *user_data);

/*------------------------------------------------------------------------*/
/* Global Function Definitions                                            */
/*------------------------------------------------------------------------*/
enum elf_result elf_injection_segment(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output)
{
	enum elf_result result;
	if (injector == NULL || bin == NULL || info == NULL || output == NULL)
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	switch (info->type) {
	case ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT:
		result = _elf_injection_segment_cave(injector, bin, info,
							output);
		break;
	case ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT_OVERRIDE:
		result = _elf_injection_segment_cave_override(injector, bin,
								info, output);
		break;
	case ELF_INJECTION_SEGMENT_INSERT:
		result = _elf_injection_segment_insert(injector, bin, info,
							output);
		break;
	case ELF_INJECTION_SEGMENT_INSERT_OVERRIDE:
		result = _elf_injection_segment_insert_override(injector, bin,
								info, output);
		break;
	default:
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);
	}

	return result;
}

/*------------------------------------------------------------------------*/
/* Local Function Definitions                                             */
/*------------------------------------------------------------------------*/
// inject pht entry and override code cave
enum elf_result _elf_injection_segment_cave(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output)
{
	enum elf_result result;
	Elf64_Ehdr *ehdr;
	uint64_t offset;

	// Construct new PHT entry
	Elf64_Phdr new_phdr = {
		p_type: PT_LOAD,	// segment will be loaded
		p_flags: PF_X | PF_R,	// segment will be executable&readable
	};

	// Calculate offset of new pht entry
	ehdr = elf_binary_get_elf_header(bin);
	offset = ehdr->e_phoff + elf_binary_get_amount_segments(bin) * sizeof(Elf64_Phdr);

	// Inject new pht entry
	result = elf_injector_inject_memory(injector, bin, (const uint8_t*)&new_phdr,
			sizeof(new_phdr), offset, ELF_AFFILIATION_UPPER);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Segments implicitly reloaded in 'elf_injector_inject_memory'. Still
	// need to "refresh" local variables.
	ehdr = elf_binary_get_elf_header(bin);
	offset = ehdr->e_phoff + elf_binary_get_amount_segments(bin) * sizeof(Elf64_Phdr);

	// Find code cave
	result = _elf_forge_phdr_from_cave(bin, info->sz_buffer, &new_phdr);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Update injected PHT entry
	*((Elf64_Phdr*)(offset + (uint64_t)ehdr)) = new_phdr;

	// Reload one last time to make last segment accessible for this
	// framework.
	ehdr->e_phnum += 1;
	result = elf_binary_reload(bin, ELF_RELOAD_SEGMENTS);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Override code cave with buffer
	result = elf_injector_override_memory(injector, bin, info->buffer,
					info->sz_buffer, new_phdr.p_offset);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Set output
	output->off_buffer = new_phdr.p_offset;

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_injection_segment_cave_override(
				elf_injector *injector, elf_binary *bin,
				struct elf_injection_segment_info *info,
				struct elf_injection_segment_output *output)
{
	enum elf_result result;
	uint32_t index;
	Elf64_Phdr new_phdr = {
		p_type: PT_LOAD,
		p_flags: PF_X | PF_R,
	};
	Elf64_Phdr *target;

	index = info->specific.cave_override_info.index;
	if (index >= elf_binary_get_amount_segments(bin))
		log_return(ELF_LOGLEVEL_ERROR, ELF_COMMON_INVALID_PARAMETERS,
				ELF_PRINTTYPE_NONE);

	// Step 1: Identify code cave
	result = _elf_forge_phdr_from_cave(bin, info->sz_buffer, &new_phdr);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Step 2: Override PHT entry
	target = elf_segment_get_program_header(
				elf_binary_get_segments(bin)[index]);
	*target = new_phdr;

	// Step 3: Override code cave with buffer
	result = elf_injector_override_memory(injector, bin, info->buffer,
					info->sz_buffer, target->p_offset);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
					"Failed to override code cave.");

	// Set output
	output->off_buffer = target->p_offset;

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_injection_segment_insert(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output)
{
	enum elf_result result;
	Elf64_Phdr new_phdr = {
		p_type: PT_NULL, // PT_LOAD,
		p_flags: PF_X | PF_R,
		p_offset: info->specific.insert_info.offset,
		p_vaddr: info->specific.insert_info.vaddr,
		p_paddr: info->specific.insert_info.vaddr,
		p_filesz: info->sz_buffer,
		p_memsz: info->sz_buffer,
		p_align: getpagesize(),
	};
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *ref;

	// Step 1: Inject segment
	result = elf_injector_inject_segment(injector, bin, &new_phdr,
						info->buffer);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
			"Failed to inject new segment and/or pht entry.");

	// Step 2: Calculate virtual address
	ehdr = elf_binary_get_elf_header(bin);
	ref = (Elf64_Phdr*)((uint8_t*)ehdr + ehdr->e_phoff
		+ (ehdr->e_phnum - 1) * sizeof(Elf64_Phdr));
	ref->p_type = PT_LOAD;

	// Set output
	output->off_buffer = ref->p_offset;

	return ELF_COMMON_SUCCESS;
}

enum elf_result _elf_injection_segment_insert_override(
				elf_injector *injector, elf_binary *bin,
				struct elf_injection_segment_info *info,
				struct elf_injection_segment_output *output)
{
	enum elf_result result;
	uint32_t index;
	Elf64_Phdr new_phdr = {
		p_type: PT_NULL,
		p_flags: PF_X | PF_R,
		p_offset:info->specific.insert_override_info.offset,
		p_vaddr: info->specific.insert_override_info.vaddr,
		p_paddr: info->specific.insert_override_info.vaddr,
		p_filesz: info->sz_buffer,
		p_memsz: info->sz_buffer,
		p_align: getpagesize(),
	};
	Elf64_Phdr *target;
	index = info->specific.insert_override_info.index;

	// Step 1: Inject segment memory
	result = elf_injector_inject_memory(injector, bin, info->buffer,
				info->sz_buffer,
				info->specific.insert_override_info.offset,
				ELF_AFFILIATION_NONE);
	if (result != ELF_COMMON_SUCCESS)
		log_forward_return(ELF_LOGLEVEL_ERROR, result,
				"Failed to inject new segment memory.");

	// Step 2: Override pht entry
	target = elf_segment_get_program_header(
				elf_binary_get_segments(bin)[index]);
	*target = new_phdr;
	target->p_type = PT_LOAD;


	// Set output
	output->off_buffer = target->p_offset;

	return ELF_COMMON_SUCCESS;
}


enum elf_result _elf_forge_phdr_from_cave(elf_binary *bin,
				uint64_t sz_cave, Elf64_Phdr *new_phdr)
{
	enum elf_result result;
	elf_segment *virtual_predecessor;
	elf_segment *virtual_successor;
	elf_segment *file_predecessor;
	elf_segment *file_successor;
	Elf64_Phdr *predecessor;

	// Step 1: Find code cave in process image
	result = elf_find_code_cave(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), sz_cave,
			ELF_CODE_CAVE_TYPE_VIRTUAL,
			&virtual_predecessor, &virtual_successor,
			_elf_forge_phdr_from_cave_condition_virtual, NULL);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Step 2: Find code cave in file
	result = elf_find_code_cave(elf_binary_get_segments(bin),
			elf_binary_get_amount_segments(bin), sz_cave,
			ELF_CODE_CAVE_TYPE_FILE,
			&file_predecessor, &file_successor,
			_elf_forge_phdr_from_cave_condition_file, NULL);
	if (result != ELF_COMMON_SUCCESS)
		log_return(ELF_LOGLEVEL_ERROR, result, ELF_PRINTTYPE_NONE);

	// Step 3: Forge pht entry that points to both
	// virtual
	predecessor = elf_segment_get_program_header(virtual_predecessor);
	new_phdr->p_vaddr = (predecessor->p_vaddr + predecessor->p_memsz);
	new_phdr->p_paddr = (predecessor->p_paddr + predecessor->p_memsz);
	new_phdr->p_memsz = sz_cave;
	new_phdr->p_align = getpagesize();

	//file
	predecessor = elf_segment_get_program_header(file_predecessor);
	new_phdr->p_offset = (predecessor->p_offset + predecessor->p_filesz);
	new_phdr->p_filesz = sz_cave;

	return ELF_COMMON_SUCCESS;
}


enum elf_callback_retval _elf_forge_phdr_from_cave_condition_virtual(
	Elf64_Phdr *cur, Elf64_Phdr *fol, uint64_t sz_cave, void *user_data)
{
	if (fol != NULL &&
	    fol->p_vaddr - (cur->p_vaddr + cur->p_memsz) >= sz_cave)
		return ELF_CALLBACK_BREAK;
	return ELF_CALLBACK_CONTINUE;
}


enum elf_callback_retval _elf_forge_phdr_from_cave_condition_file(
	Elf64_Phdr *cur, Elf64_Phdr *fol, uint64_t sz_cave, void *user_data)
{
	if (fol != NULL &&
	    fol->p_offset - (cur->p_offset + cur->p_filesz) >= sz_cave)
		return ELF_CALLBACK_BREAK;
	return ELF_CALLBACK_CONTINUE;
}