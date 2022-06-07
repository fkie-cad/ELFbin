/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_TRANSLATOR_H_
#define _ELF_TRANSLATOR_H_

/*------------------------------------------------------------------------*/
/* Includes                                                               */
/*------------------------------------------------------------------------*/
// Framework
#include "elf_common.h"

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_translator elf_translator;
typedef struct _elf_segment elf_segment;

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
// Constructor / Destructor
elf_translator *elf_translator_init(void);
void elf_translator_free(elf_translator *translator);

// Utility
/*
* 'elf_translator_vaddr_to_offset' attempts to translate a virtual address to
*	a file offset. This is done by searching for the surrounding segment
*	and abusing the assumption, that the relative offset of a virtual
*	address to its surrounding segment equals the relative offset of the
*	file offset to its surrounding segment, where the virtual address
*	and the file offset reference the same data in the process image and
*	the file view, respectively. If there is no surrounding segment, the
*	next relative segment, i.e. the beginning of the process image (0)
*	will be taken as reference, resulting in 'offset' = 'vaddr'.
* @translator: Translator object to use to calculate the translations.
* @segments: List of segments used that contains file offsets and virtual
*	addressess.
* @num_segments: Amount of segments in 'segments'.
* @vaddr: Virtual address to translate to a file offset.
* @offset: On success, this will be the file offset that references the same
*	data as the virtual address does in the process image. Note that a
*	segment's "p_filesz" member is less than or equal to "p_memsz", which
*	implies that the resulting offset might not point into the surrouding
*	segment that contains 'vaddr' in the process image. If such a case
*	occurs, 'ELF_TRANSLATOR_VADDR_OUT_OF_BOUNDS' will be returned, although
*	'offset' will still receive the calculated file offset.
* @return: Either success or one of the following:
*	- invalid parameters
*	- error returned by 'elf_translator_get_surrounding_segment_virtual'
*/
enum elf_result elf_translator_vaddr_to_offset(elf_translator *translator,
		elf_segment **segments, uint32_t num_segments, uint64_t vaddr,
		uint64_t *offset);

/*
* 'elf_translator_offset_to_vaddr' tries to translate a file offset to a
*	virtual address. This is done by searching for the surrounding segment
*	and abusing the assumptions of relative equivalence between offsets
*	and virtual addresses. If there is no surrounding segment, the
*	next relative segment, i.e. the beginning of the file (0)
*	will be taken as reference, resulting in 'offset' = 'vaddr'.
* @translator: Translator object to use to calculate the translations.
* @segments: List of segments used that contains file offsets and virtual
*	addressess.
* @num_segments: Amount of segments in 'segments'.
* @offset: File offset to translate to a virtual address.
* @vaddr: On success, this will be the virtual address that references the same
*	data as the file offset does in the file view.
* @return: Either success or one of the following:
* 	- invalid parameters
*	- error returned by 'elf_translator_get_surrounding_segment_offset'
*/
enum elf_result elf_translator_offset_to_vaddr(elf_translator *translator,
		elf_segment **segments, uint32_t num_segments, uint64_t offset,
		uint64_t *vaddr);

/*
* 'elf_translator_get_surrounding_segment_virtual' tries to find the
*	surrounding segment of 'vaddr'. The fields "p_vaddr" and "p_memsz" will
*	be used for the comparison. The general approach is to construct a
*	temporary tree from PHT and seek for the smallest (loadable) segment
*	that contains 'vaddr'.
* @translator: Translator object to use to calculate the translations.
* @segments: List of segments used that contains file offsets and virtual
*	addressess.
* @num_segments: Amount of segments in 'segments'.
* @vaddr: Virtual address, for which to find the surrounding segment.
* @loadable: If set to 0, the returned segment can be any segment, i.e. even
*	not part of a subtree of a loadable segment. Otherwise the returned
*	segment must be part of a loadable subtree.
* @container: On success, this will contain the containing segment. Otherwise
*	NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- object init failed
*	- error returned by 'elf_pht_tree_construct'
*	- error returned by 'elf_pht_tree_find_container'
*/
enum elf_result elf_translator_get_surrounding_segment_virtual(
		elf_translator *translator, elf_segment **segments,
		uint32_t num_segments, uint64_t vaddr, uint8_t loadable,
		elf_segment **container);

/*
* 'elf_translator_get_surrounding_segment_offset' tries to find the
*	surrounding segment of 'offset'. The fields "p_offset" and "p_filesz"
* 	will be used for the comparison. The general approach is to construct a
*	temporary tree from PHT and seek for the smallest (loadable) segment
*	that contains 'vaddr'.
* @translator: Translator object to use to calculate the translations.
* @segments: List of segments used that contains file offsets and virtual
*	addressess.
* @num_segments: Amount of segments in 'segments'.
* @offset: File offset, for which to find the surrounding segment.
* @loadable: If set to 0, the returned segment can be any segment, i.e. even
*	not part of a subtree of a loadable segment. Otherwise the returned
*	segment must be part of a loadable subtree.
* @container: On success, this will contain the containing segment. Otherwise
*	NULL (after parameter validation).
* @return: Either success or one of the following:
*	- invalid parameters
*	- object init failed
*	- error returned by 'elf_pht_tree_construct'
*	- error returned by 'elf_pht_tree_find_container'
*/
enum elf_result elf_translator_get_surrounding_segment_offset(
		elf_translator *translator, elf_segment **segments,
		uint32_t num_segments, uint64_t offset, uint8_t loadable,
		elf_segment **container);

#endif