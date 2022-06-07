/*------------------------------------------------------------------------*/
/* Include Guard                                                          */
/*------------------------------------------------------------------------*/
#ifndef _ELF_INJECTION_SEGMENT_H_
#define _ELF_INJECTION_SEGMENT_H_

/*------------------------------------------------------------------------*/
/* Global Type Definitions                                                */
/*------------------------------------------------------------------------*/
typedef struct _elf_binary elf_binary;
typedef struct _elf_injector elf_injector;

/*------------------------------------------------------------------------*/
/* Global Enumerations                                                    */
/*------------------------------------------------------------------------*/
/*
* Describes types of supported injection techniques that are based upon
*	segments, specifically upon PHT. Note that on x86_64 there seems to be
*	the implicit assumption that '.p_offset' and '.p_vaddr' may only differ
*	by the sum of differences of '.p_memsz' and '.p_filesz' of all
*	preceding loadable segments. This is neither specified in System V gABI
*	no in the x86_64 - processor supplement... Thus the underlying
*	heuristic that attempts to find code caves may return invalid results.
*	If that is the case, use manual segment injection with
*	'elf_injector_inject_memory' and 'elf_injector_override_memory'.
* @ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT: Attempts to find a code cave and
*	tries to interpret found cave as a segment. A new PHT entry will be
*	appended to PHT. This entry describes the code cave as segment. Note
*	that only code caves between loadable segments will be used, as those
*	segments guarantee ascending virtual addresses, which makes them
*	comparable. This approach uses the first-fit heuristic.
* @ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT_OVERRIDE: Same as
*	'ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT' except that instead of creating
*	a new entry, an existing PHT entry will be overriden.
* @ELF_INJECTION_INSERT: Expands binary by requested amount of bytes. These
*	new bytes will be interpreted as a segment. A new PHT entry will be
*	inserted into PHT. This entry describes the new segment.
* @ELF_INJECTION_INSERT_OVERRIDE: Same as 'ELF_INJECTION_INSERT' except that
*	instead of creating a new entry, an existing PHT entry will be
*	overriden.
* Notes: 'ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT' and 'ELF_INJECTION_INSERT' do
*	not conform to System V gABI as loadable segments are required to be in
*	ascending order based upon 'p_vaddr'. Those two techniques just append
*	a new loadable entry!
*/
enum elf_injection_segment_type {
	ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT = 0,
	ELF_INJECTION_SEGMENT_CAVE_AS_SEGMENT_OVERRIDE,
	ELF_INJECTION_SEGMENT_INSERT,
	ELF_INJECTION_SEGMENT_INSERT_OVERRIDE,
	ELF_INJECTION_SEGMENT_MAX
};

/*------------------------------------------------------------------------*/
/* Global Structure Definitions                                           */
/*------------------------------------------------------------------------*/
struct elf_injection_segment_cave_info {

};

/*
* Describes input information required to perform a segment injection by using
*	code caves and overriding a PHT entry.
* @index: Index of existing PHT - entry to override.
*/
struct elf_injection_segment_cave_override_info {
	uint32_t index;
};

/*
* Describes input information required to perform a segment injection by
*	injecting a new segment and PHT entry.
* @offset: File offset, at which to inject the segment.
* @vaddr: Virtual address, at which the segment will reside in the process
*	image.
*/
struct elf_injection_segment_insert_info {
	uint64_t offset;
	uint64_t vaddr;
};

/*
* Describes input information required to perform a segment injection by
*	injecting a new segment and overriding a PHT entry.
* @offset: File offset at which to inject the segment.
* @index: Index of existing PHT - entry to override.
* @vaddr: Virtual address, at which the segment will reside in the process
*	image.
*/
struct elf_injection_segment_insert_override_info {
	uint64_t offset;
	uint32_t index;
	uint64_t vaddr;
};

/*
* 'elf_injection_segment_info' contains input information for segment-/PHT-
*	related code injections.
* @buffer: Byte array to write to new segment.
* @sz_buffer: Amount of bytes in 'buffer'. This also determines the size of the
*	new segment.
* @type: Determines how 'specific' needs to be interpreted.
* @specific: Technique - specific information.
*/
struct elf_injection_segment_info {
	uint8_t *buffer;
	uint64_t sz_buffer;
	enum elf_injection_segment_type type;
	union {
		struct elf_injection_segment_cave_info cave_info;
		struct elf_injection_segment_cave_override_info cave_override_info;
		struct elf_injection_segment_insert_info insert_info;
		struct elf_injection_segment_insert_override_info insert_override_info;
	} specific;
};

struct elf_injection_segment_cave_output {

};

struct elf_injection_segment_cave_override_output {

};

struct elf_injection_segment_insert_output {

};

struct elf_injection_segment_insert_override_output {

};

/*
* 'elf_injection_segment_output' contains output information for segment-/PHT-
*	related code injections.
* @off_buffer: File offset of injected buffer. This can differ from the
*	requested offset as PHT entry injection may shift all following
*	segments and thus offsets and vaddresses arround.
* @type: Determines how 'specific' needs to be interpreted.
* @specific: Technique - specific output information.
*/
struct elf_injection_segment_output {
	uint64_t off_buffer;
	enum elf_injection_segment_type type;
	union {
		struct elf_injection_segment_cave_output cave_output;
		struct elf_injection_segment_cave_override_output cave_override_output;
		struct elf_injection_segment_insert_output insert_output;
		struct elf_injection_segment_insert_override_output insert_override_output;
	} specific;
};

/*------------------------------------------------------------------------*/
/* Global Function Declarations                                           */
/*------------------------------------------------------------------------*/
/*
* 'elf_injection_segment' tries to perform a segment/PHT - based injection 
*	using a technique specified in 'info'.
* @injector: Injector to use for injections.
* @bin: Binary, for which to create a new segment.
* @info: Input information specifying what technique to use for segment
*	injection and what to inject.
* @output: Output information that is related to input information. On success
*	it will contain technique - specific information, if any.
* @return: Either success or one of the following:
* 	- invalid parameters
*	- error returned by 'elf_injector_inject_memory'
*	- error returned by 'elf_find_code_cave'
*	- error returned by 'elf_binary_reload'
*	- error returned by 'elf_injector_override_memory'
*	- error returned by 'elf_injector_inject_segment'
*/
enum elf_result elf_injection_segment(elf_injector *injector,
		elf_binary *bin, struct elf_injection_segment_info *info,
		struct elf_injection_segment_output *output);

#endif