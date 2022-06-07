#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "structmember.h"

#include "./elf_core/include/elf_binary.h"
#include "./elf_core/include/elf_segment.h"
#include "elf_section_dynamic.h"
#include "elf_section_dynamic_entry.h"

#include "./elf_injector/include/elf_injector.h"
#include "./elf_injector/include/techniques/code_injection/elf_injection_segment.h"

#include "elf_misc.h"

/*********************************************************************/
/*                         Exceptions                                */
/*********************************************************************/
static PyObject *rawelf_parser_error = NULL;
static PyObject *rawelf_injector_error = NULL;

/*********************************************************************/
/*                         rawelf_injector                           */
/*********************************************************************/
typedef struct {
	PyObject_HEAD;
	elf_injector *inj;
	elf_binary *bin;
} rawelf_injector;

// Prototypes
static PyObject *rawelf_injector_new(PyTypeObject *type, PyObject *args,
										PyObject *kwds);
static int rawelf_injector_reload_binary(rawelf_injector *self,
											const char *name);
static int rawelf_injector_init(rawelf_injector *self, PyObject *args,
								PyObject *kwds);
static void rawelf_injector_dealloc(rawelf_injector *self);

static PyObject *rawelf_injector_overwrite_memory(rawelf_injector *self,
									PyObject *args, PyObject *kwds);
static PyObject *rawelf_injector_insert_memory(rawelf_injector *self,
									PyObject *args, PyObject *kwds);
static PyObject *rawelf_injector_append_pht_entry(
			rawelf_injector *self, PyObject *args, PyObject *kwds);
static PyObject *rawelf_injector_overwrite_pht_entry(
			rawelf_injector *self, PyObject *args, PyObject *kwds);
static PyObject *rawelf_injector_append_dynamic_entry(
			rawelf_injector *self, PyObject *args, PyObject *kwds);
static PyObject *rawelf_injector_overwrite_dynamic_entry(
	rawelf_injector *self, PyObject *args, PyObject *kwds);

static PyObject *rawelf_injector_new(PyTypeObject *type, PyObject *args,
										PyObject *kwds)
{
	rawelf_injector *self = (rawelf_injector*)type->tp_alloc(type, 0);
	if (self != NULL) {

		self->inj = elf_injector_init();
		if (self->inj == NULL) {
			Py_DECREF(self);
			PyErr_SetString(PyExc_MemoryError, "Failed to initialize"
				" injector.");
			return NULL;
		}

		self->bin = elf_binary_init();
		if (self->bin == NULL) {
			Py_DECREF(self);
			PyErr_SetString(PyExc_MemoryError, "Failed to initialize"
				" binary.");
			return NULL;
		}
	}
	return (PyObject*)self;
}

static int rawelf_injector_reload_binary(rawelf_injector *self,
											const char *name)
{
	__label__ label_return;

	int32_t result = -1;
	uint8_t is_loaded;

	if (self->bin != NULL) {

		// Check if there is already a loaded binary.
		if (elf_binary_is_loaded(self->bin, &is_loaded)
				!= ELF_COMMON_SUCCESS) {
			PyErr_SetString(rawelf_parser_error, "Could not determine"
				" whether there is already a loaded binary or not.");
			goto label_return;
		}

		if (is_loaded) {

			if (elf_binary_unload(self->bin) != ELF_COMMON_SUCCESS) {

				PyErr_SetString(rawelf_parser_error, "Could not unload"
								" the binary.");
				goto label_return;
			}
		}

		if (elf_binary_load_by_name(self->bin, name)
					!= ELF_COMMON_SUCCESS) {
			PyErr_Format(rawelf_parser_error, "Could not load %s.",
							name);
			goto label_return;
		}

		// Only success case
		result = 0;
	}

label_return:
	return result;
}

static int rawelf_injector_init(rawelf_injector *self, PyObject *args,
								PyObject *kwds)
{
	static char *kwlist[] = { "bin_name", NULL };
	const char *bin_name;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &bin_name))
		return -1;

	// Create binary object
	if (rawelf_injector_reload_binary(self, bin_name) != 0)
		return -1;

	return 0;
}

static void rawelf_injector_dealloc(rawelf_injector *self)
{
	if (self->bin != NULL)
		elf_binary_free(self->bin);
	if (self->inj != NULL)
		elf_injector_free(self->inj);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *rawelf_injector_overwrite_memory(rawelf_injector *self,
									PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "offset", "buffer",  NULL };
	uint64_t offset;
	Py_buffer buffer;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Ky*", kwlist,
			&offset, &buffer))
		return NULL;

	if (elf_injector_override_memory(self->inj, self->bin, buffer.buf,
			buffer.len, offset) != ELF_COMMON_SUCCESS) {
		PyErr_Format(rawelf_injector_error, "Failed overwrite"
			" memory at offset %p with %llx many bytes.", offset,
			buffer.len);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *rawelf_injector_insert_memory(rawelf_injector *self,
									PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "offset", "buffer", NULL };
	uint64_t offset;
	Py_buffer buffer;
	if (!PyArg_ParseTupleAndKeywords(args, kwds, "Ky*", kwlist,
			&offset, &buffer))
		return NULL;

	if (elf_injector_inject_memory(self->inj, self->bin, buffer.buf,
			buffer.len, offset, ELF_AFFILIATION_NONE)
			!= ELF_COMMON_SUCCESS) {
		PyErr_Format(rawelf_injector_error, "Failed insert"
			" memory at offset %p with %llx many bytes.", offset,
			buffer.len);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *rawelf_injector_append_pht_entry(
			rawelf_injector *self, PyObject *args, PyObject *kwds)
{
	__label__ label_finished;

	static char *kwlist[] = { "ptype", "flags", "offset", "vaddr",
		"file_size", "mem_size", "align", NULL };

	Elf64_Phdr phdr = { 0 };
	uint32_t i;
	elf_segment **segments;
	elf_segment *seg_phdr;
	Elf64_Ehdr *ehdr;
	uint64_t offset;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "IIKKKKK", kwlist,
			&phdr.p_type, &phdr.p_flags, &phdr.p_offset, &phdr.p_vaddr,
			&phdr.p_filesz, &phdr.p_memsz, &phdr.p_align))
		return NULL;

	// Physical address is assumed to be irrelevant
	phdr.p_paddr = phdr.p_vaddr;

	// As this is a module that will be used in conjunction with LIEF,
	// we can first check whether LIEF already inserted engough space
	// into the PT_PHDR segment.

	// Search for PT_PHDR segment
	seg_phdr = NULL;
	segments = elf_binary_get_segments(self->bin);
	for (i = 0; i < elf_binary_get_amount_segments(self->bin); i++) {
		if (elf_segment_get_program_header(segments[i])->p_type == PT_PHDR) {
			seg_phdr = segments[i];
			break;
		}
	}

	// Compute offset of pht entry. Either we insert new pht or overwrite
	// unused data at this offset.
	ehdr = elf_binary_get_elf_header(self->bin);
	offset = ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf64_Phdr);

	// If there is a PT_PHDR segment, then we can check whether LIEF allocated
	// additional memory.
	if (seg_phdr != NULL) {

		// If there is enough memory for another PHT entry, then we can
		// overwrite unused memory.
		if (elf_segment_get_program_header(seg_phdr)->p_filesz
				>= ehdr->e_phnum * ehdr->e_phentsize + sizeof (Elf64_Phdr)) {

			if (elf_injector_override_memory(self->inj, self->bin,
					(uint8_t*)&phdr, sizeof(Elf64_Phdr), offset)
					!= ELF_COMMON_SUCCESS) {
				PyErr_SetString(rawelf_injector_error, "Failed to overwrite"
					" unused memory that could have been used as PHT entry.");
				return NULL;
			}

			// Increase amount of PHT entries.
			ehdr->e_phnum += 1;
			goto label_finished;
		}
	}

	// Recalculate PHT entry, if necessary
	if (phdr.p_offset >= offset) {
		phdr.p_offset += sizeof(Elf64_Phdr);
		phdr.p_vaddr += sizeof(Elf64_Phdr);
		phdr.p_paddr += sizeof(Elf64_Phdr);
	}

	// Append new PHT entry to PHT
	if (elf_injector_inject_memory(self->inj, self->bin, (uint8_t*)&phdr,
			sizeof(Elf64_Phdr), offset, ELF_AFFILIATION_UPPER)
			!= ELF_COMMON_SUCCESS) {
		PyErr_SetString(rawelf_injector_error, "Failed to insert new"
			" PHT entry.");
		return NULL;
	}

	// Increase amount of PHT entries. We have to do this AFTER
	// injection s.t. 'elf_injector_inject_memory' does not try
	// to patch the new entry. Note that 'inject_memory' will reload
	// the binary and thus invalidate the previous reference to ehdr.
	ehdr = elf_binary_get_elf_header(self->bin);
	ehdr->e_phnum += 1;

	// Finally append padding s.t. we add a total of 0x1000. This is not
	// necessary for AMD64, but for ARM64.
	uint8_t buffer[0x1000 - sizeof (Elf64_Phdr)] = { 0 };
	if (elf_injector_inject_memory(self->inj, self->bin, buffer,
				0x1000 - sizeof (Elf64_Phdr), offset + sizeof (Elf64_Phdr),
				ELF_AFFILIATION_UPPER)
			!= ELF_COMMON_SUCCESS) {
		PyErr_SetString(rawelf_injector_error, "Failed to insert padding.");
		return NULL;
	}

label_finished:
	// Reload PHT s.t. new entry is part of it.
	if (elf_binary_reload(self->bin, ELF_RELOAD_SEGMENTS)
			!= ELF_COMMON_SUCCESS) {
		PyErr_SetString(rawelf_parser_error, "Failed to reload binary.");
		return NULL;
	}

	return PyLong_FromUnsignedLongLong(phdr.p_offset);
}

static PyObject *rawelf_injector_overwrite_pht_entry(
			rawelf_injector *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "ptype", "flags", "offset", "vaddr",
		"file_size", "mem_size", "align", "index", NULL };

	Elf64_Phdr phdr = { 0 };
	Elf64_Ehdr *ehdr;
	uint64_t index;
	uint64_t offset;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "IIKKKKKK", kwlist,
			&phdr.p_type, &phdr.p_flags, &phdr.p_offset, &phdr.p_vaddr,
			&phdr.p_filesz, &phdr.p_memsz, &phdr.p_align, &index))
		return NULL;

	// Physical address is assumed to be irrelevant
	phdr.p_paddr = phdr.p_vaddr;

	ehdr = elf_binary_get_elf_header(self->bin);
	if (index >= ehdr->e_phnum) {
		PyErr_SetString(rawelf_injector_error, "PHT index out of bounds.");
		return NULL;
	}

	// Compute offset
	offset = ehdr->e_phoff + index * sizeof(Elf64_Phdr);

	// Overwrite memory
	if (elf_injector_override_memory(self->inj, self->bin, (uint8_t*)&phdr,
			sizeof(Elf64_Phdr), offset) != ELF_COMMON_SUCCESS) {
		PyErr_Format(rawelf_injector_error, "Failed overwrite"
			" PHT entry at offset %p with index %ld.", offset,
			index);
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject *rawelf_injector_append_dynamic_entry(
	rawelf_injector *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "tag", "value", NULL };
	Elf64_Dyn new_entry = { 0 };

	enum elf_result result;
	elf_section_dynamic *dynamic;
	uint64_t amount_entries;
	elf_section_dynamic_entry *last_entry;
	Elf64_Dyn *raw;
	uint64_t raw_off;


	if (!PyArg_ParseTupleAndKeywords(args, kwds, "LK", kwlist,
		&new_entry.d_tag, &new_entry.d_un.d_val))
		return NULL;

	// Get .dynamic section
	result = elf_get_dynamic(elf_binary_get_segments(self->bin),
				elf_binary_get_amount_segments(self->bin), &dynamic);
	if (result != ELF_COMMON_SUCCESS) {
		PyErr_SetString(rawelf_parser_error, "Failed to find .dynamic");
		return NULL;
	}

	// Calculate file offset, at which to insert new entry
	amount_entries = elf_section_dynamic_get_amount_entries(dynamic);
	last_entry = elf_section_dynamic_get_list_entries(dynamic)
							[amount_entries - 1];
	raw = elf_section_dynamic_entry_get_raw_entry(last_entry);
	raw_off = ((uint8_t*)raw) - ((uint8_t*)elf_binary_get_elf_header(self->bin));

	// Free dynamic
	elf_section_dynamic_free(dynamic);

	// Insert new entry at file offset
	result = elf_injector_inject_memory(self->inj, self->bin,
			(uint8_t*)&new_entry, sizeof(new_entry), raw_off,
			ELF_AFFILIATION_NONE);
	if (result != ELF_COMMON_SUCCESS) {
		PyErr_Format(rawelf_injector_error, "Failed to append new"
			" .dynamic - entry of type %llx and value %llx.",
			new_entry.d_tag, new_entry.d_un.d_val);
		return NULL;
	}

	return PyLong_FromUnsignedLongLong(raw_off);
}

static PyObject *rawelf_injector_overwrite_dynamic_entry(
	rawelf_injector *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = { "tag", "value", "index", NULL };
	Elf64_Dyn new_entry = { 0 };
	uint64_t index;

	enum elf_result result;
	elf_section_dynamic *dynamic;
	uint64_t amount_entries;
	elf_section_dynamic_entry *target;
	Elf64_Dyn *raw;
	uint64_t raw_off;

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "LKK", kwlist,
			(int64_t*)&new_entry.d_tag, &new_entry.d_un.d_val,
			&index))
		return NULL;

	// Get .dynamic section
	result = elf_get_dynamic(elf_binary_get_segments(self->bin),
				elf_binary_get_amount_segments(self->bin), &dynamic);
	if (result != ELF_COMMON_SUCCESS) {
		PyErr_SetString(rawelf_parser_error, "Failed to find .dynamic");
		return NULL;
	}

	// Check if index is in range
	amount_entries = elf_section_dynamic_get_amount_entries(dynamic);
	if (index >= amount_entries) {
		elf_section_dynamic_free(dynamic);
		PyErr_SetString(rawelf_injector_error, ".dynamic index out"
			" of bounds.");
		return NULL;
	}

	// Get file offset of entry to override
	target = elf_section_dynamic_get_list_entries(dynamic)[index];
	raw = elf_section_dynamic_entry_get_raw_entry(target);
	raw_off = ((uint64_t)raw) - ((uint64_t)elf_binary_get_elf_header(self->bin));

	// Free .dynamic
	elf_section_dynamic_free(dynamic);

	// Override specified entry
	result = elf_injector_override_memory(self->inj, self->bin,
			(uint8_t*)&new_entry, sizeof(new_entry), raw_off);
	if (result != ELF_COMMON_SUCCESS) {
		PyErr_Format(rawelf_injector_error, "Failed overwrite"
			" memory at offset %p with %llx many bytes.", raw_off,
			sizeof(new_entry));
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyMemberDef rawelf_injector_members[] = {
	{ NULL }
};

static PyGetSetDef rawelf_injector_gettersetters[] = {
	{ NULL }
};

static PyMethodDef rawelf_injector_methods[] = {
	{
		"overwrite_memory",
		(PyCFunction)rawelf_injector_overwrite_memory,
		METH_VARARGS | METH_KEYWORDS,
		"Overwrite arbitrary memory in current binary."
	},
	{
		"insert_memory",
		(PyCFunction)rawelf_injector_insert_memory,
		METH_VARARGS | METH_KEYWORDS,
		"Insert arbitrary memory into current binary."
	},
	{
		"append_pht_entry",
		(PyCFunction)rawelf_injector_append_pht_entry,
		METH_VARARGS | METH_KEYWORDS,
		"Appends a new PHT entry to the PHT."
	},
	{
		"overwrite_pht_entry",
		(PyCFunction)rawelf_injector_overwrite_pht_entry,
		METH_VARARGS | METH_KEYWORDS,
		"Overwrites a PHT entry at specified index."
	},
	{
		"append_dynamic_entry",
		(PyCFunction)rawelf_injector_append_dynamic_entry,
		METH_VARARGS | METH_KEYWORDS,
		"Appends a new entry to .dynamic - table."
	},
	{
		"overwrite_dynamic_entry",
		(PyCFunction)rawelf_injector_overwrite_dynamic_entry,
		METH_VARARGS | METH_KEYWORDS,
		"Overwrites a specified .dynamic entry."
	},
	{ NULL }
};

static PyTypeObject rawelf_injector_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "_rawelf_injection.rawelf_injector",
	.tp_doc = "Elf injector use for different injection techniques"
		" implemented in BA.",
	.tp_basicsize = sizeof (rawelf_injector),
	.tp_itemsize = 0,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_new = rawelf_injector_new,
	.tp_init = (initproc)rawelf_injector_init,
	.tp_dealloc = (destructor)rawelf_injector_dealloc,
	.tp_members = rawelf_injector_members,
	.tp_methods = rawelf_injector_methods,
	.tp_getset = rawelf_injector_gettersetters,
};

/*********************************************************************/
/*                         Module Definition                         */
/*********************************************************************/

static PyModuleDef rawelf_injection_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "_rawelf_injection",
	.m_doc = "Elf injection and parsing library based on BA.",
	.m_size = -1,
};

PyMODINIT_FUNC PyInit__rawelf_injection(void)
{
	__label__ label_free_all;

	PyObject *mod;

	// Finish creation of types
	if (PyType_Ready(&rawelf_injector_type) < 0)
		return NULL;

	// Create module
	mod = PyModule_Create(&rawelf_injection_module);
	if (mod != NULL) {

		// Add types to module
		Py_INCREF(&rawelf_injector_type);
		if (PyModule_AddObject(mod, "rawelf_injector",
							(PyObject*)&rawelf_injector_type) < 0)
			goto label_free_all;

		// Create new exceptions
		rawelf_parser_error = PyErr_NewException(
						"_rawelf_injection.parser_error", NULL, NULL);
		Py_XINCREF(rawelf_parser_error);
		if (PyModule_AddObject(mod, "parser_error",
				rawelf_parser_error) < 0)
			goto label_free_all;

		rawelf_injector_error = PyErr_NewException(
						"_rawelf_injection.injector_error", NULL, NULL);
		Py_XINCREF(rawelf_injector_error);
		if (PyModule_AddObject(mod, "injector_error", 
				rawelf_injector_error) < 0)
			goto label_free_all;
	}
	
	return mod;

label_free_all:
	// Note: Py_XDECREF and Py_CLEAR do nothing if given NULL
	Py_XDECREF(&rawelf_injector_type);
	Py_XDECREF(rawelf_parser_error);
	Py_CLEAR(rawelf_parser_error);
	Py_XDECREF(rawelf_injector_error);
	Py_CLEAR(rawelf_injector_error);
	Py_DECREF(mod);

	return NULL;
}