ELF_DEBUG_SRC_DIR := ./src
ELF_DEBUG_BUILD_DIR := ./build

ELF_DEBUG_SRCS := $(shell find $(ELF_DEBUG_SRC_DIR) -name *.c)
ELF_DEBUG_OBJS := $(ELF_DEBUG_SRCS:%=$(ELF_DEBUG_BUILD_DIR)/%.o)

CC := gcc
CFLAGS := -c -Wall -Wextra

elf_debug_final: $(ELF_DEBUG_OBJS)

$(ELF_DEBUG_BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(ELF_INCLUDE_DIRS) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@rm -r $(ELF_DEBUG_BUILD_DIR)