# Von https://makefiletutorial.com

TARGET_EXEC := libelf_injector.a

BUILD_DIR := ./build
SRC_DIRS := ./src
INC_DIRS := ./include

# Find all the C to compile
SRCS := $(shell find $(SRC_DIRS) -name *.c)

# String substitution for every C file.
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

CC := gcc
CFLAGS := -c -Wall -Wextra

# The final build step.
$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	ar rsv $(ELF_CORE_LIB) $(OBJS) $(ELF_DEBUG_OBJECTS)

# Build step for C source
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(ELF_INCLUDE_DIRS) $(CFLAGS) -D __ELF_DEBUG -c $< -o $@

.PHONY: clean
clean:
	@rm -r $(BUILD_DIR)