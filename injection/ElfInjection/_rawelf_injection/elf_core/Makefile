# Von https://makefiletutorial.com

TARGET_EXEC := libelf_core.a

BUILD_DIR := ./build
SRC_DIRS := ./src

# Find all the C and C++ files we want to compile
SRCS := $(shell find $(SRC_DIRS) -name *.c)

# String substitution for every C/C++ file.
# As an example, hello.cpp turns into ./build/hello.cpp.o
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

CC := gcc
CFLAGS := -c -Wall -Wextra

# The final build step.
$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	ar rcsv $@ $(OBJS)

# Build step for C source
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(ELF_INCLUDE_DIRS) $(CFLAGS) -D __ELF_DEBUG -c $< -o $@

.PHONY: clean
clean:
	@rm -r $(BUILD_DIR)