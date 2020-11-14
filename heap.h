//
// Created by Tomala on 03.11.2020.
//

#ifndef SO2_HEAP_H
#define SO2_HEAP_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include "custom_unistd.h"

#define PAGE 4096
#define FENCE_SIZE 8

struct chunk_t {
    struct chunk_t *next;
    struct chunk_t *prev;
    size_t size;
    int free; // 1 - free, 0 - occupied
    unsigned int cheksum;
};

struct chunk_t* create_chunk (void* start, size_t size, int free, struct chunk_t *prev, struct chunk_t* next);

struct heap_t {
    void* start_brk;
    void* brk;
    struct chunk_t *first_chunk;
    size_t size;
} heap;

int heap_setup(void);
int increase_memory (size_t mem);

void heap_clean(void);

void* heap_malloc(size_t size);
struct chunk_t* search_for_free_chunk (size_t size);
void set_fences (struct chunk_t* mem, char fence, int fence_size);
void * create_first_chunk (size_t size);
void * resize_first_chunk (size_t size);
void *create_new_chunk(size_t size);
struct chunk_t *find_tail(void);

void* heap_calloc(size_t number, size_t size);

void* heap_realloc(void* memblock, size_t count);
struct chunk_t * get_chunk_from_void_pointer(void *pointer);
void *resize_chunk (struct chunk_t *chunk, size_t new_size);
void* resize_two_neighbour_chunks (struct chunk_t* to_resize, size_t added_memory);
void *merge_neighbour (struct chunk_t *to_resize, size_t size);
void* resize_at_the_end (struct chunk_t *to_resize, size_t added_memory);
void* find_best_fit (struct chunk_t* to_resize, size_t new_size);
size_t get_real_size (struct chunk_t *chunk);

void  heap_free(void* memblock);
struct chunk_t * merge_right_side(struct chunk_t *to_free);
struct chunk_t * merge_left_side(struct chunk_t *to_free);

size_t heap_get_largest_used_block_size(void);

enum pointer_type_t {
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

enum pointer_type_t get_pointer_type(const void* const pointer);

int heap_validate(void);
int control_block_corrupted (void);
int fences_corrupted(char *fence, int fence_size);
int heap_uninitialized (void);
unsigned int calculate_checksum (struct chunk_t * chunk);

void* heap_malloc_aligned(size_t count);
void * create_first_chunk_aligned (size_t size);
struct chunk_t* search_for_free_chunk_aligned (size_t size);
void *create_new_chunk_aligned(size_t size);

void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);
void* find_best_fit_aligned (struct chunk_t* to_resize, size_t new_size);

int aligned_to_page(void *ptr);

#endif //SO2_HEAP_H
