//
// Created by Tomala on 03.11.2020.
//

#include "heap.h"

int heap_setup(void) {
    heap.start_brk = custom_sbrk(0);
    if (heap.start_brk == (void *) -1) return -1;
    heap.brk = custom_sbrk(0);
    heap.size = 0;
    heap.first_chunk = NULL;
    return 0;
}

int increase_memory (size_t mem) {
    void *resize = custom_sbrk(mem);
    if (resize == (void *) -1) return 1;
    heap.brk = custom_sbrk(0);
    heap.size += mem;
    return 0;
}

struct chunk_t* create_chunk (void* start, size_t size, int free, struct chunk_t *prev, struct chunk_t* next) {
    struct chunk_t *new_chunk = (struct chunk_t *)start;
    new_chunk->size = size;
    new_chunk->free = free;
    new_chunk->prev = prev;
    new_chunk->next = next;
    new_chunk->cheksum = calculate_checksum(new_chunk);
    return new_chunk;
}

void heap_clean(void) {
    custom_sbrk(-heap.size);
    heap.start_brk = NULL;
    heap.brk = NULL;
    heap.size = 0;
    heap.first_chunk = NULL;
}

void* heap_malloc(size_t size) {
    if (size == 0) return NULL;
    if (heap_validate() != 0) return NULL;

    if (heap.first_chunk == NULL) return create_first_chunk(size);

    struct chunk_t *result = search_for_free_chunk(size);
    if (result != NULL) return (char *)result + sizeof(struct chunk_t) + FENCE_SIZE;

    // First block is free and one and only
    if (heap.first_chunk->next == NULL && heap.first_chunk->free == 1) return resize_first_chunk(size);

    return create_new_chunk (size);
}

struct chunk_t* search_for_free_chunk (size_t size) {
    for (struct chunk_t *pcurrent = heap.first_chunk; pcurrent != NULL; pcurrent = pcurrent->next) {
        if (pcurrent->free == 1 && pcurrent->size >= size + 2*FENCE_SIZE) {

            pcurrent->free = 0;
            pcurrent->size = size;
            pcurrent->cheksum = calculate_checksum(pcurrent);

            set_fences (pcurrent, '#', FENCE_SIZE);
            return pcurrent;
        }
    }
    return NULL;
}

void set_fences (struct chunk_t* mem, char fence, int fence_size) {
    memset((char *)mem + sizeof(struct chunk_t), fence, fence_size);
    memset((char *)mem + sizeof(struct chunk_t) + fence_size + mem->size, fence, fence_size);
}

void * create_first_chunk (size_t size) {
    if (increase_memory((sizeof(struct chunk_t) + 2*FENCE_SIZE + size))) return NULL;

    heap.first_chunk = create_chunk(heap.start_brk, size, 0, NULL, NULL);
    set_fences(heap.first_chunk, '#', FENCE_SIZE);

    return (char *)heap.first_chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

void * resize_first_chunk (size_t size) {
    if (increase_memory((sizeof(struct chunk_t) + 2*FENCE_SIZE + size) - heap.first_chunk->size)) return NULL;

    heap.first_chunk->size = size;
    heap.first_chunk->free = 0;
    heap.first_chunk->cheksum = calculate_checksum(heap.first_chunk);

    set_fences(heap.first_chunk, '#', FENCE_SIZE);
    return (char *)heap.first_chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

void *create_new_chunk(size_t size) {
    void *end = heap.brk;
    if (increase_memory(sizeof(struct chunk_t) + 2*FENCE_SIZE + size)) return NULL;

    struct chunk_t *tail = find_tail();
    struct chunk_t *new_chunk = create_chunk(end, size, 0, tail, NULL);

    tail->next = new_chunk;
    tail->cheksum = calculate_checksum(tail);

    set_fences(new_chunk, '#', FENCE_SIZE);

    return (char *)new_chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

struct chunk_t * find_tail(void) {
    struct chunk_t *tail = heap.first_chunk;
    for (; tail->next != NULL; tail = tail->next) {}
    return tail;
}

void* heap_calloc(size_t number, size_t size) {
    void *mem = heap_malloc(number*size);
    if (mem == NULL) return NULL;
    memset(mem, 0, number*size);
    return mem;
}

void* heap_realloc(void* memblock, size_t count) {
    if (heap_validate() != 0) return NULL;
    if (memblock == NULL) return heap_malloc(count);
    if (get_pointer_type(memblock) != pointer_valid) return NULL;

    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }

    struct chunk_t *to_realloc = get_chunk_from_void_pointer(memblock);

    if (find_tail() == to_realloc) return resize_at_the_end (to_realloc, count - to_realloc->size);

    size_t size_with_unused_memory = get_real_size(to_realloc);

    // there is enough space to resize
    if (size_with_unused_memory >= count) return resize_chunk(to_realloc, count);

    // neighbour chunk is big enough to resize and merge
    if (to_realloc->next != NULL) {
        if (to_realloc->next->free == 1 && to_realloc->next->size > count - size_with_unused_memory)
            return resize_two_neighbour_chunks(to_realloc, count - size_with_unused_memory);

        if (to_realloc->next->free == 1 && to_realloc->next->size + sizeof(struct chunk_t) >= count - size_with_unused_memory)
            return merge_neighbour (to_realloc, count);
    }

    return find_best_fit (to_realloc, count);
}

struct chunk_t * get_chunk_from_void_pointer(void *pointer) {
    if (get_pointer_type(pointer) != pointer_valid) return NULL;
    return (struct chunk_t *)((char *)pointer - sizeof(struct chunk_t) - FENCE_SIZE);
}

void * resize_chunk (struct chunk_t *chunk, size_t new_size) {
    chunk->size = new_size;
    set_fences(chunk, '#', FENCE_SIZE);
    chunk->cheksum = calculate_checksum(chunk);
    return (char *)chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

void* resize_two_neighbour_chunks (struct chunk_t* to_resize, size_t added_memory) {
    size_t unused_memory = get_real_size(to_resize) - to_resize->size;

    struct chunk_t *shifted_neighbour =
            create_chunk((char *)to_resize->next + added_memory,
                         to_resize->next->size - added_memory,
                                 1, to_resize, to_resize->next->next);

    if (shifted_neighbour->next != NULL) {
        shifted_neighbour->next->prev = shifted_neighbour;
        shifted_neighbour->next->cheksum = calculate_checksum(shifted_neighbour->next);
    }

    to_resize->size += added_memory + unused_memory;
    to_resize->next = shifted_neighbour;
    set_fences(to_resize, '#', FENCE_SIZE);
    to_resize->cheksum = calculate_checksum(to_resize);

    return (char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE;
}

void *merge_neighbour (struct chunk_t *to_resize, size_t size) {
    if (to_resize->next->next != NULL) {
        to_resize->next->next->prev = to_resize;
        to_resize->next->next->cheksum = calculate_checksum(to_resize->next->next);
    }
    to_resize->next = to_resize->next->next;

    to_resize->size = size;
    set_fences(to_resize, '#', FENCE_SIZE);
    to_resize->cheksum = calculate_checksum(to_resize);

    return (char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE;
}

void* resize_at_the_end (struct chunk_t *to_resize, size_t added_memory) {
    // There is enough space at the end of the heap
    if ((char *)heap.brk - (char *)to_resize - sizeof(struct chunk_t) - 2*FENCE_SIZE > to_resize->size + added_memory)
        return resize_chunk(to_resize, added_memory + to_resize->size);

    if (increase_memory(added_memory)) return NULL;

    return resize_chunk(to_resize, added_memory + to_resize->size);
}

void* find_best_fit (struct chunk_t* to_resize, size_t new_size) {
    void * new_block_mem = heap_malloc (new_size);
    if (new_block_mem == NULL) return NULL;
    struct chunk_t *new_block = get_chunk_from_void_pointer (new_block_mem);

    memcpy((char *)new_block + sizeof(struct chunk_t) + FENCE_SIZE,
            (char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE, to_resize->size);

    heap_free((char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE);

    return (char *)new_block + sizeof(struct chunk_t) + FENCE_SIZE;
}

size_t get_real_size (struct chunk_t *chunk) {
    if (find_tail() == chunk)
        return (char *)heap.brk - (char *)chunk - sizeof(struct chunk_t) - 2*FENCE_SIZE;
    return (char *)chunk->next - (char *)chunk - sizeof(struct chunk_t) - 2*FENCE_SIZE;
}

void  heap_free(void* memblock) {
    if (get_pointer_type(memblock) != pointer_valid) return;

    struct chunk_t *to_free = get_chunk_from_void_pointer(memblock);

    to_free = merge_right_side(to_free);
    to_free = merge_left_side(to_free);

    to_free->free = 1;
    to_free->cheksum = calculate_checksum(to_free);
}

struct chunk_t * merge_right_side(struct chunk_t *to_free) {
    if (to_free->next != NULL) {
        to_free->size = (char *)to_free->next - (char *)to_free - sizeof(struct chunk_t); // get unused memory

        if (to_free->next->free == 1) {
            struct chunk_t *pnext = to_free->next;

            to_free->size += sizeof(struct chunk_t) + pnext->size;
            to_free->next = pnext->next;
            if (pnext->next != NULL) {
                pnext->next->prev = to_free;
                pnext->next->cheksum = calculate_checksum(pnext->next);
            }
        }
    }
    return to_free;
}

struct chunk_t* merge_left_side(struct chunk_t *to_free) {
    if (to_free->prev != NULL) {
        if (to_free->prev->free == 1) {
            struct chunk_t *pprev = to_free->prev;

            pprev->size += sizeof(struct chunk_t) + to_free->size;

            if (to_free->next != NULL) {
                to_free->next->prev = pprev;
                to_free->next->cheksum = calculate_checksum(to_free->next);
            }

            pprev->next = to_free->next;
            to_free = pprev;
        }
    }
    return to_free;
}

size_t heap_get_largest_used_block_size(void) {
    if (heap_validate() != 0) return 0;

    size_t biggest_size = 0;
    for (struct chunk_t *current = heap.first_chunk; current != NULL; current = current->next) {
        if (current->size > biggest_size && current->free == 0) biggest_size = current->size;
    }

    return biggest_size;
}

enum pointer_type_t get_pointer_type(const void* const pointer) {
    if (pointer == NULL) return pointer_null;
    if (heap_validate() == 1 || heap_validate() == 3) return pointer_heap_corrupted;

    // iterujemy przez bloki i robimy obliczenia
    //          [BB####bbbbbbb####CCccccccc]
    //           ^
    //       pcurrent
    for (struct chunk_t *pcurrent = heap.first_chunk; pcurrent != NULL; pcurrent = pcurrent->next) {
        // sprawdzamy czy jest w obrebie tego bloku, jesli nie to lecimy do kolejnego bloku
        if (pcurrent->free == 1) {
            if ((char *)((char *)pcurrent + pcurrent->size + sizeof(struct chunk_t)) - (char*)pointer <= 0) continue;
        } else {
            if ((char *)((char *)pcurrent + pcurrent->size + 2*FENCE_SIZE + sizeof(struct chunk_t)) - (char*)pointer <= 0) continue;
            if((char*)pcurrent > (char*)pointer) continue;
        }

        // sprawdzamy czy pokazuje na strukture wewnetrzna sterty
        if ((char *)((char *)pcurrent + sizeof(struct chunk_t)) - (char *)pcurrent > (char *)((char *)pcurrent + sizeof(struct chunk_t)) - (char *)pointer) {
            // nie moze byc ujemna
            if ((char *)((char *)pcurrent + sizeof(struct chunk_t)) - (char *)pointer > 0) return pointer_control_block;
        }

        if (pcurrent->free == 1) {
            // musi pokazywac na obszar niezaalokowany
            return pointer_unallocated;
        } else {
            // sprawdzamy czy pokazuje na blok zwrocony przez malloc
            if (((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE) == pointer) return pointer_valid;
            // patrzymy czy wskazuje na obszar uzytkownika
            if ((char *)((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE + pcurrent->size) - (char *)((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE) >= ((char *)((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE + pcurrent->size) - (char *)pointer)) {
                // nie moze byc ujemna bo wtedy wskazuje na plotki za obszarem danych
                if ((char *)((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE + pcurrent->size) - (char *)pointer > 0) return pointer_inside_data_block;
            }

            // musi wskazywac na plotki
            return pointer_inside_fences;
        }
    }

    // wskaznik poza obszarem sterty
    return pointer_unallocated;
}

int heap_validate(void) {
    if (heap_uninitialized()) return 2;
    if (control_block_corrupted()) return 3;
    if (fences_corrupted("########", FENCE_SIZE)) return 1;
    return 0;
}

int control_block_corrupted(void) {
    for (struct chunk_t *chunk = heap.first_chunk; chunk != NULL; chunk = chunk->next) {
        if (chunk->cheksum != calculate_checksum(chunk)) return 1;
    }
    return 0;
}

int fences_corrupted(char *fence, int fence_size) {
    for (const struct chunk_t *chunk = heap.first_chunk; chunk != NULL; chunk = chunk->next) {
        if (chunk->free == 0) {
            // first fence
            if (memcmp((uint8_t *)chunk + sizeof(struct chunk_t), fence, fence_size) != 0) return 1;
            // second fence
            if (memcmp((uint8_t *)chunk + sizeof(struct chunk_t) + fence_size + chunk->size,
                       fence, fence_size) != 0) return 1;
        }
    }
    return 0;
}

int heap_uninitialized (void) {
    if (heap.brk == NULL && heap.start_brk == NULL && heap.size == 0 && heap.first_chunk == NULL) return 1;
    return 0;
}

unsigned int calculate_checksum (struct chunk_t *chunk) {
    unsigned int sum = 0;
    unsigned char *p = (unsigned char *)chunk;
    for (unsigned int i=0; i<sizeof(struct chunk_t) - sizeof(unsigned int); i++) {
        sum += p[i];
    }
    return sum;
}

void* heap_malloc_aligned(size_t count) {
    if (count == 0) return NULL;
    if (heap_validate() != 0) return NULL;

    if (heap.first_chunk == NULL) return create_first_chunk_aligned(count);

    struct chunk_t *result = search_for_free_chunk_aligned(count);
    if (result != NULL) return (char *)result + sizeof(struct chunk_t) + FENCE_SIZE;

    // First block is free and one and only
    if (heap.first_chunk->next == NULL && heap.first_chunk->free == 1
        && aligned_to_page((char *)heap.first_chunk + sizeof(struct chunk_t) + FENCE_SIZE))
            return resize_first_chunk(count);


    return create_new_chunk_aligned (count);
}

void * create_first_chunk_aligned (size_t size) {
    if (increase_memory((sizeof(struct chunk_t) + 2*FENCE_SIZE + size + PAGE))) return NULL;

    void * aligned_position = (char *)heap.start_brk + sizeof(struct chunk_t) + FENCE_SIZE;
    while (!aligned_to_page(aligned_position)) {
        aligned_position = (char *)aligned_position + 1;
    }

    heap.first_chunk = create_chunk((char *)aligned_position - sizeof(struct chunk_t) - FENCE_SIZE,
            size, 0, NULL, NULL);

    set_fences(heap.first_chunk, '#', FENCE_SIZE);

    return (char *)heap.first_chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

struct chunk_t* search_for_free_chunk_aligned (size_t size) {
    for (struct chunk_t *pcurrent = heap.first_chunk; pcurrent != NULL; pcurrent = pcurrent->next) {
        if (pcurrent->free == 1 && pcurrent->size >= size + 2*FENCE_SIZE && aligned_to_page((char *)pcurrent + sizeof(struct chunk_t) + FENCE_SIZE)) {

            pcurrent->free = 0;
            pcurrent->size = size;
            pcurrent->cheksum = calculate_checksum(pcurrent);

            set_fences (pcurrent, '#', FENCE_SIZE);
            return pcurrent;
        }
    }
    return NULL;
}

void *create_new_chunk_aligned(size_t size) {
    void *end = (char *)heap.brk + sizeof(struct chunk_t) + FENCE_SIZE;
    if (increase_memory(sizeof(struct chunk_t) + 2*FENCE_SIZE + size + PAGE)) return NULL;

    struct chunk_t *tail = find_tail();

    while (!aligned_to_page(end)) {
        end = (char *)end + 1;
    }

    struct chunk_t *new_chunk = create_chunk((char *)end - sizeof(struct chunk_t) - FENCE_SIZE, size, 0, tail, NULL);

    tail->next = new_chunk;
    tail->cheksum = calculate_checksum(tail);

    set_fences(new_chunk, '#', FENCE_SIZE);

    return (char *)new_chunk + sizeof(struct chunk_t) + FENCE_SIZE;
}

int aligned_to_page(void *ptr) {
    if (((intptr_t)ptr & (intptr_t)(PAGE - 1)) == 0) return 1;
    return 0;
}

void* heap_calloc_aligned(size_t number, size_t size) {
    void *mem = heap_malloc_aligned(number*size);
    if (mem == NULL) return NULL;
    memset(mem, 0, number*size);
    return mem;
}

void* heap_realloc_aligned(void* memblock, size_t size) {
    if (heap_validate() != 0) return NULL;
    if (memblock == NULL) return heap_malloc_aligned(size);
    if (get_pointer_type(memblock) != pointer_valid) return NULL;

    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }

    struct chunk_t *to_realloc = get_chunk_from_void_pointer(memblock);

    if (aligned_to_page(memblock)) {
        if (find_tail() == to_realloc) return resize_at_the_end (to_realloc, size - to_realloc->size);
        size_t size_with_unused_memory = get_real_size(to_realloc);

        // there is enough space to resize
        if (size_with_unused_memory >= size) return resize_chunk(to_realloc, size);

        // neighbour chunk is big enough to resize and merge
        if (to_realloc->next != NULL) {
            if (to_realloc->next->free == 1 && to_realloc->next->size > size - size_with_unused_memory)
                return resize_two_neighbour_chunks(to_realloc, size - size_with_unused_memory);

            if (to_realloc->next->free == 1 && to_realloc->next->size + sizeof(struct chunk_t) >= size - size_with_unused_memory)
                return merge_neighbour (to_realloc, size);
        }
    }

    return find_best_fit_aligned (to_realloc, size);
}

void* find_best_fit_aligned (struct chunk_t* to_resize, size_t new_size) {
    void * new_block_mem = heap_malloc_aligned (new_size);
    if (new_block_mem == NULL) return NULL;
    struct chunk_t *new_block = get_chunk_from_void_pointer (new_block_mem);

    memcpy((char *)new_block + sizeof(struct chunk_t) + FENCE_SIZE,
           (char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE, to_resize->size);

    heap_free((char *)to_resize + sizeof(struct chunk_t) + FENCE_SIZE);

    return (char *)new_block + sizeof(struct chunk_t) + FENCE_SIZE;
}
