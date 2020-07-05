#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "myMalloc.h"
#include "printing.h"

/* Due to the way assert() prints error messges we use out own assert function
 * for deteminism when testing assertions
 */
#ifdef TEST_ASSERT
  inline static void assert(int e) {
    if (!e) {
      const char * msg = "Assertion Failed!\n";
      write(2, msg, strlen(msg));
      exit(1);
    }
  }
#else
  #include <assert.h>
#endif

/*
 * Mutex to ensure thread safety for the freelist
 */
static pthread_mutex_t mutex;

/*
 * Array of sentinel nodes for the freelists
 */
header freelistSentinels[N_LISTS];

/*
 * Pointer to the second fencepost in the most recently allocated chunk from
 * the OS. Used for coalescing chunks
 */
header * lastFencePost;

/*
 * Pointer to maintian the base of the heap to allow printing based on the
 * distance from the base of the heap
 */ 
void * base;

/*
 * List of chunks allocated by  the OS for printing boundary tags
 */
header * osChunkList [MAX_OS_CHUNKS];
size_t numOsChunks = 0;

/*
 * direct the compiler to run the init function before running main
 * this allows initialization of required globals
 */
static void init (void) __attribute__ ((constructor));

// Helper functions for manipulating pointers to headers
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off);
static inline header * get_left_header(header * h);
static inline header * ptr_to_header(void * p);

// Helper functions for allocating more memory from the OS
static inline void initialize_fencepost(header * fp, size_t left_size);
static inline void insert_os_chunk(header * hdr);
static inline void insert_fenceposts(void * raw_mem, size_t size);
static header * allocate_chunk(size_t size);

// Helper functions for freeing a block
static inline void deallocate_object(void * p);

// Helper functions for allocating a block
static inline header * allocate_object(size_t raw_size);

// Helper functions for verifying that the data structures are structurally 
// valid
static inline header * detect_cycles();
static inline header * verify_pointers();
static inline bool verify_freelist();
static inline header * verify_chunk(header * chunk);
static inline bool verify_tags();

static void init();

static bool isMallocInitialized;

/**
 * @brief Helper function to retrieve a header pointer from a pointer and an 
 *        offset
 *
 * @param ptr base pointer
 * @param off number of bytes from base pointer where header is located
 *
 * @return a pointer to a header offset bytes from pointer
 */
static inline header * get_header_from_offset(void * ptr, ptrdiff_t off) {
	return (header *)((char *) ptr + off);
}

/**
 * @brief Helper function to get the header to the right of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
header * get_right_header(header * h) {
	return get_header_from_offset(h, get_size(h));
}

/**
 * @brief Helper function to get the header to the left of a given header
 *
 * @param h original header
 *
 * @return header to the right of h
 */
inline static header * get_left_header(header * h) {
  return get_header_from_offset(h, -h->left_size);
}

/**
 * @brief Fenceposts are marked as always allocated and may need to have
 * a left object size to ensure coalescing happens properly
 *
 * @param fp a pointer to the header being used as a fencepost
 * @param left_size the size of the object to the left of the fencepost
 */
inline static void initialize_fencepost(header * fp, size_t left_size) {
	set_state(fp,FENCEPOST);
	set_size(fp, ALLOC_HEADER_SIZE);
	fp->left_size = left_size;
}

/**
 * @brief Helper function to maintain list of chunks from the OS for debugging
 *
 * @param hdr the first fencepost in the chunk allocated by the OS
 */
inline static void insert_os_chunk(header * hdr) {
  if (numOsChunks < MAX_OS_CHUNKS) {
    osChunkList[numOsChunks++] = hdr;
  }
}

/**
 * @brief given a chunk of memory insert fenceposts at the left and 
 * right boundaries of the block to prevent coalescing outside of the
 * block
 *
 * @param raw_mem a void pointer to the memory chunk to initialize
 * @param size the size of the allocated chunk
 */
inline static void insert_fenceposts(void * raw_mem, size_t size) {
  // Convert to char * before performing operations
  char * mem = (char *) raw_mem;

  // Insert a fencepost at the left edge of the block
  header * leftFencePost = (header *) mem;
  initialize_fencepost(leftFencePost, ALLOC_HEADER_SIZE);

  // Insert a fencepost at the right edge of the block
  header * rightFencePost = get_header_from_offset(mem, size - ALLOC_HEADER_SIZE);
  initialize_fencepost(rightFencePost, size - 2 * ALLOC_HEADER_SIZE);
}

/**
 * @brief Allocate another chunk from the OS and prepare to insert it
 * into the free list
 *
 * @param size The size to allocate from the OS
 *
 * @return A pointer to the allocable block in the chunk (just after the 
 * first fencpost)
 */
static header * allocate_chunk(size_t size) {
  void * mem = sbrk(size);
  
  insert_fenceposts(mem, size);
  header * hdr = (header *) ((char *)mem + ALLOC_HEADER_SIZE);
  set_state(hdr, UNALLOCATED);
  set_size(hdr, size - 2 * ALLOC_HEADER_SIZE);
  hdr->left_size = ALLOC_HEADER_SIZE;
  return hdr;
}

/**
 * @brief Helper allocate an object given a raw request size from the user
 *
 * @param raw_size number of bytes the user needs
 *
 * @return A block satisfying the user's request
 */
static inline header * allocate_object(size_t raw_size) {
  // TODO implement allocation
  //(void) raw_size;
  //assert(false);
  //exit(1);

	//printf("beginning\n");
	//check if the size of malloc call is valid
	if (raw_size == 0) {
		return NULL;
	}


	size_t real_size = raw_size;

	//set to minimum size to 16 if raw_size < 16
	if (real_size < 16) {
		real_size = ALLOC_HEADER_SIZE;
	} else {
		//round up real_size to multiple of 8
		real_size = ((real_size + 7) & (-8));
		//real_size = ((real_size + 7) & (-8)) + 16;
	}

	//printf("iterating freelists\n");
	//find optimal unallocated memory
	for (int i = real_size/8-1; i < N_LISTS-1; i++) {
		if (freelistSentinels[i].next != &freelistSentinels[i]) {
			header* temp = &freelistSentinels[i];

			//if unallocated memory > real_size + 32
			if (get_size(temp->next) - (real_size + ALLOC_HEADER_SIZE) >= 32) {
				//remove free memory from freelist
				//printf("FLAGGGGGGGGGGGG\n");
				temp = freelistSentinels[i].next;
				freelistSentinels[i].next = temp->next;
				freelistSentinels[i].next->prev = &freelistSentinels[i];
				temp->next = NULL;
				temp->prev = NULL;
				set_size(temp, get_size(temp) - (real_size + ALLOC_HEADER_SIZE));
				//printf("temp size: %ld\n", get_size(temp));
				//printf("111111111111111\n");
				freelistSentinels[(get_size(temp)-16) / 8 - 1].next->prev = temp;
				temp->next = freelistSentinels[(get_size(temp)-16) / 8 - 1].next;
				temp->prev = &freelistSentinels[(get_size(temp)-16) / 8 - 1];
				freelistSentinels[(get_size(temp)-16) / 8 - 1].next = temp;
				//printf("22222222222222222\n");
				//allocate memory and set left_size
				header* t1 = get_right_header(temp);
				set_size_and_state(t1, real_size + ALLOC_HEADER_SIZE, ALLOCATED);
				t1->left_size = get_size(temp);
				//printf("3333333333333333333\n");
				//set left_size of the right-neighbor of allocated memory
				header* t2 = get_right_header(t1);
				t2->left_size = get_size(t1);
				//printf("444444444444444444444\n");

				return (header*)t1->data;
			} else {
				//allocate memory
				temp = freelistSentinels[i].next;
				freelistSentinels[i].next = temp->next;
				freelistSentinels[i].next->prev = &freelistSentinels[i];
				temp->next = NULL;
				temp->prev = NULL;
				set_size_and_state(temp, real_size + 16, ALLOCATED);
				return (header*)temp->data;
			}
		}
	}

	//iterate last free list for optimal unallocated memory
	header* iterator = &freelistSentinels[N_LISTS - 1];

	//printf("iterating last list\n");
	while (iterator->next != &freelistSentinels[N_LISTS - 1]) {
		iterator = iterator->next;
		header* temp;

		//free memory has +32 extra space than asked
		if (get_size(iterator) - (real_size + 16) >= 32) {
			//get right header of free memory
			header* right = get_right_header(iterator);

			//split memory
			set_size(iterator, get_size(iterator) - (real_size + 16));

			//update left_size of right header of free memory
			right->left_size = real_size + 16;
			
			//temp is now at newly allocated memory address
			temp = get_left_header(right);
			
			//set size
			set_size_and_state(temp, real_size + 16, ALLOCATED);

			//set left_size
			temp->left_size = get_size(iterator);

			//check if remainder of free memory has to be placed in a new freelistSentinel
			if (get_size(iterator) < 488) {
				iterator->prev->next = iterator->next;
				iterator->next->prev = iterator->prev;
				iterator->next = NULL;
				iterator->prev = NULL;
				freelistSentinels[(get_size(iterator)-16)/8-1].next->prev = iterator;
				iterator->next = freelistSentinels[(get_size(iterator)-16)/8-1].next;
				iterator->prev = &freelistSentinels[(get_size(iterator)-16)/8-1];
				freelistSentinels[(get_size(iterator)-16)/8-1].next = iterator;
			}


			return (header*) temp->data;
		} else if (get_size(iterator) - (real_size + 16) >= 0) {
			//allocate free memory
			iterator->prev->next = iterator->next;
			iterator->next->prev = iterator->prev;
			iterator->next = NULL;
			iterator->prev = NULL;

			set_state(iterator, ALLOCATED);

			return (header*) iterator->data;
		} else {
			//go to next memory in freelistSentinels
			continue;
		}
	}

	//no free memory found, use system call sbrk()
	header* block = allocate_chunk(ARENA_SIZE);		//fenceposts initialized
	//printf("block size: %ld\n", get_size(block));
	header* prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
	//printf("prevFencePost size: %ld\n", get_size(prevFencePost));
	header* checker = get_header_from_offset(prevFencePost, -ALLOC_HEADER_SIZE);

	//when new chunk is adjacent to previous chunk
	if (checker == lastFencePost) {
		//coalesce the chunks
		set_state(prevFencePost, UNALLOCATED);
		set_size_and_state(checker, get_size(block) + 2 * ALLOC_HEADER_SIZE, UNALLOCATED);
		//printf("block size: %ld\n", get_size(block));
		//printf("checker size: %ld\n", get_size(checker));
		
		header* leftie = get_left_header(checker);

		//check if left-neighbor is free
		if (get_state(leftie) == UNALLOCATED) {
			//printf("YESSSSSSSSSSSSSSSSSSSSSSSSSSS\n");
			header* temp = get_left_header(checker);
			temp->prev->next = temp->next;
			temp->next->prev = temp->prev;
			temp->next = NULL;
			temp->prev = NULL;

			set_size(temp, get_size(temp) + get_size(checker));
			checker = temp;
		}

		//update lastFencePost
		lastFencePost = get_header_from_offset(checker, get_size(checker));
		lastFencePost->left_size = real_size + ALLOC_HEADER_SIZE;

		//if the coalesced chunk is not big enough for requested memory
		if (get_size(checker) < real_size + ALLOC_HEADER_SIZE) {
			lastFencePost->left_size = get_size(checker);

			checker->prev->next = checker->next;
			checker->next->prev = checker->prev;

			//insert the new free memory to freelistSentinel
			freelistSentinels[N_LISTS - 1].next->prev = checker;
			checker->next = freelistSentinels[N_LISTS - 1].next;
			freelistSentinels[N_LISTS - 1].next = checker;
			checker->prev = &freelistSentinels[N_LISTS - 1];

			allocate_object(raw_size);
		}
		

		//allocate memory requested from coalesced chunk
		//printf("real_size: %ld\n", real_size);
		set_size(checker, get_size(checker) - (real_size + ALLOC_HEADER_SIZE));
		//printf("checker size: %ld\n", get_size(checker));
		header* new = get_header_from_offset(checker, get_size(checker));
		set_size_and_state(new, real_size + ALLOC_HEADER_SIZE, ALLOCATED);
		new->left_size = get_size(checker);

		//insert split up memory into freeListSentinel
		if (get_size(checker) < 488) {
			freelistSentinels[(get_size(checker) - 16) / 8 - 1].next->prev = checker;
			checker->next = freelistSentinels[(get_size(checker) - 16) / 8 - 1].next;
			checker->prev = &freelistSentinels[(get_size(checker) - 16) / 8 - 1];
			freelistSentinels[(get_size(checker) - 16) / 8 - 1].next = checker;
		} else {
			freelistSentinels[N_LISTS - 1].next->prev = checker;
			checker->next = freelistSentinels[N_LISTS - 1].next;
			freelistSentinels[N_LISTS - 1].next = checker;
			checker->prev = &freelistSentinels[N_LISTS - 1];
		}

		return (header*) new->data;
	} else {
		insert_os_chunk(prevFencePost);
		lastFencePost = get_header_from_offset(block, get_size(block));

		//if new chunk is smaller than request size
		if (get_size(block) < real_size) {
			//insert the new free memory to freelistSentinel
			freelistSentinels[N_LISTS - 1].next->prev = block;
			block->next = freelistSentinels[N_LISTS - 1].next;
			freelistSentinels[N_LISTS - 1].next = block;
			block->prev = &freelistSentinels[N_LISTS - 1];

			allocate_object(raw_size);
		} else {
			//update left_size of lastFencePost
			lastFencePost->left_size = real_size + ALLOC_HEADER_SIZE;

			//allocate memory requested from coalesced chunk
			set_size(block, get_size(block) - (real_size + ALLOC_HEADER_SIZE));
			header* new = get_header_from_offset(block, get_size(block));
			set_size_and_state(new, real_size + ALLOC_HEADER_SIZE, ALLOCATED);
			new->left_size = get_size(block);

			if (get_size(block) < 488) {
				freelistSentinels[(get_size(block) - 16) / 8 - 1].next->prev = block;
				block->next = freelistSentinels[(get_size(block) - 16) / 8 - 1].next;
				block->prev = &freelistSentinels[(get_size(block) - 16) / 8 - 1];
				freelistSentinels[(get_size(block) - 16) / 8 - 1].next = block;
			}
			else {
				freelistSentinels[N_LISTS - 1].next->prev = block;
				block->next = freelistSentinels[N_LISTS - 1].next;
				freelistSentinels[N_LISTS - 1].next = block;
				block->prev = &freelistSentinels[N_LISTS - 1];
			}

			return (header*) new->data;
		}
	}
}

/**
 * @brief Helper to get the header from a pointer allocated with malloc
 *
 * @param p pointer to the data region of the block
 *
 * @return A pointer to the header of the block
 */
static inline header * ptr_to_header(void * p) {
  return (header *)((char *) p - ALLOC_HEADER_SIZE); //sizeof(header));
}

/**
 * @brief Helper to manage deallocation of a pointer returned by the user
 *
 * @param p The pointer returned to the user by a call to malloc
 */
static inline void deallocate_object(void * p) {
  // TODO implement deallocation
  //(void) p;
  //assert(false);
  //exit(1);
	if (p != NULL) {
		header* temp = p - 16;

		/*
		if (p == NULL) {
			printf("Freeing a null pointer\n");
			exit(1);
		}
		*/

		//check if p is already free
		if (get_state(temp) == UNALLOCATED) {
			fprintf(stderr, "Double Free Detected\n");
			assert(false);
		}

		//free the memory
		set_state(temp, UNALLOCATED);

		//flag to avoid "no neighbor statement 
		int flag = 0;

		//check if right-neighbor is free
		header* right = get_right_header(temp);
		int size_holder = get_size(temp);

		if (get_state(right) == UNALLOCATED) {
			//remove the memory to be coalesced from freelistSentinel
			right->prev->next = right->next;
			right->next->prev = right->prev;

			//update size of coalesced memory
			size_holder += get_size(right);
			set_size(temp, size_holder);

			//set left_size of right block of coalesced memory
			right = get_right_header(temp);
			right->left_size = get_size(temp);

			if (get_size(temp) < 488) {
				freelistSentinels[((get_size(temp) - 16) / 8) - 1].next->prev = temp;
				temp->next = freelistSentinels[((get_size(temp) - 16) / 8) - 1].next;
				freelistSentinels[((get_size(temp) - 16) / 8) - 1].next = temp;
				temp->prev = &freelistSentinels[((get_size(temp) - 16) / 8) - 1];
			}
			else {
				freelistSentinels[N_LISTS - 1].next->prev = temp;
				temp->next = freelistSentinels[N_LISTS - 1].next;
				freelistSentinels[N_LISTS - 1].next = temp;
				temp->prev = &freelistSentinels[N_LISTS - 1];
			}

			flag = 1;
		}


		//check if left-neighbor is free
		header* left = get_left_header(temp);
		size_holder = get_size(temp);

		if (get_state(left) == UNALLOCATED) {
			//printf("1111111111111\n");
			//remove the memory to be coalesced from freelistSentinel
			left->prev->next = left->next;
			left->next->prev = left->prev;

			if (flag == 1) {
				temp->prev->next = temp->next;
				temp->next->prev = temp->prev;
			}

			//update size of coalesced memory
			size_holder += get_size(left);
			set_size(left, size_holder);

			//set left_size of right block of coalesced memory
			right = get_right_header(left);
			right->left_size = get_size(left);

			if (get_size(left) < 488) {
				freelistSentinels[((get_size(left) - 16) / 8) - 1].next->prev = left;
				left->next = freelistSentinels[((get_size(left) - 16) / 8) - 1].next;
				freelistSentinels[((get_size(left) - 16) / 8) - 1].next = left;
				left->prev = &freelistSentinels[((get_size(left) - 16) / 8) - 1];
			}
			else {
				freelistSentinels[N_LISTS - 1].next->prev = left;
				left->next = freelistSentinels[N_LISTS - 1].next;
				freelistSentinels[N_LISTS - 1].next = left;
				left->prev = &freelistSentinels[N_LISTS - 1];
			}

			flag = 1;
		}

		//no neighbors are free
		if (flag == 0) {
			if (get_size(temp) < 488) {
				freelistSentinels[((get_size(temp) - 16) / 8) - 1].next->prev = temp;
				temp->next = freelistSentinels[((get_size(temp) - 16) / 8) - 1].next;
				freelistSentinels[((get_size(temp) - 16) / 8) - 1].next = temp;
				temp->prev = &freelistSentinels[((get_size(temp) - 16) / 8) - 1];
			}
			else {
				freelistSentinels[N_LISTS - 1].next->prev = temp;
				temp->next = freelistSentinels[N_LISTS - 1].next;
				freelistSentinels[N_LISTS - 1].next = temp;
				temp->prev = &freelistSentinels[N_LISTS - 1];
			}
		}
	}
}

/**
 * @brief Helper to detect cycles in the free list
 * https://en.wikipedia.org/wiki/Cycle_detection#Floyd's_Tortoise_and_Hare
 *
 * @return One of the nodes in the cycle or NULL if no cycle is present
 */
static inline header * detect_cycles() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * slow = freelist->next, * fast = freelist->next->next; 
         fast != freelist; 
         slow = slow->next, fast = fast->next->next) {
      if (slow == fast) {
        return slow;
      }
    }
  }
  return NULL;
}

/**
 * @brief Helper to verify that there are no unlinked previous or next pointers
 *        in the free list
 *
 * @return A node whose previous and next pointers are incorrect or NULL if no
 *         such node exists
 */
static inline header * verify_pointers() {
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    for (header * cur = freelist->next; cur != freelist; cur = cur->next) {
      if (cur->next->prev != cur || cur->prev->next != cur) {
        return cur;
      }
    }
  }
  return NULL;
}

/**
 * @brief Verify the structure of the free list is correct by checkin for 
 *        cycles and misdirected pointers
 *
 * @return true if the list is valid
 */
static inline bool verify_freelist() {
  header * cycle = detect_cycles();
  if (cycle != NULL) {
    fprintf(stderr, "Cycle Detected\n");
    print_sublist(print_object, cycle->next, cycle);
    return false;
  }

  header * invalid = verify_pointers();
  if (invalid != NULL) {
    fprintf(stderr, "Invalid pointers\n");
    print_object(invalid);
    return false;
  }

  return true;
}

/**
 * @brief Helper to verify that the sizes in a chunk from the OS are correct
 *        and that allocated node's canary values are correct
 *
 * @param chunk AREA_SIZE chunk allocated from the OS
 *
 * @return a pointer to an invalid header or NULL if all header's are valid
 */
static inline header * verify_chunk(header * chunk) {
	if (get_state(chunk) != FENCEPOST) {
		fprintf(stderr, "Invalid fencepost\n");
		print_object(chunk);
		return chunk;
	}
	
	for (; get_state(chunk) != FENCEPOST; chunk = get_right_header(chunk)) {
		if (get_size(chunk)  != get_right_header(chunk)->left_size) {
			fprintf(stderr, "Invalid sizes\n");
			print_object(chunk);
			return chunk;
		}
	}
	
	return NULL;
}

/**
 * @brief For each chunk allocated by the OS verify that the boundary tags
 *        are consistent
 *
 * @return true if the boundary tags are valid
 */
static inline bool verify_tags() {
  for (size_t i = 0; i < numOsChunks; i++) {
    header * invalid = verify_chunk(osChunkList[i]);
    if (invalid != NULL) {
      return invalid;
    }
  }

  return NULL;
}

/**
 * @brief Initialize mutex lock and prepare an initial chunk of memory for allocation
 */
static void init() {
  // Initialize mutex for thread safety
  pthread_mutex_init(&mutex, NULL);

#ifdef DEBUG
  // Manually set printf buffer so it won't call malloc when debugging the allocator
  setvbuf(stdout, NULL, _IONBF, 0);
#endif // DEBUG

  // Allocate the first chunk from the OS
  header * block = allocate_chunk(ARENA_SIZE);

  header * prevFencePost = get_header_from_offset(block, -ALLOC_HEADER_SIZE);
  insert_os_chunk(prevFencePost);

  lastFencePost = get_header_from_offset(block, get_size(block));

  // Set the base pointer to the beginning of the first fencepost in the first
  // chunk from the OS
  base = ((char *) block) - ALLOC_HEADER_SIZE; //sizeof(header);

  // Initialize freelist sentinels
  for (int i = 0; i < N_LISTS; i++) {
    header * freelist = &freelistSentinels[i];
    freelist->next = freelist;
    freelist->prev = freelist;
  }

  // Insert first chunk into the free list
  header * freelist = &freelistSentinels[N_LISTS - 1];
  freelist->next = block;
  freelist->prev = block;
  block->next = freelist;
  block->prev = freelist;
}

/* 
 * External interface
 */
void * my_malloc(size_t size) {
  pthread_mutex_lock(&mutex);
  header * hdr = allocate_object(size); 
  pthread_mutex_unlock(&mutex);
  return hdr;
}

void * my_calloc(size_t nmemb, size_t size) {
  return memset(my_malloc(size * nmemb), 0, size * nmemb);
}

void * my_realloc(void * ptr, size_t size) {
  void * mem = my_malloc(size);
  memcpy(mem, ptr, size);
  my_free(ptr);
  return mem; 
}

void my_free(void * p) {
  pthread_mutex_lock(&mutex);
  deallocate_object(p);
  pthread_mutex_unlock(&mutex);
}

bool verify() {
  return verify_freelist() && verify_tags();
}
