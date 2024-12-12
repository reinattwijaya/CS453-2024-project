/**
 * @file   tm.c
 * @author [...]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers

// Internal headers
#include <tm.hpp>
#include <iostream>
#include <cstdlib>
#include <string>
#include <atomic>
#include <set>
#include <map>
#include "lock.hpp"

#include "macros.h"

using namespace std;

struct transaction {
    set<const void*> read_set;
    map<const void*, void*> write_set;
    int rv;
    bool is_ro;
};

/**
 * @brief List of dynamically allocated segments.
 */
struct segment_node {
    struct segment_node* prev;
    struct segment_node* next;
    // uint8_t segment[] // segment of dynamic size
};
typedef struct segment_node* segment_list;

/**
 * @brief Simple Shared Memory Region (a.k.a Transactional Memory).
 */
struct region {
    atomic<int> global_version; // Global version number
    void* start;        // Start of the shared memory region (i.e., of the non-deallocable memory segment)
    void* locks;        // Locks for each word in the shared memory region
    segment_list allocs; // Shared memory segments dynamically allocated via tm_alloc within transactions
    segment_list lock_allocs; // Locks for dynamically allocated via tm_alloc within transactions
    size_t size;        // Size of the non-deallocable memory segment (in bytes)
    size_t align;       // Size of a word in the shared memory region (in bytes)
};

lock_t* get_lock(shared_t shared, const void* addr){
    struct region* region = (struct region*) shared;
    size_t offset = (size_t) addr - (size_t) region->start;
    return (lock_t*) ((size_t) region->locks + offset);
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept{
    struct region* region = (struct region*) malloc(sizeof(struct region));
    if (unlikely(!region)) {
        return invalid_shared;
    }
    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&(region->start), align, size) != 0) {
        free(region);
        return invalid_shared;
    }
    //ask to TA about this
    if (posix_memalign(&(region->locks), align, size) != 0) {
        free(region);
        return invalid_shared;
    }
    memset(region->start, 0, size);
    region->allocs      = NULL;
    region->lock_allocs = NULL;
    region->size        = size;
    region->align       = align;
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) noexcept{
    struct region* region = (struct region*) shared;
    while (region->allocs) { // Free allocated segments
        segment_list tail = region->allocs->next;
        free(region->allocs);
        region->allocs = tail;
    }
    free(region->start);
    free(region->locks);
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) noexcept{
    return ((struct region*) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept{
    return ((struct region*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept{
    return ((struct region*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept{
    transaction* tx = new transaction();
    tx->is_ro = is_ro;
    tx->rv = ((struct region*) shared)->global_version.load();
    return reinterpret_cast<tx_t>(tx);
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept{
    transaction* end_tx = reinterpret_cast<transaction*>(tx);
    if(end_tx->is_ro)
        return true;
    for(const auto& entry : end_tx->write_set){
        lock_t* lock = get_lock(shared, entry.first);
        if(!lock_acquire(lock)){
            for(const auto& entry2 : end_tx->write_set){
                if(entry2.first == entry.first)
                    break;
                lock_t* lock = get_lock(shared, entry.first);
                lock_release(lock);
            }
            return false;
        }
    }
    struct region* region = (struct region*) shared;
    int wv = region->global_version.fetch_add(1);
    if(end_tx->rv + 1 != wv){
        for(const auto& entry: end_tx->read_set){
            lock_t* lock = get_lock(shared, entry);
            if (is_locked(lock) || get_version(lock) > end_tx->rv){
                // handle abort logic -> release lock
                for(const auto& entry : end_tx->write_set){
                    lock_t* lock = get_lock(shared, entry.first);
                    lock_release(lock, wv);
                }
                return false;
            }
        }
    }
    for(const auto& entry : end_tx->write_set){
        lock_t* lock = get_lock(shared, entry.first);
        lock_release(lock, wv);
    }
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/
bool tm_read(shared_t shared, tx_t tx, void const* source, size_t size, void* target) noexcept{
    transaction* read_tx = reinterpret_cast<transaction*>(tx);
    //if it is read only
    lock_t* lock = get_lock(shared, source);
    if (is_locked(lock) || get_version(lock) > read_tx->rv)
        // handle abort logic -> nothing
        return false;
    if (read_tx->is_ro) {
        memcpy(target, source, size);
        return true;
    }
    //if not read only
    else{
        auto it = read_tx->write_set.find(source);
        if (it != read_tx->write_set.end()){
            memcpy(target, it->second, size);
            return true;
        }
        read_tx->read_set.insert(source);
        memcpy(target, source, size);
        return true;
    }
    return false;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t unused(shared), tx_t tx, void const* source, size_t unused(size), void* target) noexcept{
    transaction* write_tx = reinterpret_cast<transaction*>(tx);
    write_tx->write_set.insert({source, target});
    return false;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) noexcept{
    size_t align = ((struct region*) shared)->align;
    align = align < sizeof(struct segment_node*) ? sizeof(void*) : align;

    struct segment_node* sn;
    if (unlikely(posix_memalign((void**)&sn, align, sizeof(struct segment_node) + size) != 0)) // Allocation failed
        return Alloc::nomem;

    // Insert in the linked list
    sn->prev = NULL;
    sn->next = ((struct region*) shared)->allocs;
    if (sn->next) sn->next->prev = sn;
    ((struct region*) shared)->allocs = sn;

    void* segment = (void*) ((uintptr_t) sn + sizeof(struct segment_node));
    memset(segment, 0, size);
    *target = segment;
    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t unused(tx), void* segment) noexcept{
    struct segment_node* sn = (struct segment_node*) ((uintptr_t) segment - sizeof(struct segment_node));

    // Remove from the linked list
    if (sn->prev) sn->prev->next = sn->next;
    else ((struct region*) shared)->allocs = sn->next;
    if (sn->next) sn->next->prev = sn->prev;

    free(sn);
    return true;
}
