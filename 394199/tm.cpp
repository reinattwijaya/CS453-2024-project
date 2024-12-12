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
#include "tm.hpp"
#include <iostream>
#include <cstdlib>
#include <string>
#include <atomic>
#include <unordered_set>
#include <map>
#include <mutex>
#include "lock.hpp"

#include "macros.h"

using namespace std;

/**
 * @brief Simple Shared Memory Region (a.k.a Transactional Memory).
 */
struct Region {
    atomic<int> global_version{0}; // Global version number
    void* start;        // Start of the shared memory region (i.e., of the non-deallocable memory segment)
    vector<void*> allocs;        // allocated segments
    vector<lock_t*> locks; //Lock for each segment
    mutex vector_lock; // Lock for the shared memory region
    size_t size;        // Size of the non-deallocable memory segment (in bytes)
    size_t align;       // Size of a word in the shared memory region (in bytes)
};

struct Transaction {
    unordered_set<const void*> read_set;
    map<void*, const void*> write_set;
    unordered_set<int> segment_ids;
    int rv;
    bool is_ro;
};

static thread_local Transaction tx;

// get both the starting address and the actual address
pair<void*, void*> get_address(shared_t shared, const void* addr){
    struct region* region = (struct region*) shared;
    uintptr_t address = reinterpret_cast<uintptr_t>(addr);
    uint16_t segment_id = address>>48;
    void* actual_address = reinterpret_cast<void*>((address << 16) >> 16);
    if(segment_id == 0)
        return make_pair(region->start, actual_address);
    auto the_ptr = region->allocs;
    int count = 1;
    while (the_ptr) { // Free allocated segments
        if(count == segment_id)
            break;
        the_ptr = region->allocs->next;
        count++;
    }
    return make_pair(the_ptr + sizeof(struct segment_node), actual_address);
}

lock_t* get_lock(shared_t shared, const void* addr){
    pair<void*, void*> address = get_address(shared, addr);
    struct region* region = (struct region*) shared;
    size_t offset = (size_t) address.second - (size_t) address.first;

    return &region->locks[offset / region->align];
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept{
    Region* region = new Region();
    if (unlikely(!region)) {
        return invalid_shared;
    }
    // We allocate the shared memory buffer such that its words are correctly
    // aligned.
    if (posix_memalign(&(region->start), align, size) != 0) {
        free(region);
        return invalid_shared;
    }
    memset(region->start, 0, size);
    //allocate locks the same number as the size/align
    lock_t* init_lock = new lock_t[size/align + 1];

    region->vector_lock.lock();
    region->locks.push_back(init_lock);
    region->vector_lock.unlock();
    
    region->size        = size;
    region->align       = align;
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) noexcept{
    Region* region = (struct Region*) shared;
    while (region->allocs) { // Free allocated segments
        segment_list tail = region->allocs->next;
        free(region->allocs);
        region->allocs = tail;
    }
    free(region->start);
    delete[] region->locks;
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared) noexcept{
    return ((struct Region*) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept{
    return ((struct Region*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept{
    return ((struct Region*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept{
    Transaction* tx = new Transaction();
    tx->is_ro = is_ro;
    tx->rv = ((struct Region*) shared)->global_version.load();
    return reinterpret_cast<tx_t>(tx);
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept{
    Transaction* end_tx = reinterpret_cast<Transaction*>(tx);
    if(end_tx->is_ro){
        delete end_tx;
        tx = 0;
        return true;
    }
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
    struct Region* region = (struct Region*) shared;
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
        memcpy(entry.first, entry.second, sizeof(entry.second));
        lock_t* lock = get_lock(shared, entry.first);
        lock_release(lock, wv);
    }
    delete end_tx;
    tx = 0;
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
    Transaction* read_tx = reinterpret_cast<Transaction*>(tx);
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
        // for(const auto& enter: read_tx->write_set){
        //     cout << enter.first << ' ' << *(int*)enter.second << endl;
        // }
        void* the_source = (void*) source;
        //cout << "THE SOURCE: " << the_source << endl;
        auto it = read_tx->write_set.find(the_source);
        if (it != read_tx->write_set.end()){
            memcpy(target, it->second, size);
            return true;
        }
        read_tx->read_set.insert(source);
        //cout << *(int*)source << endl;
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
    Transaction* write_tx = reinterpret_cast<Transaction*>(tx);
    write_tx->write_set.insert({target, source});
    return false;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t tx, size_t size, void** target) noexcept{
    Region* region = (Region*) shared;
    Transaction* transaction = (Transaction*) tx;
    size_t align = ((struct Region*) shared)->align;

    void* segment;
    if (unlikely(posix_memalign(&segment, align, size) != 0)) // Allocation failed
        return Alloc::nomem;

    memset(segment, 0, size);

    lock_t* new_lock = new lock_t[size/align + 1];

    region->vector_lock.lock();
    region->allocs.push_back(segment);
    region->locks.push_back(new_lock);
    uint64_t vector_size = region->locks.size();
    region->vector_lock.unlock();
    transaction->segment_ids.insert(vector_size - 1);


    *target = reinterpret_cast<void*>((vector_size << 48) | reinterpret_cast<uintptr_t>(segment));

    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared, tx_t tx, void* segment) noexcept{
    struct Region* region = (struct Region*) shared;
    Transaction* transaction = (Transaction*) tx;
    uint16_t segment_id = reinterpret_cast<uintptr_t>(segment) >> 48;

    region->vector_lock.lock();
    free(region->allocs[segment_id]);
    free(region->locks[segment_id]);
    region->allocs[segment_id] = 0;
    region->locks[segment_id] = 0;
    region->vector_lock.unlock();

    return true;
}
