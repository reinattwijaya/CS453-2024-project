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
#pragma GCC optimize("Ofast")


// Internal headers
#include "tm.hpp"
#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <atomic>
#include <unordered_set>
#include <map>
#include <memory>
#include <shared_mutex>
#include <vector>
#include "lock.hpp"

#include "macros.h"

using namespace std;

/**
 * @brief Simple Shared Memory Region (a.k.a Transactional Memory).
 */

struct Segment{
    lock_t lock;
    void* data;
};

struct SegmentVector{
    vector<Segment> segment_vec;
    SegmentVector(size_t size): segment_vec(size){}
};

struct Region {
    Region(size_t size, size_t align): 
        size(size), align(align) {
            for (size_t i = 0; i < 2; ++i) {
                segments.push_back(std::make_unique<SegmentVector>(size/align + 10));
            }
        }
    size_t size;        // Size of the non-deallocable memory segment (in bytes)
    size_t align;       // Size of a word in the shared memory region (in bytes)
    size_t start;
    atomic<uint64_t> global_version{0}; // Global version number
    atomic<uint64_t> segment_count{2}; // Global segment count
    shared_mutex alloc_lock;
    vector<unique_ptr<SegmentVector>> segments;
};

struct Transaction {
    unordered_set<void*> read_set;
    map<uintptr_t, void*> write_set;
    uint64_t rv;
    bool is_ro = false;
};

thread_local Transaction the_transaction;

Segment& get_segment(Region* region, uintptr_t addr){
    shared_lock<shared_mutex> shared_lock(region->alloc_lock);
    SegmentVector* ptr = region->segments[addr >> 48].get();
    shared_lock.unlock();
    return ptr->segment_vec[((addr << 16) >> 16)/region->align];
}

SegmentVector* get_segment_vector(Region* region, uintptr_t addr){
    return region->segments[addr >> 48].get();
}

void abort_transaction(){
    the_transaction.rv = 0;
    the_transaction.is_ro = false;
    for (const auto &entry : the_transaction.write_set) {
       free(entry.second);
    }
    the_transaction.write_set.clear();
    the_transaction.read_set.clear();
}

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size, size_t align) noexcept{
    Region* region = new Region(size, align);
    if (unlikely(!region)) {
        return invalid_shared;
    }
    return region;
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared) noexcept{
    // cout << "destroying" << endl;
    Region* region = (struct Region*) shared;
    delete region;
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t unused(shared)) noexcept{
    // cout << "starting" << endl;
    return (void *)((uint64_t)1 << 48);
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared) noexcept{
    // cout << "sizing" << endl;
    return ((struct Region*) shared)->size;
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared) noexcept{
    // cout << "aligning" << endl;
    return ((struct Region*) shared)->align;
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared, bool is_ro) noexcept{
    // cout << the_transaction << endl;

    the_transaction.is_ro = is_ro;
    the_transaction.rv = ((struct Region*) shared)->global_version.load();
    // the_transaction->read_set.clear();
    // the_transaction->write_set.clear();
    return reinterpret_cast<tx_t>(&the_transaction);
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t unused(tx)) noexcept{
    // cout << "end" << endl;
    if(the_transaction.is_ro || the_transaction.write_set.empty()){
        abort_transaction();
        return true;
    }

    Region* region = (struct Region*) shared;
    // shared_lock shared_lock(region->alloc_lock);

    for (auto it = the_transaction.write_set.begin(); it != the_transaction.write_set.end(); ++it){
        Segment &segment = get_segment(region, it->first);
        if(!lock_acquire(&segment.lock)){
            for(auto temp_it = the_transaction.write_set.begin(); temp_it != it; ++temp_it){
                Segment &temp_segment = get_segment(region, temp_it->first);
                lock_release(&temp_segment.lock);
            }
            abort_transaction();
            return false;
        }
    }

    uint64_t wv = region->global_version.fetch_add(1)+1;

    if(the_transaction.rv + 1 != wv){
        for(const auto& entry: the_transaction.read_set){
            Segment &segment = get_segment(region, reinterpret_cast<uintptr_t>(entry));
            uint64_t val = get_lock(&segment.lock);
            if ((val & 1) || (val >> 1) > the_transaction.rv){
                for(const auto& entry : the_transaction.write_set){
                    Segment &temp_segment = get_segment(region, entry.first);
                    lock_release(&temp_segment.lock);
                }
                abort_transaction();
                return false;
            }
        }
    }
    for(const auto& entry : the_transaction.write_set){
        Segment &segment = get_segment(region, entry.first);
        memcpy(&segment.data, entry.second, region->align);
        if(!lock_release(&segment.lock, wv)){
            abort_transaction();
            return false;
        }
    }
    abort_transaction();
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
bool tm_read(shared_t shared, tx_t unused(tx), void const* source, size_t size, void* target) noexcept{
    // cout << "read" << endl;
    Region* region = (struct Region*) shared;
    // shared_lock shared_lock(region->alloc_lock);

    for(size_t i = 0; i < size / region->align; i++){
        uintptr_t addr = ((uintptr_t)source + region->align * i);
        Segment &segment = get_segment(region, addr);
        void* the_target = (void*)((uintptr_t)target + region->align * i); 

        if (the_transaction.is_ro) {
            uint64_t prev_value = get_lock(&segment.lock);
            memcpy(the_target, &segment.data, region->align);
            uint64_t post_value = get_lock(&segment.lock);
            if ((post_value & 1) || (prev_value >> 1) > the_transaction.rv || (post_value >> 1) != (prev_value >> 1)){
                // handle abort logic -> nothing
                abort_transaction();
                return false;
            }
            continue;
        }
        //if not read only
        else{
            auto it = the_transaction.write_set.find(addr);
            if (it != the_transaction.write_set.end()){
                memcpy(the_target, it->second, region->align);
                continue;
            }
            uint64_t prev_value = get_lock(&segment.lock);
            memcpy(target, &segment.data, size);

            uint64_t post_value = get_lock(&segment.lock);
            if ((post_value & 1) || (prev_value >> 1) > the_transaction.rv || (post_value >> 1) != (prev_value >> 1)){
                // handle abort logic -> nothing
                abort_transaction();
                return false;
            }
            the_transaction.read_set.emplace(reinterpret_cast<void*>(addr));
        }
    }

    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared, tx_t unused(tx), void const* source, size_t size, void* target) noexcept{
    // cout << "write" << endl;
    struct Region *region = (struct Region *)shared;
    for (size_t i = 0; i < size / region->align; i++) {
        uintptr_t the_target = ((uintptr_t)target + region->align * i); 
        void* the_source = reinterpret_cast<void*>((uintptr_t)source + region->align * i);
        void* source_copy = malloc(region->align); // free this
        memcpy(source_copy, the_source, region->align);
        the_transaction.write_set[the_target] = source_copy;
    }
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
Alloc tm_alloc(shared_t shared, tx_t unused(tx), size_t size, void** target) noexcept{
    // cout << "alloc" << endl;
    Region* region = (Region*) shared;
    unique_lock<shared_mutex> lock(region->alloc_lock);
    region->segments.push_back(std::make_unique<SegmentVector>(size/region->align + 10));
    *target = (void *)(region->segment_count.fetch_add(1) << 48ULL);
    return Alloc::success;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t unused(shared), tx_t unused(tx), void* unused(segment)) noexcept{
    // struct segment_node* sn = (struct segment_node*) ((uintptr_t) segment - sizeof(struct segment_node));

    // // Remove from the linked list
    // if (sn->prev) sn->prev->next = sn->next;
    // else ((struct region*) shared)->allocs = sn->next;
    // if (sn->next) sn->next->prev = sn->prev;

    // free(sn);
    
    return true;
}
