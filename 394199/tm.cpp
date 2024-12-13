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
    lock_t lock = lock_t();
    uint64_t data = 0;
};

struct Region {
    Region(size_t size, size_t align): 
        size(size), align(align), locks(500, vector<Segment>(1500)){}
    size_t size;        // Size of the non-deallocable memory segment (in bytes)
    size_t align;       // Size of a word in the shared memory region (in bytes)
    atomic<uint64_t> global_version{0}; // Global version number
    atomic<uint64_t> segment_count{2}; // Global segment count
    vector<vector<Segment>> locks; //Lock for each segment
};

struct Transaction {
    unordered_set<void*> read_set;
    multimap<void*, uint64_t> write_set;
    uint64_t rv;
    bool is_ro;
};

static thread_local shared_ptr<Transaction> the_transaction;

Segment& get_segment(Region* region, void* addr){
    return region->locks[(reinterpret_cast<uintptr_t>(addr) >> 48)][((reinterpret_cast<uintptr_t>(addr) << 16) >> 16)/region->align];
}

void abort_transaction(){
    the_transaction->rv = 0;
    the_transaction->is_ro = false;
    the_transaction->write_set.clear();
    the_transaction->read_set.clear();
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
    if(!the_transaction)
        the_transaction = make_shared<Transaction>();
    the_transaction->is_ro = is_ro;
    the_transaction->rv = ((struct Region*) shared)->global_version.load();
    the_transaction->read_set.clear();
    the_transaction->write_set.clear();
    return reinterpret_cast<tx_t>(the_transaction.get());
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared, tx_t tx) noexcept{
    Transaction* end_tx = reinterpret_cast<Transaction*>(tx);
    if(end_tx->is_ro || end_tx->write_set.empty()){
        abort_transaction();
        return true;
    }
    Region* region = (struct Region*) shared;

    for (auto it = end_tx->write_set.begin(); it != end_tx->write_set.end(); ++it){
        const auto& entry = *it;
        Segment &segment = get_segment(region, entry.first);
        lock_t &lock = segment.lock;
        if(!lock_acquire(&lock)){
            for(auto temp_it = end_tx->write_set.begin(); temp_it != it; ++temp_it){
                Segment &temp_segment = get_segment(region, temp_it->first);
                lock_t &temp_lock = temp_segment.lock;
                lock_release(&temp_lock);
            }
            abort_transaction();
            return false;
        }
    }

    uint64_t wv = region->global_version.fetch_add(1)+1;

    if(end_tx->rv + 1 != wv){
        for(const auto& entry: end_tx->read_set){
            Segment &segment = get_segment(region, entry);
            lock_t &lock = segment.lock;
            if (is_locked(&lock) || get_version(&lock) > end_tx->rv){
                for(const auto& entry : end_tx->write_set){
                    Segment &temp_segment = get_segment(region, entry.first);
                    lock_t &temp_lock = temp_segment.lock;
                    lock_release(&temp_lock);
                }
                abort_transaction();
                return false;
            }
        }
    }
    for(const auto& entry : end_tx->write_set){
        Segment &segment = get_segment(region, entry.first);
        uint64_t &data = segment.data;
        memcpy(&data, &entry.second, sizeof(entry.second));
        lock_t &lock = segment.lock;
        lock_release(&lock, wv);
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
    Region* region = (struct Region*) shared;
    Transaction* read_tx = reinterpret_cast<Transaction*>(tx);

    for(size_t i = 0; i < size / region->align; i++){
        void* addr = reinterpret_cast<void*>((uintptr_t)source + region->align * i);
        Segment &segment = get_segment(region, addr);
        lock_t &lock = segment.lock;
        uint64_t &data = segment.data;
        uint64_t version = get_version(&lock);
        void* the_target = (void*)((uintptr_t)target + region->align * i); 

        if (is_locked(&lock) || version > read_tx->rv){
            // handle abort logic -> nothing
            abort_transaction();
            return false;
        }

        if (read_tx->is_ro) {
            memcpy(the_target, &data, size);
            if (is_locked(&lock) || get_version(&lock) > read_tx->rv || get_version(&lock) != version){
                // handle abort logic -> nothing
                abort_transaction();
                return false;
            }
            return true;
        }
        //if not read only
        else{
            auto it = read_tx->write_set.find(addr);
            if (it != read_tx->write_set.end()){
                memcpy(target, &it->second, size);
                return true;
            }
            read_tx->read_set.insert(addr);
            memcpy(target, &data, size);
            if (is_locked(&lock) || get_version(&lock) > read_tx->rv || get_version(&lock) != version){
                // handle abort logic -> nothing
                abort_transaction();
                return false;
            }
            return true;
        }
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
    struct Region *region = (struct Region *)shared;
    Transaction* write_tx = reinterpret_cast<Transaction*>(tx);
    for (size_t i = 0; i < size / region->align; i++) {
        void* the_target = (void*)((uintptr_t)target + region->align * i); 
        uint64_t the_source = (uint64_t)((uintptr_t)source + region->align * i);
        write_tx->write_set.insert({the_target, the_source});
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
Alloc tm_alloc(shared_t shared, tx_t unused(tx), size_t unused(size), void** target) noexcept{
    // cout << "allocating" << endl;
    Region* region = (Region*) shared;
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
    return true;
}
