#pragma once

#include <atomic>
#include <shared_mutex>

using namespace std;

/**
 * @brief A lock that can only be taken exclusively. Contrarily to shared locks,
 * exclusive locks have wait/wake_up capabilities.
 */
struct lock_t {
    atomic<uint64_t> version;

    lock_t() : version(0) {}
    lock_t(const lock_t &lock){version = lock.version.load();}
};

/** Wait and acquire the given lock.
 * @param lock Lock to acquire
 * @return Whether the operation is a success
**/
bool lock_acquire(struct lock_t* lock);

/** Release the given lock.
 * @param lock Lock to release
**/
bool lock_release(struct lock_t* lock, uint64_t new_version);

/** Release the given lock.
 * @param lock Lock to release
**/
bool lock_release(struct lock_t* lock);

/** Get the current version of the lock.
 * @param lock Lock to query
 * @return Current version of the lock
**/
uint64_t get_version(struct lock_t* lock);

/** Get whether the lock is locked.
 * @param lock Lock to query
 * @return Whether the lock is locked
**/
bool is_locked(struct lock_t* lock);

uint64_t get_lock(struct lock_t* lock);
