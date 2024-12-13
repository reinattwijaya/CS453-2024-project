#include "lock.hpp"
#include <iostream>

bool lock_acquire(struct lock_t* lock) {
    int bounded_try = 1;
    do {
        // We use the lock_word's LSB for the lock state and the rest for the version number
        uint64_t current = lock->version.load();
        
        // Prepare desired value: lock bit is 1 (locked) and version stays the same
        uint64_t expected = current & ~1; // we want to make sure the expected is not locked
        uint64_t desired = current | 1;  // Set the LSB to 1 (locked)

        // Perform CAS (Compare-And-Swap)
        while (!lock->version.compare_exchange_strong(expected, desired)) {
        }
        return true;
        // If CAS fails, try again with the current value
    } while (bounded_try --);

    return false;
}

void lock_release(struct lock_t* lock, int new_version) {
    // Store the new lock word (release the lock)
    lock->version.store(new_version << 1);
}

void lock_release(struct lock_t* lock) {
    // Store the new lock word (release the lock)
    lock->version.store(lock->version.load() & ~1);
}

uint64_t get_version(struct lock_t* lock){
    return lock->version.load() >> 1;
}

bool is_locked(struct lock_t* lock){
    return lock->version.load() & 1;
}
