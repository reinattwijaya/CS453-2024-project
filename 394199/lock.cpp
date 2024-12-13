#include "lock.hpp"
#include <iostream>

bool lock_acquire(struct lock_t* lock) {
    // We use the lock_word's LSB for the lock state and the rest for the version number
    uint64_t current = lock->version.load();
    if(current & 1){
        return false;
    }
    
    // Prepare desired value: lock bit is 1 (locked) and version stays the same
    uint64_t desired = current | 1;  // Set the LSB to 1 (locked)

    // Perform CAS (Compare-And-Swap)
    return lock->version.compare_exchange_strong(current, desired);
    // If CAS fails, try again with the current value

}

bool lock_release(struct lock_t* lock, uint64_t new_version) {
    // Store the new lock word (release the lock)
    uint64_t current = lock->version.load();
    if(!(current & 1)){
        return false;
    }

    // Perform CAS (Compare-And-Swap)
    return lock->version.compare_exchange_strong(current, new_version << 1);
}

bool lock_release(struct lock_t* lock) {
    // Store the new lock word (release the lock)
    uint64_t current = lock->version.load();
    if(!(current & 1)){
        return false;
    }

    // Perform CAS (Compare-And-Swap)
    return lock->version.compare_exchange_strong(current, current & ~1);
}

uint64_t get_version(struct lock_t* lock){
    return lock->version.load() >> 1;
}

bool is_locked(struct lock_t* lock){
    return lock->version.load() & 1;
}

uint64_t get_lock(struct lock_t* lock){
    return lock->version.load();
}