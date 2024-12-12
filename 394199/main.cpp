#include<iostream>
#include"tm.hpp"
#include<thread>
#include <unistd.h>

using namespace std;

void read_and_write(shared_t shared){
    // sleep(1);
    tx_t tx = tm_begin(shared, false);
    int x = 5, x1 = 6;
    tm_write(shared, tx, &x, sizeof(int), shared);
    tm_write(shared, tx, &x1, sizeof(int), (void*)(static_cast<char*>(shared) + 40));
    int y = 0, y1 = 1;
    tm_read(shared, tx, shared, sizeof(int), &y);
    tm_read(shared, tx, (void*)(static_cast<char*>(shared) + 40), sizeof(int), &y1);
    cout << x << ' ' << y << ' ' << y1 << endl;
    if(!tm_end(shared, tx))
        cout << "TRANSACTION FAILED" << endl;
}

void read_and_write2(shared_t shared){
    // sleep(1);
    tx_t tx = tm_begin(shared, false);
    int x = 7, x1 = 8;
    tm_write(shared, tx, &x, sizeof(int), shared);
    tm_write(shared, tx, &x1, sizeof(int), (void*)(static_cast<char*>(shared) + 40));
    int y = 0, y1 = 1;
    tm_read(shared, tx, shared, sizeof(int), &y);
    tm_read(shared, tx, (void*)(static_cast<char*>(shared) + 40), sizeof(int), &y1);
    cout << x << ' ' << y << ' ' << y1 << endl;
    if(!tm_end(shared, tx))
        cout << "TRANSACTION FAILED" << endl;
}

void read1(shared_t shared){
    sleep(1);
    tx_t tx = tm_begin(shared, false);
    int y = 0, y1 = 1;
    tm_read(shared, tx, shared, sizeof(int), &y);
    tm_read(shared, tx, (void*)(static_cast<char*>(shared) + 40), sizeof(int), &y1);
    cout << y << ' ' << y1 << endl;
    tm_end(shared, tx);
}

int main(){

    shared_t shared = tm_create(1000, 8);
    if(shared == invalid_shared){
        cout << "Invalid shared memory region" << endl;
        return 1;
    }
    thread t1(read_and_write, shared);
    thread t2(read_and_write2, shared);
    thread t3(read1, shared);

    t1.join();
    t2.join();
    t3.join();
    // tm_start(shared);
    // int x = 5, x1 = 6;
    // tx_t tx = tm_begin(shared, false);
    // tm_write(shared, tx, &x, sizeof(int), shared);
    // tm_write(shared, tx, &x1, sizeof(int), (void*)(static_cast<char*>(shared) + 40));
    // int y = 0, y1 = 1;
    // tm_read(shared, tx, shared, sizeof(int), &y);
    // tm_read(shared, tx, (void*)(static_cast<char*>(shared) + 40), sizeof(int), &y1);
    // cout << x << ' ' << y << ' ' << y1 << endl;
    // tm_end(shared, tx);
    // int z = *(int *)shared;
    // cout << "Z: " << z << endl;

    // tx_t tx2 = tm_begin(shared, false);
    // int z1 = 0;
    // tm_read(shared, tx2, (void*)(static_cast<char*>(shared) + 40), sizeof(int), &z1);
    // cout << z1 << endl;
    // tm_end(shared, tx2);
    tm_destroy(shared);

    return 0;
}