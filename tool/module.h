#ifndef MODULE_H
#define MODULE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "msh3.h"

typedef struct REQ_CTX {
    volatile int RequestDone;
    size_t TotalReceived;
    uint8_t* RespBuf;
    size_t RespLen;
    uint32_t StatusCode;
    uint64_t StartNs;
    uint64_t FirstByteNs;
    uint64_t DoneNs;
    int SawFirstByte;
} REQ_CTX;

typedef struct CLIENT_CTX {
    volatile int ConnDone;
} CLIENT_CTX;

static uint64_t NowNs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}


#endif // MODULE_H