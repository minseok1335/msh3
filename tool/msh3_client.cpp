// msh3_file_client.c
// Usage:
//   ./msh3fileclient <server_ip> <port> <path>
// Example:
//   ./msh3fileclient 127.0.0.1 4123 /Bible_4.2M.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
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

static MSH3_STATUS MSH3_CALL
RequestCallback(
    MSH3_REQUEST* Request,
    void* Context,
    MSH3_REQUEST_EVENT* Event)
{
    REQ_CTX* Ctx = (REQ_CTX*)Context;

    switch (Event->Type) {

    case MSH3_REQUEST_EVENT_HEADER_RECEIVED: {
        const MSH3_HEADER* h = Event->HEADER_RECEIVED.Header;
        printf("[req] header: %.*s: %.*s\n",
               (int)h->NameLength,  h->Name,
               (int)h->ValueLength, h->Value);

        if (h->NameLength == 7 && memcmp(h->Name, ":status", 7) == 0) {
            char tmp[8] = {0};
            uint32_t n = h->ValueLength < sizeof(tmp) - 1 ? h->ValueLength : (uint32_t)(sizeof(tmp) - 1);
            memcpy(tmp, h->Value, n);
            Ctx->StatusCode = (uint32_t)atoi(tmp);
        }
        break;
    }

    case MSH3_REQUEST_EVENT_DATA_RECEIVED: {
        size_t len = Event->DATA_RECEIVED.Length;
        const uint8_t* data = Event->DATA_RECEIVED.Data;

        if (!Ctx->SawFirstByte) {
            Ctx->SawFirstByte = 1;
            Ctx->FirstByteNs = NowNs();
        }

        uint8_t* newBuf = (uint8_t*)realloc(Ctx->RespBuf, Ctx->RespLen + len);
        if (!newBuf) {
            fprintf(stderr, "[req] realloc failed\n");
            return MSH3_STATUS_SUCCESS;
        }

        memcpy(newBuf + Ctx->RespLen, data, len);
        Ctx->RespBuf = newBuf;
        Ctx->RespLen += len;
        Ctx->TotalReceived += len;
        break;
    }

    case MSH3_REQUEST_EVENT_PEER_SEND_SHUTDOWN:
        printf("[req] peer finished sending, total=%zu bytes\n", Ctx->TotalReceived);
        Ctx->DoneNs = NowNs();
        MsH3RequestCompleteReceive(Request, (uint32_t)Ctx->TotalReceived);
        break;

    case MSH3_REQUEST_EVENT_SEND_COMPLETE:
        printf("[req] send complete\n");
        if (!Event->SEND_COMPLETE.Canceled &&
            Event->SEND_COMPLETE.ClientContext) {
            free(Event->SEND_COMPLETE.ClientContext);
        }
        break;

    case MSH3_REQUEST_EVENT_SHUTDOWN_COMPLETE:
        printf("[req] shutdown complete\n");
        MsH3RequestClose(Request);
        Ctx->RequestDone = 1;
        break;

    default:
        break;
    }

    return MSH3_STATUS_SUCCESS;
}

static MSH3_STATUS MSH3_CALL
ConnectionCallback(
    MSH3_CONNECTION* Connection,
    void* Context,
    MSH3_CONNECTION_EVENT* Event)
{
    CLIENT_CTX* Ctx = (CLIENT_CTX*)Context;

    switch (Event->Type) {

    case MSH3_CONNECTION_EVENT_CONNECTED:
        printf("[conn] connected\n");
        break;

    case MSH3_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn] shutdown by transport, status=0x%x, error=0x%llx\n",
               Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status,
               (unsigned long long)Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        break;

    case MSH3_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn] shutdown by peer, error=0x%llx\n",
               (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;

    case MSH3_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn] shutdown complete\n");
        Ctx->ConnDone = 1;
        break;

    default:
        break;
    }

    (void)Connection;
    return MSH3_STATUS_SUCCESS;
}

int main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <path>\n", argv[0]);
        fprintf(stderr, "Example: %s 127.0.0.1 4123 /Bible_4.2M.txt\n", argv[0]);
        return 1;
    }

    const char* server_ip = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    const char* path = argv[3];

    CLIENT_CTX ConnCtx;
    memset(&ConnCtx, 0, sizeof(ConnCtx));

    REQ_CTX ReqCtx;
    memset(&ReqCtx, 0, sizeof(ReqCtx));

    MSH3_API* api = MsH3ApiOpen();
    if (!api) {
        fprintf(stderr, "MsH3ApiOpen failed\n");
        return 1;
    }

    MSH3_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IsSet.IdleTimeoutMs = 1;
    settings.IdleTimeoutMs = 30000;

    MSH3_CONFIGURATION* config =
        MsH3ConfigurationOpen(api, &settings, sizeof(settings));
    if (!config) {
        fprintf(stderr, "MsH3ConfigurationOpen failed\n");
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_CREDENTIAL_CONFIG cred;
    memset(&cred, 0, sizeof(cred));
    cred.Type = MSH3_CREDENTIAL_TYPE_NONE;
    cred.Flags = MSH3_CREDENTIAL_FLAG_CLIENT |
                 MSH3_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (MSH3_FAILED(MsH3ConfigurationLoadCredential(config, &cred))) {
        fprintf(stderr, "MsH3ConfigurationLoadCredential failed\n");
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_CONNECTION* conn =
        MsH3ConnectionOpen(api, &ConnectionCallback, &ConnCtx);
    if (!conn) {
        fprintf(stderr, "MsH3ConnectionOpen failed\n");
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_ADDR addr;
    memset(&addr, 0, sizeof(addr));
    addr.Ipv4.sin_family = AF_INET;
    addr.Ipv4.sin_addr.s_addr = inet_addr(server_ip);
    MSH3_SET_PORT(&addr, port);

    if (MSH3_FAILED(MsH3ConnectionStart(conn, config, server_ip, &addr))) {
        fprintf(stderr, "MsH3ConnectionStart failed\n");
        MsH3ConnectionClose(conn);
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_REQUEST* Req =
        MsH3RequestOpen(conn, &RequestCallback, &ReqCtx, MSH3_REQUEST_FLAG_NONE);
    if (!Req) {
        fprintf(stderr, "MsH3RequestOpen failed\n");
        MsH3ConnectionClose(conn);
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    MsH3RequestSetReceiveEnabled(Req, true);

    char authority[128];
    snprintf(authority, sizeof(authority), "%s:%u", server_ip, (unsigned)port);

    MSH3_HEADER headers[4];
    headers[0] = (MSH3_HEADER){":method", 7, "GET", 3};
    headers[1] = (MSH3_HEADER){":scheme", 7, "https", 5};
    headers[2] = (MSH3_HEADER){":authority", 10, authority, (uint32_t)strlen(authority)};
    headers[3] = (MSH3_HEADER){":path", 5, path, (uint32_t)strlen(path)};

    ReqCtx.StartNs = NowNs();

    MsH3RequestSend(
        Req,
        MSH3_REQUEST_SEND_FLAG_FIN,
        headers, 4,
        NULL, 0,
        NULL);

    while (!ReqCtx.RequestDone) {
        usleep(1000);
    }

    double total_ms = ReqCtx.DoneNs ? (double)(ReqCtx.DoneNs - ReqCtx.StartNs) / 1e6 : -1.0;
    double ttfb_ms = ReqCtx.SawFirstByte ? (double)(ReqCtx.FirstByteNs - ReqCtx.StartNs) / 1e6 : -1.0;

    printf("[result] status=%u bytes=%zu TTFB=%.2f ms total=%.2f ms\n",
           ReqCtx.StatusCode, ReqCtx.TotalReceived, ttfb_ms, total_ms);

    if (ReqCtx.RespBuf && ReqCtx.RespLen > 0) {
        printf("\n===== Full Response Body =====\n");
        fwrite(ReqCtx.RespBuf, 1, ReqCtx.RespLen, stdout);
        printf("\n==============================\n");
    }

    free(ReqCtx.RespBuf);
    MsH3ConnectionClose(conn);
    MsH3ConfigurationClose(config);
    MsH3ApiClose(api);
    return 0;
}