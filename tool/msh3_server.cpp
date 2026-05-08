// msh3_server.cpp
#include "msh3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>

static const char* g_docroot = ".";

typedef struct REQ_CTX {
    char method[16];
    char path[2048];
    int saw_method;
    int saw_path;
} REQ_CTX;

static const char* GuessContentType(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return "application/octet-stream";
    ext++;

    if (!strcasecmp(ext, "html") || !strcasecmp(ext, "htm")) return "text/html";
    if (!strcasecmp(ext, "txt")) return "text/plain";
    if (!strcasecmp(ext, "json")) return "application/json";
    if (!strcasecmp(ext, "jpg") || !strcasecmp(ext, "jpeg")) return "image/jpeg";
    if (!strcasecmp(ext, "png")) return "image/png";
    if (!strcasecmp(ext, "css")) return "text/css";
    if (!strcasecmp(ext, "js")) return "application/javascript";
    return "application/octet-stream";
}

static int SanitizePath(const char* in, char* out, size_t cap) {
    if (!in || !out || cap == 0) return 0;
    if (strstr(in, "..")) return 0;

    while (*in == '/') in++;
    if (*in == '\0') in = "index.html";

    size_t n = strlen(in);
    if (n + 1 > cap) return 0;

    memcpy(out, in, n + 1);
    return 1;
}

static int ReadEntireFile(const char* fs_path, uint8_t** data, size_t* len) {
    *data = NULL;
    *len = 0;

    FILE* f = fopen(fs_path, "rb");
    if (!f) return 0;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }

    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return 0;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return 0;
    }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) {
        free(buf);
        return 0;
    }

    *data = buf;
    *len = (size_t)sz;
    return 1;
}

static void SendPlain(MSH3_REQUEST* Request, int status_code, const char* msg) {
    char status[4];
    snprintf(status, sizeof(status), "%d", status_code);

    MSH3_HEADER hdrs[] = {
        { ":status", 7, status, (uint32_t)strlen(status) },
        { "content-type", 12, "text/plain", 10 }
    };

    MsH3RequestSend(
        Request,
        MSH3_REQUEST_SEND_FLAG_FIN,
        hdrs,
        sizeof(hdrs) / sizeof(hdrs[0]),
        msg,
        (uint32_t)strlen(msg),
        NULL);
}

static void SendFileResponse(MSH3_REQUEST* Request, const char* fs_path) {
    uint8_t* file_data = NULL;
    size_t file_len = 0;

    if (!ReadEntireFile(fs_path, &file_data, &file_len)) {
        SendPlain(Request, 404, "Not Found\n");
        return;
    }

    const char* ctype = GuessContentType(fs_path);
    char clen[32];
    snprintf(clen, sizeof(clen), "%zu", file_len);

    MSH3_HEADER hdrs[] = {
        { ":status", 7, "200", 3 },
        { "content-type", 12, ctype, (uint32_t)strlen(ctype) },
        { "content-length", 14, clen, (uint32_t)strlen(clen) }
    };

    MsH3RequestSend(
        Request,
        MSH3_REQUEST_SEND_FLAG_FIN,
        hdrs,
        sizeof(hdrs) / sizeof(hdrs[0]),
        file_data,
        (uint32_t)file_len,
        file_data);
}

static MSH3_STATUS MSH3_CALL
RequestCallback(
    MSH3_REQUEST* Request,
    void* Context,
    MSH3_REQUEST_EVENT* Event
    )
{
    REQ_CTX* ctx = (REQ_CTX*)Context;

    switch (Event->Type) {

    case MSH3_REQUEST_EVENT_HEADER_RECEIVED: {
        const MSH3_HEADER* h = Event->HEADER_RECEIVED.Header;

        if (h->NameLength == 7 && memcmp(h->Name, ":method", 7) == 0) {
            size_t n = h->ValueLength < sizeof(ctx->method) - 1 ? h->ValueLength : sizeof(ctx->method) - 1;
            memcpy(ctx->method, h->Value, n);
            ctx->method[n] = 0;
            ctx->saw_method = 1;
        } else if (h->NameLength == 5 && memcmp(h->Name, ":path", 5) == 0) {
            size_t n = h->ValueLength < sizeof(ctx->path) - 1 ? h->ValueLength : sizeof(ctx->path) - 1;
            memcpy(ctx->path, h->Value, n);
            ctx->path[n] = 0;
            ctx->saw_path = 1;
        }
        return MSH3_STATUS_SUCCESS;
    }

    case MSH3_REQUEST_EVENT_DATA_RECEIVED:
        MsH3RequestCompleteReceive(Request, Event->DATA_RECEIVED.Length);
        return MSH3_STATUS_SUCCESS;

    case MSH3_REQUEST_EVENT_PEER_SEND_SHUTDOWN: {
        if (!ctx->saw_method || !ctx->saw_path) {
            SendPlain(Request, 400, "Bad Request\n");
            return MSH3_STATUS_SUCCESS;
        }

        if (strcmp(ctx->method, "GET") != 0) {
            SendPlain(Request, 405, "Method Not Allowed\n");
            return MSH3_STATUS_SUCCESS;
        }

        char rel[2048];
        if (!SanitizePath(ctx->path, rel, sizeof(rel))) {
            SendPlain(Request, 400, "Bad Request\n");
            return MSH3_STATUS_SUCCESS;
        }

        char fs_path[4096];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", g_docroot, rel);

        SendFileResponse(Request, fs_path);
        return MSH3_STATUS_SUCCESS;
    }

    case MSH3_REQUEST_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.ClientContext) {
            free(Event->SEND_COMPLETE.ClientContext);
        }
        return MSH3_STATUS_SUCCESS;

    case MSH3_REQUEST_EVENT_SHUTDOWN_COMPLETE:
        free(ctx);
        return MSH3_STATUS_SUCCESS;

    default:
        return MSH3_STATUS_SUCCESS;
    }
}

static MSH3_STATUS MSH3_CALL
ConnectionCallback(
    MSH3_CONNECTION* Connection,
    void* Context,
    MSH3_CONNECTION_EVENT* Event
    )
{
    (void)Connection;
    (void)Context;

    switch (Event->Type) {

    case MSH3_CONNECTION_EVENT_CONNECTED:
        printf("[conn] connected\n");
        return MSH3_STATUS_SUCCESS;

    case MSH3_CONNECTION_EVENT_NEW_REQUEST: {
        MSH3_REQUEST* request = Event->NEW_REQUEST.Request;

        REQ_CTX* ctx = (REQ_CTX*)calloc(1, sizeof(REQ_CTX));
        if (!ctx) {
            fprintf(stderr, "[conn] REQ_CTX alloc failed\n");
            MsH3RequestClose(request);
            return MSH3_STATUS_SUCCESS;
        }

        MsH3RequestSetCallbackHandler(request, RequestCallback, ctx);
        MsH3RequestSetReceiveEnabled(request, true);
        return MSH3_STATUS_SUCCESS;
    }

    case MSH3_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        printf("[conn] shutdown by transport, status=0x%x, error=0x%llx\n",
               Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status,
               (unsigned long long)Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        return MSH3_STATUS_SUCCESS;

    case MSH3_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("[conn] shutdown by peer, error=0x%llx\n",
               (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        return MSH3_STATUS_SUCCESS;

    case MSH3_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("[conn] shutdown complete\n");
        return MSH3_STATUS_SUCCESS;

    default:
        return MSH3_STATUS_SUCCESS;
    }
}

static MSH3_STATUS MSH3_CALL
ListenerCallback(
    MSH3_LISTENER* Listener,
    void* Context,
    MSH3_LISTENER_EVENT* Event
    )
{
    (void)Listener;
    MSH3_CONFIGURATION* config = (MSH3_CONFIGURATION*)Context;

    switch (Event->Type) {

    case MSH3_LISTENER_EVENT_NEW_CONNECTION: {
        printf("[listener] new connection from %.*s\n",
               (int)Event->NEW_CONNECTION.ServerNameLength,
               Event->NEW_CONNECTION.ServerName);

        MsH3ConnectionSetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            ConnectionCallback,
            NULL);

        MSH3_STATUS st = MsH3ConnectionSetConfiguration(
            Event->NEW_CONNECTION.Connection,
            config);

        if (MSH3_FAILED(st)) {
            printf("[listener] failed to configure connection, status=0x%x\n", st);
            MsH3ConnectionClose(Event->NEW_CONNECTION.Connection);
        }
        return MSH3_STATUS_SUCCESS;
    }

    case MSH3_LISTENER_EVENT_SHUTDOWN_COMPLETE:
        printf("[listener] shutdown complete\n");
        return MSH3_STATUS_SUCCESS;

    default:
        return MSH3_STATUS_SUCCESS;
    }
}

int main(int argc, char** argv) {
    uint16_t port = (argc > 1) ? (uint16_t)atoi(argv[1]) : 4123;
    if (argc > 2) g_docroot = argv[2];

    MSH3_API* api = MsH3ApiOpen();
    if (!api) {
        printf("Failed to initialize MSH3 API\n");
        return 1;
    }

    MSH3_SETTINGS settings;
    memset(&settings, 0, sizeof(settings));
    settings.IsSet.IdleTimeoutMs = 1;
    settings.IdleTimeoutMs = 30000;

    MSH3_CONFIGURATION* config =
        MsH3ConfigurationOpen(api, &settings, sizeof(settings));
    if (!config) {
        printf("Failed to create configuration\n");
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_CERTIFICATE_FILE certFile = {
        .PrivateKeyFile = "server.key",
        .CertificateFile = "server.crt"
    };

    MSH3_CREDENTIAL_CONFIG credConfig;
    memset(&credConfig, 0, sizeof(credConfig));
    credConfig.Type = MSH3_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    credConfig.Flags = MSH3_CREDENTIAL_FLAG_NONE;
    credConfig.CertificateFile = &certFile;

    MSH3_STATUS status = MsH3ConfigurationLoadCredential(config, &credConfig);
    if (MSH3_FAILED(status)) {
        printf("Failed to load credentials, status=0x%x\n", status);
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    MSH3_ADDR localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.Ipv4.sin_family = AF_INET;
    localAddr.Ipv4.sin_addr.s_addr = INADDR_ANY;
    MSH3_SET_PORT(&localAddr, port);

    MSH3_LISTENER* listener =
        MsH3ListenerOpen(api, &localAddr, ListenerCallback, config);
    if (!listener) {
        printf("Failed to create listener\n");
        MsH3ConfigurationClose(config);
        MsH3ApiClose(api);
        return 1;
    }

    printf("HTTP/3 file server listening on port %u (docroot=%s)\n", port, g_docroot);
    printf("Example: /Bible_4.2M.txt -> %s/Bible_4.2M.txt\n", g_docroot);
    printf("Press Enter to terminate...\n");
    getchar();

    MsH3ListenerClose(listener);
    MsH3ConfigurationClose(config);
    MsH3ApiClose(api);
    return 0;
}