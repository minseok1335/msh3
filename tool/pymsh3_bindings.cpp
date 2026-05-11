#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "msh3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <mutex>
#include <vector>
#include <thread>
#include <chrono>
#include <string>
#include <atomic>
#include <condition_variable>

namespace py = pybind11;

// For H3Client

typedef struct CLIENT_REQ_CTX {
    std::atomic<bool> RequestDone{false};
    size_t TotalReceived = 0;
    std::vector<uint8_t> RespBuf;
    uint32_t StatusCode = 0;
    uint64_t StartNs = 0;
    uint64_t FirstByteNs = 0;
    uint64_t DoneNs = 0;
    int SawFirstByte = 0;

    std::mutex Mutex;
    std::condition_variable Cv;
} CLIENT_REQ_CTX;

typedef struct CLIENT_CTX {
    std::atomic<bool> Connected{false};
    std::atomic<bool> ConnDone{false};
    std::mutex Mutex;
    std::condition_variable Cv;
} CLIENT_CTX;

static uint64_t NowNs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static MSH3_STATUS MSH3_CALL
ClientRequestCallback(
    MSH3_REQUEST* Request,
    void* Context,
    MSH3_REQUEST_EVENT* Event)
{
    CLIENT_REQ_CTX* Ctx = (CLIENT_REQ_CTX*)Context;

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

        Ctx->RespBuf.insert(
            Ctx->RespBuf.end(),
            data,
            data + len
        );
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
        {
            std::lock_guard<std::mutex> lock(Ctx->Mutex);
            Ctx->RequestDone.store(true);
        }
        Ctx->Cv.notify_all();
        break;

    default:
        break;
    }

    return MSH3_STATUS_SUCCESS;
}

static MSH3_STATUS MSH3_CALL
ClientConnectionCallback(
    MSH3_CONNECTION* Connection,
    void* Context,
    MSH3_CONNECTION_EVENT* Event)
{
    CLIENT_CTX* Ctx = (CLIENT_CTX*)Context;

    switch (Event->Type) {

    case MSH3_CONNECTION_EVENT_CONNECTED:
        {
            std::lock_guard<std::mutex> lock(Ctx->Mutex);
            Ctx->ConnDone.store(false);
            Ctx->Connected.store(true);
        }
        Ctx->Cv.notify_all();
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
        {
            std::lock_guard<std::mutex> lock(Ctx->Mutex);
            Ctx->Connected.store(false);
            Ctx->ConnDone.store(true);
        }
        Ctx->Cv.notify_all();
        printf("[conn] shutdown complete\n");        
        break;

    default:
        break;
    }

    (void)Connection;
    return MSH3_STATUS_SUCCESS;
}

class H3Client {
public:
    H3Client(const std::string& server_ip, uint16_t port, bool verify_cert)
        : server_ip_(server_ip),
          port_(port),
          verify_cert_(verify_cert) {}

    ~H3Client() {
        if (conn_) {
            MsH3ConnectionClose(conn_);
            conn_ = nullptr;
        }
        if (config_) {
            MsH3ConfigurationClose(config_);
            config_ = nullptr;
        }
        if (api_) {
            MsH3ApiClose(api_);
            api_ = nullptr;
        }
    }

    bool start() {
        // 여기에 msh3_client.cpp의 초기화 로직:
        // MsH3ApiOpen
        // MsH3ConfigurationOpen
        // MsH3ConfigurationLoadCredential
        // MsH3ConnectionOpen
        // MsH3ConnectionStart
        if (conn_) {
            printf("Connection is already started\n");
            return true;
        }

        this->api_ = MsH3ApiOpen();
        if (!this->api_) {
            printf("Failed to initialize MSH3 API\n");
            return false;
        }

        memset(&this->settings_, 0, sizeof(this->settings_));
        this->settings_.IsSet.IdleTimeoutMs = 1;
        this->settings_.IdleTimeoutMs = 30000;

        this->config_ = MsH3ConfigurationOpen(this->api_, &this->settings_, sizeof(this->settings_));
        if (!this->config_) {
            printf("Failed to initialize MSH3 Configuration\n");
            MsH3ApiClose(this->api_);
            return false;
        }
        memset(&this->cred_config_, 0, sizeof(this->cred_config_));
        this->cred_config_.Type = MSH3_CREDENTIAL_TYPE_NONE;
        this->cred_config_.Flags = MSH3_CREDENTIAL_FLAG_CLIENT |
                                   MSH3_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        MSH3_STATUS st = MsH3ConfigurationLoadCredential(this->config_, &this->cred_config_);
        if (MSH3_FAILED(st)) {
            printf("Failed to load credentials, status=0x%x\n", st);
            MsH3ConfigurationClose(this->config_);
            MsH3ApiClose(this->api_);
            return false;
        }

        memset(&this->server_addr_, 0, sizeof(this->server_addr_));
        this->server_addr_.Ipv4.sin_family = AF_INET;
        this->server_addr_.Ipv4.sin_addr.s_addr = inet_addr(this->server_ip_.c_str());
        MSH3_SET_PORT(&this->server_addr_, this->port_);

        this->conn_ = MsH3ConnectionOpen(this->api_, &ClientConnectionCallback, &this->conn_ctx_);
        if (!this->conn_) {
            printf("Failed to create connection\n");
            MsH3ConfigurationClose(this->config_);
            MsH3ApiClose(this->api_);
            return false;
        }

        st = MsH3ConnectionStart(this->conn_, this->config_, this->server_ip_.c_str(), &this->server_addr_);
        if (MSH3_FAILED(st)) {
            printf("Failed to start connection, status=0x%x\n", st);
            MsH3ConnectionClose(this->conn_);
            MsH3ConfigurationClose(this->config_);
            MsH3ApiClose(this->api_);
            return false;
        }

        {
            std::unique_lock<std::mutex> lock(this->conn_ctx_.Mutex);
            bool ok = this->conn_ctx_.Cv.wait_for(
                lock,
                std::chrono::seconds(5),
                [&]() {
                    return this->conn_ctx_.Connected.load() ||
                        this->conn_ctx_.ConnDone.load();
                }
            );

            if (!ok || !this->conn_ctx_.Connected.load()) {
                fprintf(stderr, "Connection did not complete\n");
                return false;
            }
        }

        return true;
    }

    py::dict get(const std::string& path) {
        // 여기에 msh3_client.cpp의 main() 내부 로직을 함수화해서 넣기
        // RespBuf/RespLen/StatusCode/TTFB/total_ms를 채움

        if (!conn_ || !conn_ctx_.Connected.load()) {
            throw std::runtime_error("H3Client is not connected");
        }

        CLIENT_REQ_CTX req_ctx;

        MSH3_REQUEST* request = nullptr;
        {
            std::lock_guard<std::mutex> lock(request_open_mutex_);
            request = MsH3RequestOpen(this->conn_, &ClientRequestCallback, &req_ctx, MSH3_REQUEST_FLAG_NONE);
        }
        if (!request) {
            fprintf(stderr, "MsH3RequestOpen failed\n");
            return py::dict();
        }
        char authority[128];
        snprintf(authority, sizeof(authority), "%s:%u", server_ip_.c_str(), (unsigned)port_);
        
        MsH3RequestSetReceiveEnabled(request, true);
        MSH3_HEADER hdrs[] = {
            { ":method", 7, "GET", 3 },
            {":scheme", 7, "https", 5},
            { ":authority", 10, authority, (uint32_t)strlen(authority) },
            { ":path", 5, path.c_str(), (uint32_t)path.size() }
        };
        req_ctx.StartNs = NowNs();

        bool ok = MsH3RequestSend(
            request,
            MSH3_REQUEST_SEND_FLAG_FIN,
            hdrs,
            sizeof(hdrs) / sizeof(hdrs[0]),
            nullptr,
            0,
            nullptr
        );

        if (!ok) {
            MsH3RequestClose(request);
            throw std::runtime_error("MsH3RequestSend failed");
        }

        {
            py::gil_scoped_release release;
            std::unique_lock<std::mutex> lock(req_ctx.Mutex);
            req_ctx.Cv.wait(lock, [&]() {return req_ctx.RequestDone.load();});
        }

        MsH3RequestClose(request);

        py::dict result;
        result["status_code"] = req_ctx.StatusCode;
        
        result["body"] = py::bytes(
            reinterpret_cast<const char*>(req_ctx.RespBuf.data()),
            req_ctx.RespBuf.size()
        );
        
        result["bytes"] = req_ctx.RespBuf.size();

        double total_ms = req_ctx.DoneNs ? (double)(req_ctx.DoneNs - req_ctx.StartNs) / 1e6 : -1.0;
        double ttfb_ms = req_ctx.SawFirstByte ? (double)(req_ctx.FirstByteNs - req_ctx.StartNs) / 1e6 : -1.0;
        result["ttfb_ms"] = ttfb_ms;
        result["total_ms"] = total_ms;

        req_ctx.RespBuf.clear();

        return result;
    }

private:
    std::string server_ip_;
    uint16_t port_;
    bool verify_cert_;

    uint32_t status_code_ = 0;
    CLIENT_CTX conn_ctx_;
    std::vector<uint8_t> resp_buf_;

    MSH3_API* api_ = nullptr;
    MSH3_SETTINGS settings_;
    MSH3_CONFIGURATION* config_ = nullptr;
    MSH3_CREDENTIAL_CONFIG cred_config_;
    MSH3_CONNECTION* conn_ = nullptr;
    MSH3_ADDR server_addr_;

    double ttfb_ms_ = -1.0;
    double total_ms_ = -1.0;

    std::mutex request_open_mutex_;
};


// For H3FileServer
typedef struct SERVER_REQ_CTX {
    std::string docroot;
    char method[16] = {};
    char path[2048] = {};
    int saw_method = 0;
    int saw_path = 0;
} SERVER_REQ_CTX;

typedef struct SERVER_CTX {
    std::string docroot;
    MSH3_CONFIGURATION* config = nullptr;
} SERVER_CTX;

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

static bool ReadEntireFile(const char* fs_path, std::vector<uint8_t>& out) {
    
    out.clear();

    FILE* f = fopen(fs_path, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return false;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }

    out.resize(static_cast<size_t>(sz));

    if (sz > 0) {
        size_t rd = fread(out.data(), 1, out.size(), f);
        if (rd != out.size()) {
            fclose(f);
            out.clear();
            return false;
        }
    }

    fclose(f);
    return true;
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
    auto file_data = new std::vector<uint8_t>();

    if (!ReadEntireFile(fs_path, *file_data)) {
        delete file_data;
        SendPlain(Request, 404, "Not Found\n");
        return;
    }

    const char* ctype = GuessContentType(fs_path);

    char clen[32];
    snprintf(clen, sizeof(clen), "%zu", file_data->size());

    MSH3_HEADER hdrs[] = {
        { ":status", 7, "200", 3 },
        { "content-type", 12, ctype, static_cast<uint32_t>(strlen(ctype)) },
        { "content-length", 14, clen, static_cast<uint32_t>(strlen(clen)) }
    };

    MsH3RequestSend(
        Request,
        MSH3_REQUEST_SEND_FLAG_FIN,
        hdrs,
        sizeof(hdrs) / sizeof(hdrs[0]),
        file_data->data(),
        static_cast<uint32_t>(file_data->size()),
        file_data
    );
}

static MSH3_STATUS MSH3_CALL
ServerRequestCallback(
    MSH3_REQUEST* Request,
    void* Context,
    MSH3_REQUEST_EVENT* Event
    )
{
    SERVER_REQ_CTX* ctx = (SERVER_REQ_CTX*)Context;

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
        snprintf(fs_path, sizeof(fs_path), "%s/%s", ctx->docroot.c_str(), rel);

        SendFileResponse(Request, fs_path);
        return MSH3_STATUS_SUCCESS;
    }

    case MSH3_REQUEST_EVENT_SEND_COMPLETE:
        if (Event->SEND_COMPLETE.ClientContext) {
            delete static_cast<std::vector<uint8_t>*>(
                Event->SEND_COMPLETE.ClientContext
            );
        }
        return MSH3_STATUS_SUCCESS;

    case MSH3_REQUEST_EVENT_SHUTDOWN_COMPLETE:
        delete ctx;
        return MSH3_STATUS_SUCCESS;

    default:
        return MSH3_STATUS_SUCCESS;
    }
}

static MSH3_STATUS MSH3_CALL
ServerConnectionCallback(
    MSH3_CONNECTION* Connection,
    void* Context,
    MSH3_CONNECTION_EVENT* Event
    )
{
    (void)Connection;
    SERVER_CTX* server_ctx = (SERVER_CTX*)Context;

    switch (Event->Type) {

    case MSH3_CONNECTION_EVENT_CONNECTED:
        printf("[conn] connected\n");
        return MSH3_STATUS_SUCCESS;

    case MSH3_CONNECTION_EVENT_NEW_REQUEST: {
        MSH3_REQUEST* request = Event->NEW_REQUEST.Request;

        SERVER_REQ_CTX* ctx = new SERVER_REQ_CTX();
        if (!ctx) {
            fprintf(stderr, "[conn] REQ_CTX alloc failed\n");
            MsH3RequestClose(request);
            return MSH3_STATUS_SUCCESS;
        }

        ctx->docroot = server_ctx->docroot;

        MsH3RequestSetCallbackHandler(request, ServerRequestCallback, ctx);
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
    SERVER_CTX* server_ctx = (SERVER_CTX*)Context;
    MSH3_CONFIGURATION* config = server_ctx->config;

    switch (Event->Type) {

    case MSH3_LISTENER_EVENT_NEW_CONNECTION: {
        printf("[listener] new connection from %.*s\n",
               (int)Event->NEW_CONNECTION.ServerNameLength,
               Event->NEW_CONNECTION.ServerName);

        MsH3ConnectionSetCallbackHandler(
            Event->NEW_CONNECTION.Connection,
            ServerConnectionCallback,
            server_ctx);

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


class H3FileServer {
public:
    H3FileServer(
        uint16_t port,
        const std::string& docroot,
        const std::string& cert_file,
        const std::string& key_file
    )
        : port_(port),
          cert_file_(cert_file),
          key_file_(key_file) {
                server_ctx_.docroot = docroot;
          }

    ~H3FileServer() {
        stop();
    }

    void start() {
        // 여기에 msh3_server.cpp의 초기화 로직:
        // MsH3ApiOpen
        // MsH3ConfigurationOpen
        // MsH3ConfigurationLoadCredential
        // MsH3ListenerOpen
        if (running_) {
            printf("Server is already running\n");
            return;
        }
        
        this->api_ = MsH3ApiOpen();
        if (!this->api_) {
            printf("Failed to initialize MSH3 API\n");
            return;
        }

        memset(&this->settings, 0, sizeof(this->settings));
        this->settings.IsSet.IdleTimeoutMs = 1;
        this->settings.IdleTimeoutMs = 30000;

        this->server_ctx_.config = MsH3ConfigurationOpen(this->api_, &this->settings, sizeof(this->settings));
        if (!this->server_ctx_.config) {
            printf("Failed to initialize MSH3 Configuration\n");
            MsH3ApiClose(this->api_);
            return;
        }

        this->certFile.CertificateFile = this->cert_file_.c_str();
        this->certFile.PrivateKeyFile = this->key_file_.c_str();

        memset(&this->credConfig, 0, sizeof(this->credConfig));
        this->credConfig.Type = MSH3_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        this->credConfig.Flags = MSH3_CREDENTIAL_FLAG_NONE;
        this->credConfig.CertificateFile = &this->certFile;

        MSH3_STATUS st = MsH3ConfigurationLoadCredential(this->server_ctx_.config, &this->credConfig);
        if (MSH3_FAILED(st)) {
            printf("Failed to load credentials, status=0x%x\n", st);
            MsH3ConfigurationClose(this->server_ctx_.config);
            MsH3ApiClose(this->api_);
            return;
        }

        memset(&this->localAddr, 0, sizeof(this->localAddr));
        this->localAddr.Ipv4.sin_family = AF_INET;
        this->localAddr.Ipv4.sin_addr.s_addr = INADDR_ANY;
        MSH3_SET_PORT(&this->localAddr, this->port_);

        this->listener = MsH3ListenerOpen(this->api_, &this->localAddr, ListenerCallback, &this->server_ctx_);
        if (!this->listener) {
            printf("Failed to create listener\n");
            MsH3ConfigurationClose(this->server_ctx_.config);
            MsH3ApiClose(this->api_);
            return;
        }
        printf("HTTP/3 file server listening on port %d with docroot '%s'\n", this->port_, this->server_ctx_.docroot.c_str());
        running_ = true;
    }

    void stop() {
        // MsH3ListenerClose
        // MsH3ConfigurationClose
        // MsH3ApiClose
        
        if (!running_) {
            printf("Server is not running\n");
            return;
        }

        if (this->listener) {
            MsH3ListenerClose(this->listener);
            this->listener = nullptr;
        }

        if (this->server_ctx_.config) {
            MsH3ConfigurationClose(this->server_ctx_.config);
            this->server_ctx_.config = nullptr;
        }

        if (this->api_) {
            MsH3ApiClose(this->api_);
            this->api_ = nullptr;
        }
        memset(&this->localAddr, 0, sizeof(this->localAddr));
        running_ = false;
    }

private:
    uint16_t port_;
    std::string cert_file_;
    std::string key_file_;
    bool running_ = false;

    // MSH3 Members
    MSH3_API* api_ = nullptr;
    MSH3_SETTINGS settings;
    MSH3_CERTIFICATE_FILE certFile;
    MSH3_CREDENTIAL_CONFIG credConfig;
    MSH3_ADDR localAddr;
    MSH3_LISTENER* listener = nullptr;

    SERVER_CTX server_ctx_;
};

PYBIND11_MODULE(pymsh3, m) {
    py::class_<H3Client>(m, "H3Client")
        .def(py::init<std::string, uint16_t, bool>())
        .def("start", &H3Client::start)
        .def("get", &H3Client::get);

    py::class_<H3FileServer>(m, "H3FileServer")
        .def(py::init<uint16_t, std::string, std::string, std::string>())
        .def("start", &H3FileServer::start)
        .def("stop", &H3FileServer::stop);
}