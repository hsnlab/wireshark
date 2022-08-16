/* packet-http3.c
 * Routines for HTTP/3 dissection
 * Copyright 2019, Peter Wu <peter@lekensteyn.nl>
 * Copyright 2022, Omer Shapira <oesh@github.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * https://tools.ietf.org/html/draft-ietf-quic-http-29
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-16
 *
 * Depends on the QUIC dissector for providing a reassembled stream of data, see
 * packet-quic.c for details about supported QUIC draft versions.
 * Depends on nghttp3 for HTTP header dissection.
 * Currently supported HTTP/3 versions: h3-23 up to and including h3-29.
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/to_str.h>
#include <string.h>
#include <wsutil/pint.h>

#include <epan/conversation_table.h>
#include <epan/dissectors/packet-http.h> /* for getting status reason-phrase */


#include "packet-quic.h"

#include <epan/uat.h>
#include <epan/decode_as.h>

#ifdef HAVE_NGHTTP3
#include <nghttp3/nghttp3.h>
#endif

// Comment out to disable dissector debug
#define HTTP3_DISSECTOR_DEBUG 1

#if defined(HTTP3_DISSECTOR_DEBUG)
#define HTTP3_DISSECTOR_DPRINTF(fmt, ...) \
    printf("HTTP3 DEBUG: %s:%d (%s) " fmt "\n", __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define HTTP3_DISSECTOR_DPRINTF(fmt, ...) do{} while(0)
#endif

void proto_reg_handoff_http3(void);
void proto_register_http3(void);

static int proto_http3 = -1;
static int hf_http3_stream_type = -1;
static int hf_http3_push_id = -1;
static int hf_http3_frame_type = -1;
static int hf_http3_frame_length = -1;
static int hf_http3_frame_payload = -1;

static int hf_http3_headers = -1;
static int hf_http3_headers_count = -1;
static int hf_http3_header = -1;
static int hf_http3_header_length = -1;
static int hf_http3_header_name_length = -1;
static int hf_http3_header_name = -1;
static int hf_http3_header_value_length = -1;
static int hf_http3_header_value = -1;
static int hf_http3_header_request_full_uri = -1;

static int hf_http3_header_qpack_blocked = -1;
static int hf_http3_header_qpack_blocked_stream_rcint = -1;
static int hf_http3_header_qpack_blocked_decoder_wicnt = -1;
static int hf_http3_header_qpack_fatal = -1;

#ifdef HAVE_NGHTTP3
/* Static HTTP3 headers */
static int hf_http3_headers_status = -1;
static int hf_http3_headers_path = -1;
static int hf_http3_headers_method = -1;
static int hf_http3_headers_scheme = -1;
static int hf_http3_headers_accept = -1;
static int hf_http3_headers_accept_charset = -1;
static int hf_http3_headers_accept_encoding = -1;
static int hf_http3_headers_accept_language = -1;
static int hf_http3_headers_accept_ranges = -1;
static int hf_http3_headers_access_control_allow_origin = -1;
static int hf_http3_headers_age = -1;
static int hf_http3_headers_allow = -1;
static int hf_http3_headers_authorization = -1;
static int hf_http3_headers_authority = -1;
static int hf_http3_headers_cache_control = -1;
static int hf_http3_headers_content_disposition = -1;
static int hf_http3_headers_content_encoding = -1;
static int hf_http3_headers_content_language = -1;
static int hf_http3_headers_content_length = -1;
static int hf_http3_headers_content_location = -1;
static int hf_http3_headers_content_range = -1;
static int hf_http3_headers_content_type = -1;
static int hf_http3_headers_cookie = -1;
static int hf_http3_headers_date = -1;
static int hf_http3_headers_etag = -1;
static int hf_http3_headers_expect = -1;
static int hf_http3_headers_expires = -1;
static int hf_http3_headers_from = -1;
static int hf_http3_headers_if_match = -1;
static int hf_http3_headers_if_modified_since = -1;
static int hf_http3_headers_if_none_match = -1;
static int hf_http3_headers_if_range = -1;
static int hf_http3_headers_if_unmodified_since = -1;
static int hf_http3_headers_last_modified = -1;
static int hf_http3_headers_link = -1;
static int hf_http3_headers_location = -1;
static int hf_http3_headers_max_forwards = -1;
static int hf_http3_headers_proxy_authenticate = -1;
static int hf_http3_headers_proxy_authorization = -1;
static int hf_http3_headers_range = -1;
static int hf_http3_headers_referer = -1;
static int hf_http3_headers_refresh = -1;
static int hf_http3_headers_retry_after = -1;
static int hf_http3_headers_server = -1;
static int hf_http3_headers_set_cookie = -1;
static int hf_http3_headers_strict_transport_security = -1;
static int hf_http3_headers_user_agent = -1;
static int hf_http3_headers_vary = -1;
static int hf_http3_headers_via = -1;
static int hf_http3_headers_www_authenticate = -1;
#endif

static int hf_http3_qpack = -1;
static int hf_http3_qpack_encoder = -1;
static int hf_http3_qpack_encoder_length = -1;
static int hf_http3_qpack_encoder_icnt = -1;
static int hf_http3_qpack_encoder_icnt_inc = -1;
static int hf_http3_qpack_encoder_opcode = -1;
static int hf_http3_qpack_encoder_opcode_insert_indexed = -1;
static int hf_http3_qpack_encoder_opcode_insert_indexed_ref = -1;
static int hf_http3_qpack_encoder_opcode_insert_indexed_val = -1;
static int hf_http3_qpack_encoder_opcode_insert = -1;
static int hf_http3_qpack_encoder_opcode_insert_name = -1;
static int hf_http3_qpack_encoder_opcode_insert_val = -1;
static int hf_http3_qpack_encoder_opcode_duplicate = -1;
static int hf_http3_qpack_encoder_opcode_duplicate_val = -1;
static int hf_http3_qpack_encoder_opcode_dtable_cap = -1;
static int hf_http3_qpack_encoder_opcode_dtable_cap_val = -1;

static int hf_http3_settings = -1;
static int hf_http3_settings_identifier = -1;
static int hf_http3_settings_value = -1;
static int hf_http3_settings_qpack_max_table_capacity = -1;
static int hf_http3_settings_max_field_section_size = -1;
static int hf_http3_settings_qpack_blocked_streams = -1;
static int hf_http3_settings_extended_connect = -1;
static int hf_http3_settings_enable_webtransport = -1;
static int hf_http3_settings_h3_datagram = -1;
static int hf_http3_priority_update_element_id = -1;
static int hf_http3_priority_update_field_value = -1;
static int hf_http3_wt_session_id = -1;
static int hf_http3_wt_stream_body = -1;


static expert_field ei_http3_header_decoding_failed = EI_INIT;
static expert_field ei_http3_qpack_enc_update = EI_INIT;
static expert_field ei_http3_qpack_failed = EI_INIT;
static expert_field ei_http3_unknown_stream_type = EI_INIT;
static expert_field ei_http3_data_not_decoded = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_http3 = -1;
static gint ett_http3_settings = -1;

static gint ett_http3_headers = -1;
static gint ett_http3_headers_qpack_blocked = -1;
static gint ett_http3_qpack_update = -1;
static gint ett_http3_qpack_opcode = -1;

/* http header keys and values */
#define HTTP3_HEADER_CONTENT_ENCODING "content-encoding"
#define HTTP3_HEADER_STATUS ":status"
#define HTTP3_HEADER_STATUS_PARTIAL_CONTENT "206"
#define HTTP3_HEADER_METHOD ":method"
#define HTTP3_HEADER_METHOD_CONNECT "CONNECT"
#define HTTP3_HEADER_TRANSFER_ENCODING "transfer-encoding"
#define HTTP3_HEADER_PATH ":path"
#define HTTP3_HEADER_AUTHORITY ":authority"
#define HTTP3_HEADER_SCHEME ":scheme"
#define HTTP3_HEADER_CONTENT_TYPE "content-type"
#define HTTP3_HEADER_UNKNOWN "<unknown>"

/**
 * Unidirectional stream types.
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-6.2
 * https://tools.ietf.org/html/draft-ietf-quic-qpack-16#section-4.2
 */
enum http3_stream_type {
    HTTP3_STREAM_TYPE_CONTROL,
    HTTP3_STREAM_TYPE_PUSH,
    HTTP3_STREAM_TYPE_QPACK_ENCODER,
    HTTP3_STREAM_TYPE_QPACK_DECODER,
};

/*
 * Unidirectional stream types (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-11.2.4
 */
static const val64_string http3_stream_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Approval. */
    { 0x00, "Control Stream" },
    { 0x01, "Push Stream" },
    { 0x02, "QPACK Encoder Stream" },
    { 0x03, "QPACK Decoder Stream" },
    /* 0x40 - 0x3FFFFFFFFFFFFFFF Assigned via Specification Required policy */
    { 0, NULL }
};

/*
 * Frame type codes (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#section-11.2.1
 */
#define HTTP3_DATA                              0x0
#define HTTP3_HEADERS                           0x1
#define HTTP3_CANCEL_PUSH                       0x3
#define HTTP3_SETTINGS                          0x4
#define HTTP3_PUSH_PROMISE                      0x5
#define HTTP3_GOAWAY                            0x7
#define HTTP3_DUPLICATE_PUSH                    0xE  /* Removed in draft-26. */
#define HTTP3_MAX_PUSH_ID                       0xD
#define HTTP3_WEBTRANSPORT_STREAM               0x41
#define HTTP3_UNIDIRECTIONAL_STREAM             0x51

#define HTTP3_PRIORITY_UPDATE_REQUEST_STREAM    0xF0700
#define HTTP3_PRIORITY_UPDATE_PUSH_STREAM       0xF0701

static const val64_string http3_frame_types[] = {
    /* 0x00 - 0x3f Assigned via Standards Action or IESG Approval. */
    { HTTP3_DATA, "DATA" },
    { HTTP3_HEADERS, "HEADERS" },
    { 0x02, "Reserved" },       // "PRIORITY" in draft-22 and before
    { HTTP3_CANCEL_PUSH, "CANCEL_PUSH" },
    { HTTP3_SETTINGS, "SETTINGS" },
    { HTTP3_PUSH_PROMISE, "PUSH_PROMISE" },
    { 0x06, "Reserved" },
    { HTTP3_GOAWAY, "GOAWAY" },
    { 0x08, "Reserved" },
    { 0x09, "Reserved" },
    { HTTP3_MAX_PUSH_ID, "MAX_PUSH_ID" },
    { HTTP3_WEBTRANSPORT_STREAM, "WEBTRANSPORT_STREAM" }, // https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-03#section-4.2
    { HTTP3_UNIDIRECTIONAL_STREAM, "UNIDIRECTIONAL_STREAM" },
    { 0x0e, "Reserved" }, // "DUPLICATE_PUSH" in draft-26 and before
    { HTTP3_PRIORITY_UPDATE_REQUEST_STREAM, "PRIORITY_UPDATE" }, // draft-ietf-httpbis-priority-03
    { HTTP3_PRIORITY_UPDATE_PUSH_STREAM, "PRIORITY_UPDATE" }, // draft-ietf-httpbis-priority-03
    /* 0x40 - 0x3FFFFFFFFFFFFFFF Assigned via Specification Required policy */
    { 0, NULL }
};

/*
 * Settings parameter type codes (62-bit code space).
 * https://tools.ietf.org/html/draft-ietf-quic-http-29#name-http-2-settings-parameters
 */

#define HTTP3_QPACK_MAX_TABLE_CAPACITY          0x01
#define HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE   0x06
#define HTTP3_QPACK_BLOCKED_STREAMS             0x07
#define HTTP3_EXTENDED_CONNECT                  0x08 /* https://datatracker.ietf.org/doc/draft-ietf-httpbis-h3-websockets */
#define HTTP3_ENABLE_WEBTRANSPORT               0x2b603742 /* https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-03#section-8.2 */
#define HTTP3_H3_DATAGRAM                       0xffd277 /* https://www.ietf.org/archive/id/draft-ietf-masque-h3-datagram-08.html#section-5.1 */

static const val64_string http3_settings_vals[] = {
    { HTTP3_QPACK_MAX_TABLE_CAPACITY, "Max Table Capacity" },
    { HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE, "Max Field Section Size" },
    { HTTP3_QPACK_BLOCKED_STREAMS, "Blocked Streams" },
    { HTTP3_EXTENDED_CONNECT, "Extended CONNECT" },
    { HTTP3_ENABLE_WEBTRANSPORT, "Enable webtransport" },
    { HTTP3_H3_DATAGRAM, "H3 Datagram" },
    { 0, NULL }
};

#define NGHTTP3_QPACK_ES_OPCODE_INSERT_INDEXED 0x80
#define NGHTTP3_QPACK_ES_OPCODE_INSERT 0x40
#define NGHTTP3_QPACK_ES_OPCODE_DUPLICATE
#define NGHTTP3_QPACK_ES_OPCODE_SET_DTABLE_CAP 0x20

 typedef enum _http3_stream_dir {
    FROM_CLIENT_TO_SERVER   = 0,   /**< client to server */
    FROM_SERVER_TO_CLIENT = 1, /**< server to client */
} http3_stream_dir;

/* QPACK support (predicated by build) */
typedef void * qpack_decoder_t;
typedef void * qpack_decoder_ctx_t;

/** Max size of the QPACK dynamic table. */
#define QPACK_MAX_DTABLE_SIZE 65536

/** Upper limit on number of streams blocked on QPACK updates. */
#define QPACK_MAX_BLOCKED     512

typedef struct _http3_stream_qpack_info {
    qpack_decoder_ctx_t  context;   /**< Stream context for QPACK decoding */
    wmem_array_t        *pending;   /**< Pending QPACK bytes */
} http3_stream_qpack_info_t;

typedef struct _http3_stream_info {
    guint64                 uni_stream_type;
    guint64                 broken_from_offset;   /**< Unrecognized stream starting at offset (if non-zero). */
    http3_stream_dir        direction;
    http3_stream_qpack_info_t qpack;                /**< QPACK-related stream info */
} http3_stream_info_t;

typedef struct _http3_session_info {
    guint       id;
    qpack_decoder_t qpack_decoder[2]; /**< Decoders for outgoing/incoming QPACK streams. */
} http3_session_info_t;

http3_session_info_t* get_http3_session_info(packet_info *pinfo);

/* Decompressed header field */
typedef struct _http3_header_field_def {
    const guint8 *name;
    guint name_len;
} http3_header_field_def_t;

typedef struct _http3_header_field {
    struct {
        guint len;
        guint offset;
    } encoded;
    struct {
        const guint8 *pstr;
        guint pstr_len;
    } decoded;
    http3_header_field_def_t *def;
} http3_header_field_t;

#define HTTP3_INITIAL_PENDING_LENGTH 64

typedef struct _http3_header_data {
    struct {
        /* list of pointer to wmem_array_t, which is array of
        http3_header_t */
        wmem_array_t *headers;
    } decoded;
    struct {
        guint8          *bytes;
        guint32         len;
        guint32         pos;
    } encoded;
} http3_header_data_t;

#define HTTP3_HEADER_DATA_ENCODED_PTR(hdata)                                \
    ((hdata)->encoded.bytes == NULL ? NULL                                  \
    : ((hdata)->encoded.pos == (hdata)->encoded.len) ? NULL                 \
    : (hdata)->encoded.bytes + (hdata)->encoded.pos)

#define HTTP3_HEADER_DATA_ENCODED_LEN(hdata)                                \
    ((hdata)->encoded.bytes == NULL ? 0                                     \
    : ((hdata)->encoded.len - (hdata)->encoded.pos))

#define HTTP3_HEADER_DATA_ENCODED_ADVANCE(hdata, nread)                     \
    do {                                                                    \
        if ((hdata)) {                                                      \
            (hdata)->encoded.pos += (nread);                                \
            DISSECTOR_ASSERT(                                               \
                (hdata)->encoded.pos <= (hdata)->encoded.len);              \
        }                                                                   \
    } while(0)

/* We need to lookup underlying QUIC connections. */
static wmem_map_t *http3_conn_info_map = NULL;

static guint http3_conn_info_hash(gconstpointer key)
{
    guint8 bkey[QUIC_MAX_CID_LENGTH];
    const quic_cid_t *v = (const quic_cid_t *)key;

    memset(&bkey[0], 0, QUIC_MAX_CID_LENGTH);
    memcpy(&bkey[0], &v->cid[0], v->len);

    return wmem_strong_hash(&bkey[0], QUIC_MAX_CID_LENGTH);
}

static gboolean http3_conn_info_equal(gconstpointer lhs, gconstpointer rhs)
{
    const quic_cid_t *a = (const quic_cid_t *)lhs;
    const quic_cid_t *b = (const quic_cid_t *)rhs;
    size_t alen = a->len;
    size_t blen = b->len;

    return alen == blen && memcmp(&a->cid[0], &b->cid[0], alen) == 0;
}

#ifdef HAVE_NGHTTP3
/* Due to QPACK compression, we may get lots of relatively large
   header decoded_header_fields (e.g., 4KiB).  Allocating each of them requires lots
   of memory.  The maximum compression is achieved in QPACK by
   referencing header field stored in dynamic table by one or two
   bytes.  We reduce memory usage by caching header field in this
   wmem_map_t to reuse its memory region when we see the same header
   field next time. */
static wmem_map_t *http3_hdrcache_map = NULL;

static size_t http3_hdrcache_length(gconstpointer vv)
{
    const guint8 *v = (const guint8 *)vv;
    guint32 namelen, valuelen;

    namelen = pntoh32(v);
    valuelen = pntoh32(v + sizeof(namelen) + namelen);

    return namelen + sizeof(namelen) + valuelen + sizeof(valuelen);
}

static guint http3_hdrcache_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, http3_hdrcache_length(key));
}

static gboolean http3_hdrcache_equal(gconstpointer lhs, gconstpointer rhs)
{
    const guint8 *a = (const guint8 *)lhs;
    const guint8 *b = (const guint8 *)rhs;
    size_t alen = http3_hdrcache_length(a);
    size_t blen = http3_hdrcache_length(b);

    return alen == blen && memcmp(a, b, alen) == 0;
}

static wmem_map_t *http3_hdrdefcache_map = NULL;

static size_t http3_hdrdefcache_length(gconstpointer vv)
{
    const guint8 *v = (const guint8 *)vv;
    guint32 namelen;

    namelen = pntoh32(v);

    return namelen + sizeof(namelen);
}

static guint http3_hdrdefcache_hash(gconstpointer key)
{
    return wmem_strong_hash((const guint8 *)key, http3_hdrdefcache_length(key));
}

static gboolean http3_hdrdefcache_equal(gconstpointer lhs, gconstpointer rhs)
{
    const guint8 *a = (const guint8 *)lhs;
    const guint8 *b = (const guint8 *)rhs;
    size_t alen = http3_hdrdefcache_length(a);
    size_t blen = http3_hdrdefcache_length(b);

    return alen == blen && memcmp(a, b, alen) == 0;
}

static GHashTable* header_fields_hash = NULL;

static void
register_static_headers(void) {
    header_fields_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
                                               g_free, NULL);

    /* Here hf[x].hfinfo.name is a header method which is used as key
     * for matching ids while processing http3 packets */
    static hf_register_info hf[] = {
        {
            &hf_http3_headers_authority,
                {":authority", "http3.headers.authority",
                FT_STRING, BASE_NONE, NULL, 0x0,
                "Authority portion of the target URI", HFILL}
        },
        {
            &hf_http3_headers_status,
                {":status", "http3.headers.status",
                 FT_UINT16, BASE_DEC, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_path,
                {":path", "http3.headers.path",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_method,
                {":method", "http3.headers.method",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_scheme,
                {":scheme", "http3.headers.scheme",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_accept,
                {"accept", "http3.headers.accept",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Media types that are acceptable to the user agent", HFILL}
        },
        {
            &hf_http3_headers_accept_charset,
                {"accept-charset", "http3.headers.accept_charset",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Acceptable charsets in textual responses for the user agent", HFILL}
        },
        {
            &hf_http3_headers_accept_encoding,
                {"accept-encoding", "http3.headers.accept_encoding",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Acceptable content codings (like compression) in responses for the user agent", HFILL}
        },
        {
            &hf_http3_headers_accept_language,
                {"accept-language", "http3.headers.accept_language",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Preferred natural languages for the user agent", HFILL}
        },
        {
            &hf_http3_headers_accept_ranges,
                {"accept-ranges", "http3.headers.accept_ranges",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Bytes range which server may use for partial data transfer", HFILL}
        },
        {
            &hf_http3_headers_access_control_allow_origin,
                {"access-control-allow-origin", "http3.headers.access_control_allow_origin",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Origin control for cross-origin resource sharing", HFILL}
        },
        {
            &hf_http3_headers_age,
                {"age", "http3.headers.age",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Time in seconds which was spent for transferring data through proxy", HFILL}
        },
        {
            &hf_http3_headers_allow,
                {"allow", "http3.headers.allow",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "List of allowed methods for request", HFILL}
        },
        {
            &hf_http3_headers_authorization,
                {"authorization", "http3.headers.authorization",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Credentials for a server-side authorization", HFILL}
        },
        {
            &hf_http3_headers_cache_control,
                {"cache-control", "http3.headers.cache_control",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Request or response directives for a cache control", HFILL}
        },
        {
            &hf_http3_headers_content_disposition,
                {"content-disposition", "http3.headers.content_disposition",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Indicates that response will be displayed as page or downloaded with dialog box", HFILL}
        },
        {
            &hf_http3_headers_content_encoding,
                {"content-encoding", "http3.headers.content_encoding",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_content_language,
                {"content-language", "http3.headers.content_language",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 NULL, HFILL}
        },
        {
            &hf_http3_headers_content_length,
                {"content-length", "http3.headers.content_length",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Size of body in bytes", HFILL}
        },
        {
            &hf_http3_headers_content_location,
                {"content-location", "http3.headers.content_location",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Alternative URL for a response data", HFILL}
        },
        {
            &hf_http3_headers_content_range,
                {"content-range", "http3.headers.content_range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Range of bytes which was sent by server for partial data transfer", HFILL}
        },
        {
            &hf_http3_headers_content_type,
                {"content-type", "http3.headers.content_type",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "MIME type of response", HFILL}
        },
        {
            &hf_http3_headers_cookie,
                {"cookie", "http3.headers.cookie",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Stored cookies", HFILL}
        },
        {
            &hf_http3_headers_date,
                {"date", "http3.headers.date",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Date and time at which the data was originated", HFILL}
        },
        {
            &hf_http3_headers_etag,
                {"etag", "http3.headers.etag",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Directive for version indication of resource", HFILL}
        },
        {
            &hf_http3_headers_expect,
                {"expect", "http3.headers.expect",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Expectations that need to be fulfilled for correct request", HFILL}
        },
        {
            &hf_http3_headers_expires,
                {"expires", "http3.headers.expires",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Data after which resource will be stale", HFILL}
        },
        {
            &hf_http3_headers_from,
                {"from", "http3.headers.from",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Email of a person who responsible for a requesting data", HFILL}
        },
        {
            &hf_http3_headers_if_match,
                {"if-match", "http3.headers.if_match",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for requesting data matched by a list of ETags", HFILL}
        },
        {
            &hf_http3_headers_if_modified_since,
                {"if-modified-since", "http3.headers.if_modified_since",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Resource will be sent with status code 200 if it was modified otherwise with status code 304", HFILL}
        },
        {
            &hf_http3_headers_if_none_match,
                {"if-none-match", "http3.headers.if_none_match",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for requesting data not matched by a list of ETags", HFILL}
        },
        {
            &hf_http3_headers_if_range,
                {"if-range", "http3.headers.if_range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for a range request which is used to check if a resource was modified", HFILL}
        },
        {
            &hf_http3_headers_if_unmodified_since,
                {"if-unmodified-since", "http3.headers.if_unmodified_since",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Resource will be processed if it was not modified otherwise 412 error will be returned", HFILL}
        },
        {
            &hf_http3_headers_last_modified,
                {"last-modified", "http3.headers.last_modified",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Date and time at which the origin server believes the resource was last modified", HFILL}
        },
        {
            &hf_http3_headers_link,
                {"link", "http3.headers.link",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for indicating that resource will be preloaded", HFILL}
        },
        {
            &hf_http3_headers_location,
                {"location", "http3.headers.location",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for indicating that client will be redirected", HFILL}
        },
        {
            &hf_http3_headers_max_forwards,
                {"max-forwards", "http3.headers.max_forwards",
                 FT_UINT64, BASE_DEC, NULL, 0x0,
                 "Mechanism for limiting the number of proxies", HFILL}
        },
        {
            &hf_http3_headers_proxy_authenticate,
                {"proxy-authenticate", "http3.headers.proxy_authenticate",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Authentication method that should be used to gain access to a resource behind a proxy server", HFILL}
        },
        {
            &hf_http3_headers_proxy_authorization,
                {"proxy-authorization", "http3.headers.proxy_authorization",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Credentials for a proxy-side authorization", HFILL}
        },
        {
            &hf_http3_headers_range,
                {"range", "http3.headers.range",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Range of resource bytes that server should return", HFILL}
        },
        {
            &hf_http3_headers_referer,
                {"referer", "http3.headers.referer",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Address of the previous web page", HFILL}
        },
        {
            &hf_http3_headers_refresh,
                {"refresh", "http3.headers.refresh",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Time in seconds after which client will be redirected by given url", HFILL}
        },
        {
            &hf_http3_headers_retry_after,
                {"retry-after", "http3.headers.retry_after",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism to indicate when resource expected to be available", HFILL}
        },
        {
            &hf_http3_headers_server,
                {"server", "http3.headers.server",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Information about server software", HFILL}
        },
        {
            &hf_http3_headers_set_cookie,
                {"set-cookie", "http3.headers.set_cookie",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Send a cookie to the client", HFILL}
        },
        {
            &hf_http3_headers_strict_transport_security,
                {"strict-transport-security", "http3.headers.strict_transport_security",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "HSTS indicates that resource should be accessed only using HTTPS", HFILL}
        },
        {
            &hf_http3_headers_user_agent,
                {"user-agent", "http3.headers.user_agent",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Information about client software", HFILL}
        },
        {
            &hf_http3_headers_vary,
                {"vary", "http3.headers.vary",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Mechanism for selecting which header will be used for content negotiation algorithm", HFILL}
        },
        {
            &hf_http3_headers_via,
                {"via", "http3.headers.via",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Additional information for loop detection and protocol capabilities in proxy requests", HFILL}
        },
        {
            &hf_http3_headers_www_authenticate,
                {"www-authenticate", "http3.headers.www_authenticate",
                 FT_STRING, BASE_NONE, NULL, 0x0,
                 "Authentication method that should be used to gain access to a resource", HFILL}
        }
    };
    gchar* header_name;
    for (guint i = 0; i < G_N_ELEMENTS(hf); ++i) {
        header_name = g_strdup(hf[i].hfinfo.name);

        g_hash_table_insert(header_fields_hash, header_name, &hf[i].hfinfo.id);
    }
    proto_register_field_array(proto_http3, hf, G_N_ELEMENTS(hf));
}
#else
#define register_static_headers() do {} while(false)
#endif /* HAVE_NGHTTP3 */

/**
 * Whether this is a reserved code point for Stream Type, Frame Type, Error
 * Code, etc.
 */
static inline gboolean
http3_is_reserved_code(guint64 stream_type)
{
    return (stream_type - 0x21) % 0x1f == 0;
}

static gboolean
try_get_quic_varint(tvbuff_t *tvb, int offset, guint64 *value, int *lenvar)
{
    if (tvb_reported_length_remaining(tvb, offset) == 0) {
        return FALSE;
    }
    gint len = 1 << (tvb_get_guint8(tvb, offset) >> 6);
    if (tvb_reported_length_remaining(tvb, offset) < len) {
        return FALSE;
    }
    *lenvar = len;
    if (value) {
        gint n = (gint)tvb_get_varint(tvb, offset, -1, value, ENC_VARINT_QUIC);
        DISSECTOR_ASSERT_CMPINT(n, ==, len);
    }
    return TRUE;
}

/** Returns the size of the whole HTTP/3 frame. */
static int
get_http3_frame_size(tvbuff_t *tvb, int offset)
{
    int type_size, length_size;
    guint64 frame_length;

    if (!try_get_quic_varint(tvb, offset, NULL, &type_size)) {
        return 0;
    }
    offset += type_size;

    if (!try_get_quic_varint(tvb, offset, &frame_length, &length_size)) {
        return 0;
    }

    guint64 frame_size = type_size + length_size + frame_length;
    if (frame_size > G_MAXINT32) {
        // We do not support such large frames.
        return 0;
    }
    return (int)frame_size;
}

static gboolean
http3_check_frame_size(tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    int frame_size = get_http3_frame_size(tvb, offset);
    int remaining = tvb_reported_length_remaining(tvb, offset);
    if (frame_size && frame_size <= remaining) {
        return TRUE;
    }

    pinfo->desegment_offset = offset;
    pinfo->desegment_len = frame_size ? (frame_size - remaining) : DESEGMENT_ONE_MORE_SEGMENT;
    return FALSE;
}

#ifdef HAVE_NGHTTP3
static gboolean
qpack_decoder_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data) {
    nghttp3_qpack_decoder_del((nghttp3_qpack_decoder*)user_data);
    return FALSE;
}

static gboolean
qpack_stream_context_del_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data) {
    nghttp3_qpack_stream_context_del((nghttp3_qpack_stream_context*)user_data);
    return FALSE;
}

struct qpack_allocation_options
{
    int debug;
    wmem_allocator_t *allocator;
} g_qpack_allocation_options;

static void *
http3_nghttp3_malloc(size_t size, void *user_data)
{
    (void)user_data;
    return wmem_alloc0(wmem_file_scope(), size);
}

static void
http3_nghttp3_free(void *ptr, void *user_data)
{
    (void)user_data;
    return wmem_free(wmem_file_scope(), ptr);
}

static void *
http3_nghttp3_calloc(size_t nmemb, size_t size, void *user_data)
{
    (void)user_data;
    return wmem_alloc0(wmem_file_scope(), nmemb * size);
}

static void *
http3_nghttp3_realloc(void *ptr, size_t size, void *user_data)
{
    (void)user_data;
    return wmem_realloc(wmem_file_scope(), ptr, size);
}

static nghttp3_mem g_qpack_mem_allocator = {
    .user_data = NULL,
    .malloc = http3_nghttp3_malloc,
    .free = http3_nghttp3_free,
    .calloc = http3_nghttp3_calloc,
    .realloc = http3_nghttp3_realloc,
};

static nghttp3_mem *
qpack_mem_allocator(wmem_allocator_t *allocator, int debug)
{
    (void)allocator;
    (void)debug;
    nghttp3_mem * mem;
    mem = &g_qpack_mem_allocator;
    return mem;
}

static void
http3_initialize_qpack_decoders(http3_session_info_t *h3session)
{
    for (int dir=0; dir < 2; dir++) {
        nghttp3_qpack_decoder **pdecoder = (nghttp3_qpack_decoder**)&(h3session->qpack_decoder[dir]);
        nghttp3_qpack_decoder_new(
                pdecoder,
                QPACK_MAX_DTABLE_SIZE,
                QPACK_MAX_BLOCKED,
                qpack_mem_allocator(wmem_file_scope(), 1));
        nghttp3_qpack_decoder_set_max_dtable_capacity(
                *pdecoder,
                QPACK_MAX_DTABLE_SIZE);
        wmem_register_callback(wmem_file_scope(), qpack_decoder_del_cb, *pdecoder);
    }
}

static void
http3_initailize_qpack_stream_context(quic_stream_info *stream_info, http3_stream_info_t *h3_stream)
{
    nghttp3_qpack_stream_context *qpack_stream_context;
    nghttp3_qpack_stream_context_new(&qpack_stream_context, stream_info->stream_id, nghttp3_mem_default());
    h3_stream->qpack.context = qpack_stream_context;
    wmem_register_callback(wmem_file_scope(), qpack_stream_context_del_cb, h3_stream->qpack.context);
}

#else /* HAVE_NGHTTP3 */
#define http3_initialize_qpack_decoders(session) do {} while(false)
#define http3_initailize_qpack_stream_context(stream_info, stream) do {} while(false)
#endif /* HAVE_NGHTTP3 */

static http3_session_info_t*
http3_session_new(void) {
    http3_session_info_t* h3session;

    h3session = wmem_new0(wmem_file_scope(), http3_session_info_t);
    http3_initialize_qpack_decoders(h3session);
    return h3session;
}

http3_session_info_t*
get_http3_session_info(packet_info *pinfo)
{
    http3_session_info_t* h3session;


    /* First, try to look up the session by initial QUIC DCID */
    quic_cid_t initial_dcid;
    if (quic_conn_data_get_conn_client_dcid_initial(pinfo, &initial_dcid) && false) {
        /* Look up the session data in the conn map */
        if (!http3_conn_info_map) {
            http3_conn_info_map = wmem_map_new(wmem_file_scope(),
                http3_conn_info_hash, http3_conn_info_equal);
        }
        h3session = (http3_session_info_t *)wmem_map_lookup(http3_conn_info_map, &initial_dcid);
        if (h3session == NULL) {
            h3session = http3_session_new();
            wmem_map_insert(http3_conn_info_map, &initial_dcid, h3session);
        }
    } else {
        /* Initial DCID can not be found, use the 5-tuple for lookup */
        conversation_t* conversation = find_or_create_conversation(pinfo);
        h3session = (http3_session_info_t*)conversation_get_proto_data(conversation,
                proto_http3);

        if (h3session == NULL) {
            h3session = http3_session_new();
            conversation_add_proto_data(conversation, proto_http3, h3session);
        }
    }

    return h3session;
}

#ifdef HAVE_NGHTTP3
static const char *
cid_to_string(const quic_cid_t *cid)
{
    if (cid->len == 0) {
        return "(none)";
    }
    char *str = (char *)wmem_alloc0(wmem_packet_scope(), 2 * cid->len + 1);
    bytes_to_hexstr(str, cid->cid, cid->len);
    return str;
}

static http3_header_data_t *
http3_get_header_data(packet_info *pinfo)
{
    http3_header_data_t *data;

    data = (http3_header_data_t*)p_get_proto_data(
        wmem_file_scope(), pinfo, proto_http3, 0);
    if (data == NULL) {
        data = wmem_new0(wmem_file_scope(), http3_header_data_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_http3, 0, data);
    }
    return data;
}

static http3_stream_dir
http3_packet_get_direction(packet_info *pinfo)
{
    if (pinfo->destport == 443) {
        return FROM_CLIENT_TO_SERVER;
    }
    return FROM_SERVER_TO_CLIENT;
}

char *http3_header_pstr = NULL;

static void
try_append_method_path_info(packet_info *pinfo, proto_tree *tree,
                        const gchar *method_header_value, const gchar *path_header_value)
{
    if (method_header_value != NULL && path_header_value != NULL) {
        /* append request inforamtion to info column (for example, HEADERS: GET /demo/1.jpg) */
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s %s", method_header_value, path_header_value);
        /* append request information to Stream node */
        proto_item_append_text(tree, ", %s %s", method_header_value, path_header_value);
    }
}

static proto_item*
try_add_named_header_field(proto_tree *tree, tvbuff_t *tvb, int offset, guint32 length, const char *header_name, const char *header_value)
{
    int hf_id = -1;
    header_field_info *hfi;
    proto_item* ti = NULL;

    const gint *entry = (const gint*) g_hash_table_lookup(header_fields_hash, header_name);
    if (entry == NULL) {
        return NULL;
    }

    hf_id = *entry;

    hfi = proto_registrar_get_nth(hf_id);
    DISSECTOR_ASSERT(hfi != NULL);

    if (IS_FT_UINT32(hfi->type)) {
        guint32 value;
        if (ws_strtou32(header_value, NULL, &value)) {
            ti = proto_tree_add_uint(tree, hf_id, tvb, offset, length, value);
        }
    } else if (IS_FT_UINT(hfi->type)) {
        guint64 value;
        if (ws_strtou64(header_value, NULL, &value)) {
            ti = proto_tree_add_uint64(tree, hf_id, tvb, offset, length, value);
        }
    } else {
        ti = proto_tree_add_item(tree, hf_id, tvb, offset, length, ENC_BIG_ENDIAN);
    }
    return ti;
}

static int
dissect_http3_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, http3_stream_info_t *h3_stream)
{
    http3_header_data_t *header_data;
    gint length = 0;
    http3_session_info_t *h3_session;
    guint32 header_name_length;
    guint32 header_value_length;
    const guint8 *header_name;
    const guint8 *header_value;
    h3_session = get_http3_session_info(pinfo);
    http3_stream_dir packet_direction;
    nghttp3_qpack_decoder *decoder;
    nghttp3_qpack_stream_context *stream_context;
    int header_len = 0, hoffset = 0;
    tvbuff_t *header_tvb;
    proto_tree *header_tree, *blocked_rcint_tree;
    proto_item *header, *ti, *ti_named_field;
    const gchar *method_header_value = NULL;
    const gchar *path_header_value = NULL;
    const gchar *scheme_header_value = NULL;
    const gchar *authority_header_value = NULL;

    HTTP3_DISSECTOR_DPRINTF("pdinfo visited=%d", PINFO_FD_VISITED(pinfo));

    header_data = http3_get_header_data(pinfo);

    if(!PINFO_FD_VISITED(pinfo)) {
        /* This packet has not been processed yet, which means this is
           the first linear scan.  We do header decompression only
           once in linear scan and cache the result.  If we don't
           cache, already processed data will be fed into decompressor
           again and again since dissector will be called randomly.
           This makes context out-of-sync. */

        length = tvb_reported_length_remaining(tvb, offset);
        packet_direction = http3_packet_get_direction(pinfo);
        //packet_direction = FROM_CLIENT_TO_SERVER;
        decoder = h3_session->qpack_decoder[packet_direction];
        DISSECTOR_ASSERT(decoder);
        stream_context = h3_stream->qpack.context;
        DISSECTOR_ASSERT(stream_context);

        if (!http3_hdrcache_map) {
            http3_hdrcache_map = wmem_map_new(wmem_file_scope(), http3_hdrcache_hash, http3_hdrcache_equal);
        }

        if (!http3_hdrdefcache_map) {
            http3_hdrdefcache_map = wmem_map_new(wmem_file_scope(), http3_hdrdefcache_hash, http3_hdrdefcache_equal);
        }

        DISSECTOR_ASSERT(header_data);
        DISSECTOR_ASSERT(header_data->encoded.bytes == NULL);
        DISSECTOR_ASSERT(header_data->encoded.len == 0);
        DISSECTOR_ASSERT(header_data->decoded.headers == NULL);

        header_data->encoded.bytes = tvb_memdup(wmem_file_scope(), tvb, offset, length);
        header_data->encoded.pos = 0;
        header_data->encoded.len = length;

        HTTP3_DISSECTOR_DPRINTF("Header data: %p %d %d\n",
            header_data->encoded.bytes, header_data->encoded.pos,
            header_data->encoded.len);

        /* Attempt to decode headers.
        * TODO: This may incorrectly put headers that were blocked
        * for packet k in the past to this packet n.
        *
        * We will deal with this later
        */
        while (HTTP3_HEADER_DATA_ENCODED_LEN(header_data)) {
            nghttp3_qpack_nv nv;
            guint8 flags;

            HTTP3_DISSECTOR_DPRINTF(
                "%p %p:%d decode decoder=%p stream_context=%p",
                header_data->encoded.bytes,
                HTTP3_HEADER_DATA_ENCODED_PTR(header_data),
                HTTP3_HEADER_DATA_ENCODED_LEN(header_data),
                decoder,
                stream_context);

            gint32 nread = (gint32)nghttp3_qpack_decoder_read_request(
                decoder, stream_context, &nv, &flags,
                HTTP3_HEADER_DATA_ENCODED_PTR(header_data),
                HTTP3_HEADER_DATA_ENCODED_LEN(header_data), 1);

            if (nread < 0) {
                // This should be signaled up
                HTTP3_DISSECTOR_DPRINTF("Early return nread=%d err=%s", nread, nghttp3_strerror(nread));
                break;
            }

            // Check whether the QPACK decoder is blocked on QPACK encoder stream
            if (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) {
                guint64 ricnt = nghttp3_qpack_stream_context_get_ricnt(stream_context);
                guint64 wicnt = nghttp3_qpack_decoder_get_icnt(decoder);
                ti = proto_tree_add_boolean(tree, hf_http3_header_qpack_blocked, tvb, offset, 0, true);
                proto_item_set_generated(ti);
                blocked_rcint_tree = proto_item_add_subtree(ti, ett_http3_headers_qpack_blocked);
                ti = proto_tree_add_uint(blocked_rcint_tree, hf_http3_header_qpack_blocked_stream_rcint, tvb, offset, 0, (guint32)ricnt);
                proto_item_set_generated(ti);
                ti = proto_tree_add_uint(blocked_rcint_tree, hf_http3_header_qpack_blocked_decoder_wicnt, tvb, offset, 0, (guint32)wicnt);

                HTTP3_DISSECTOR_DPRINTF("Early return nread=%d blocked=%hhu ricnt=%lu wicnt=%lu", nread, flags, ricnt, wicnt);
                break;
            }

            // Check whether the decoder has emitted header data
            if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
                http3_header_field_t *out;
                http3_header_field_def_t *def;
                char* cached_pstr;
                nghttp3_vec name_vec;
                nghttp3_vec value_vec;
                guint32 name_len;
                guint8 *name;
                guint32 value_len;
                guint8 *value;
                guint32 pstr_len;

                HTTP3_DISSECTOR_DPRINTF("Emit nread=%d flags=%hhu", nread, flags);

                if (header_data->decoded.headers == NULL) {
                    header_data->decoded.headers = wmem_array_new(wmem_file_scope(), sizeof(http3_header_field_t));
                }

                name_vec = nghttp3_rcbuf_get_buf(nv.name);
                name_len = (guint32)name_vec.len;
                name = name_vec.base;
                value_vec = nghttp3_rcbuf_get_buf(nv.value);
                value_len = (guint32)value_vec.len;
                value = value_vec.base;

                HTTP3_DISSECTOR_DPRINTF("HTTP header: %.*s: %.*s", name_len, name, value_len, value);

                pstr_len = (name_len + value_len + 4 + 4);
                http3_header_pstr = (char *)wmem_realloc(wmem_file_scope(), http3_header_pstr, pstr_len);
                phton32(&http3_header_pstr[0], name_len);
                memcpy(&http3_header_pstr[4], name, name_len);
                phton32(&http3_header_pstr[4 + name_len], value_len);
                memcpy(&http3_header_pstr[4 + name_len + 4], value, value_len);

                /* Lookup a field definition, or create one if needed */
                def = (http3_header_field_def_t*)wmem_map_lookup(http3_hdrdefcache_map, http3_header_pstr);
                if (def == NULL) {
                    char * def_name = NULL;
                    def_name = (char *)wmem_realloc(wmem_file_scope(), def_name, name_len + 1);
                    memcpy(def_name, name, name_len);

                    def = wmem_new0(wmem_file_scope(), http3_header_field_def_t);
                    def->name_len = name_len;
                    def->name = (const char*)def_name;

                    wmem_map_insert(http3_hdrdefcache_map, http3_header_pstr, def);
                }

                /* Create an output field and add it to the headers array */
                out = wmem_new0(wmem_file_scope(), http3_header_field_t);
                out->def = def;

                cached_pstr = (char*)wmem_map_lookup(http3_hdrcache_map, http3_header_pstr);
                if (cached_pstr) {
                    out->decoded.pstr = cached_pstr;
                } else {
                    out->decoded.pstr = http3_header_pstr;
                    wmem_map_insert(http3_hdrcache_map, http3_header_pstr, http3_header_pstr);
                    http3_header_pstr = NULL;
                }
                out->decoded.pstr_len = pstr_len;

                wmem_array_append(header_data->decoded.headers, out, 1);

                // Decrease the reference counts on the NGHTTP3 nv structure to avoid
                // memory leaks
                nghttp3_rcbuf_decref(nv.name);
                nghttp3_rcbuf_decref(nv.value);
            }

            // Check whether the QPACK decoder has finished
            if (nread == 0 || (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL)) {
                break;
            }

            HTTP3_HEADER_DATA_ENCODED_ADVANCE(header_data, nread);
        }
    }

    if((header_data->decoded.headers == NULL) ||
       (wmem_array_get_count(header_data->decoded.headers) == 0)) {
        return offset;
    }

    header_tvb = tvb_new_composite();

    for(guint i = 0; i < wmem_array_get_count(header_data->decoded.headers); ++i) {
        http3_header_field_t *in;
        tvbuff_t *next_tvb;

        in = (http3_header_field_t*)wmem_array_index(header_data->decoded.headers, i);
        header_len += in->decoded.pstr_len;

        /* Now setup the tvb buffer to have the new data */
        next_tvb = tvb_new_child_real_data(tvb, in->decoded.pstr, in->decoded.pstr_len, in->decoded.pstr_len);
        tvb_composite_append(header_tvb, next_tvb);
    }

    tvb_composite_finalize(header_tvb);
    add_new_data_source(pinfo, header_tvb, "Decompressed Header");

    ti = proto_tree_add_uint(tree, hf_http3_header_length, header_tvb,
        hoffset, 1, header_len);
    proto_item_set_generated(ti);

    ti = proto_tree_add_uint(tree, hf_http3_headers_count, header_tvb,
        hoffset, 1, wmem_array_get_count(header_data->decoded.headers));
    proto_item_set_generated(ti);

    for(guint i = 0; i < wmem_array_get_count(header_data->decoded.headers); ++i) {
        http3_header_field_t *in;

        in = (http3_header_field_t*)wmem_array_index(header_data->decoded.headers, i);

        /* Populate tree with header name/value details. */
        /* Add 'Header' subtree with description. */
        header = proto_tree_add_item(tree, hf_http3_header, tvb, offset, in->encoded.len, ENC_NA);

        header_tree = proto_item_add_subtree(header, ett_http3_headers);

        /* header value length */
        proto_tree_add_item_ret_uint(header_tree, hf_http3_header_name_length, header_tvb,
            hoffset, sizeof(guint32), ENC_BIG_ENDIAN, &header_name_length);
        hoffset += sizeof(guint32);

        /* Add header name. */
        proto_tree_add_item_ret_string(header_tree, hf_http3_header_name, header_tvb,
            hoffset, header_name_length, ENC_ASCII|ENC_NA, pinfo->pool, &header_name);
        hoffset += header_name_length;

        /* header value length */
        proto_tree_add_item_ret_uint(header_tree, hf_http3_header_value_length, header_tvb,
            hoffset, sizeof(guint32), ENC_BIG_ENDIAN, &header_value_length);
        hoffset += sizeof(guint32);

        /* Add header value. */
        proto_tree_add_item_ret_string(header_tree, hf_http3_header_value, header_tvb,
            hoffset, header_value_length, ENC_ASCII|ENC_NA, pinfo->pool, &header_value);

        ti_named_field = try_add_named_header_field(header_tree, header_tvb, hoffset, header_value_length, header_name, header_value);

        hoffset += header_value_length;

        proto_item_append_text(header, ": %s: %s", header_name, header_value);

        /* Display :method, :path and :status in info column (just like http1.1 dissector does)*/
        if (strcmp(header_name, HTTP3_HEADER_METHOD) == 0) {
            method_header_value = header_value;
            try_append_method_path_info(pinfo, tree, method_header_value, path_header_value);
        }
        else if (strcmp(header_name, HTTP3_HEADER_PATH) == 0) {
            path_header_value = header_value;
            try_append_method_path_info(pinfo, tree, method_header_value, path_header_value);
            http_add_path_components_to_tree(header_tvb, pinfo, ti_named_field,
                hoffset - header_value_length, header_value_length);
        }
        else if (strcmp(header_name, HTTP3_HEADER_STATUS) == 0) {
            const gchar* reason_phase = val_to_str((guint)strtoul(header_value, NULL, 10), vals_http_status_code, "Unknown");
            /* append response status and reason phrase to info column (for example, HEADERS: 200 OK) */
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ": ", "%s %s", header_value, reason_phase);
            /* append response status and reason phrase to header_tree and Stream node */
            proto_item_append_text(header_tree, " %s", reason_phase);
            proto_item_append_text(tree, ", %s %s", header_value, reason_phase);
        }
        else if (strcmp(header_name, HTTP3_HEADER_AUTHORITY) == 0) {
            authority_header_value = header_value;
        }
        else if (strcmp(header_name, HTTP3_HEADER_SCHEME) == 0) {
            scheme_header_value = header_value;
        }

        offset += in->encoded.len;
    }

    /* Use the Authority Header as an indication that this packet is a request */
    if (authority_header_value) {
        proto_item *e_ti;
        gchar *uri;

        /* RFC9113 8.3.1:
        "All HTTP/2 requests MUST include exactly one valid value for the
        ":method", ":scheme", and ":path" pseudo-header fields, unless they
        are CONNECT requests"
        */
        if (method_header_value &&
            strcmp(method_header_value, HTTP3_HEADER_METHOD_CONNECT) == 0) {
            uri = wmem_strdup(wmem_packet_scope(), authority_header_value);
        } else {
            uri = wmem_strdup_printf(wmem_packet_scope(), "%s://%s%s", scheme_header_value, authority_header_value, path_header_value);
        }
        e_ti = proto_tree_add_string(tree, hf_http3_header_request_full_uri, tvb, 0, 0, uri);
        proto_item_set_url(e_ti);
        proto_item_set_generated(e_ti);
    }

    return offset;
}
#else /* HAVE_NGHTTP3 */
static int
dissect_http3_headers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, http3_stream_info_t *h3_stream)
{
    (void)pinfo;
    (void)tree;
    (void)h3_stream;
    return offset + tvb_reported_length_remaining(tvb, offset);
}
#endif

/* Settings */
static int
dissect_http3_settings(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http3_tree, guint offset)
{
    guint64 settingsid, value;
    proto_item *ti_settings, *pi;
    int lenvar;
    proto_tree *settings_tree;
    while(tvb_reported_length_remaining(tvb, offset) > 0){

        ti_settings = proto_tree_add_item(http3_tree, hf_http3_settings, tvb, offset, 2, ENC_NA);
        settings_tree = proto_item_add_subtree(ti_settings, ett_http3_settings);
        pi = proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_identifier, tvb, offset, -1, ENC_VARINT_QUIC, &settingsid, &lenvar);
        /* Check if it is a GREASE Settings ID */
        if (http3_is_reserved_code(settingsid)) {
            proto_item_set_text(pi, "Type: GREASE (%#" PRIx64 ")", settingsid);
            proto_item_append_text(ti_settings, " - GREASE" );
        } else {
            proto_item_append_text(ti_settings, " - %s",
                                   val64_to_str_const(settingsid, http3_settings_vals, "Unknown") );
        }
        offset += lenvar;


        proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_value, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
        switch(settingsid){
            case HTTP3_QPACK_MAX_TABLE_CAPACITY:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_qpack_max_table_capacity, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_SETTINGS_MAX_FIELD_SECTION_SIZE:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_max_field_section_size, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_QPACK_BLOCKED_STREAMS:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_qpack_blocked_streams, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_EXTENDED_CONNECT:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_extended_connect, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_ENABLE_WEBTRANSPORT:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_enable_webtransport, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            case HTTP3_H3_DATAGRAM:
                proto_tree_add_item_ret_varint(settings_tree, hf_http3_settings_h3_datagram, tvb, offset, -1, ENC_VARINT_QUIC, &value, &lenvar);
                proto_item_append_text(ti_settings, ": %" PRIu64, value );
            break;
            default:
                /* No Default */
            break;
        }
        offset += lenvar;
    }

    return offset;
}
/* Priority Update */
static int
dissect_http3_priority_update(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http3_tree, guint offset, guint64 frame_length)
{
    guint64 priority_field_value_len;
    int lenvar;

    proto_tree_add_item_ret_varint(http3_tree, hf_http3_priority_update_element_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
    offset += lenvar;
    priority_field_value_len = frame_length - lenvar;

    proto_tree_add_item(http3_tree, hf_http3_priority_update_field_value, tvb, offset, (int)priority_field_value_len, ENC_ASCII);
    offset += (int)priority_field_value_len;

    return offset;
}

/* Webtransport stream (uni-, bidirectional) */
static int
dissect_http3_webtransport_stream(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* http3_tree, guint offset, guint64 frame_length)
{
    guint64 session_body_len, session_id;
    int lenvar;

    proto_tree_add_item_ret_varint(http3_tree, hf_http3_wt_session_id, tvb, offset, -1, ENC_VARINT_QUIC, &session_id, &lenvar);
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%" PRIu64 ")", session_id);
    offset += lenvar;
    session_body_len = frame_length - lenvar;

    proto_tree_add_item(http3_tree, hf_http3_wt_stream_body, tvb, offset, (int)session_body_len, ENC_ASCII);
    offset += (int)session_body_len;

    return offset;
}

static int
dissect_http3_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, http3_stream_info_t *h3_stream)
{
    guint64 frame_type, frame_length;
    int lenvar;
    proto_item *pi;

    pi = proto_tree_add_item_ret_varint(tree, hf_http3_frame_type, tvb, offset, -1, ENC_VARINT_QUIC, &frame_type, &lenvar);
    offset += lenvar;
    if (http3_is_reserved_code(frame_type)) {
        proto_item_set_text(pi, "Type: Reserved (%#" PRIx64 ")", frame_type);
    } else {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val64_to_str_const(frame_type, http3_frame_types, "Unknown"));
    }

    if (frame_type == HTTP3_WEBTRANSPORT_STREAM ||
        frame_type == HTTP3_UNIDIRECTIONAL_STREAM) {
        frame_length = tvb_reported_length_remaining(tvb, offset);
        //proto_item_set_text(pi, "WT_Framelength: (%#" PRIx64 ")", frame_length);
    } else {
        proto_tree_add_item_ret_varint(tree, hf_http3_frame_length, tvb, offset, -1, ENC_VARINT_QUIC, &frame_length, &lenvar);
        offset += lenvar;
    }

    if (frame_length) {
        proto_tree_add_item(tree, hf_http3_frame_payload, tvb, offset, (int)frame_length, ENC_NA);

        switch (frame_type) {
            case HTTP3_DATA: /* TODO: dissect Data Frame */
            break;
            case HTTP3_HEADERS: {/* TODO: dissect Headers Frame */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_headers(next_tvb, pinfo, tree, 0, h3_stream);
            }
            break;
            case HTTP3_CANCEL_PUSH: /* TODO: dissect Cancel_Push Frame */
            break;
            case HTTP3_SETTINGS: { /* Settings Frame */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_settings(next_tvb, pinfo, tree, 0);
            }
            break;
            case HTTP3_PUSH_PROMISE: /* TODO: dissect Push_Promise_Frame */
            break;
            case HTTP3_GOAWAY: /* TODO: dissect Goaway Frame */
            break;
            case HTTP3_MAX_PUSH_ID: /* TODO: dissect Max_Push_ID Frame */
            break;
            case HTTP3_DUPLICATE_PUSH: /* TODO: add expert_advise */
            break;
            case HTTP3_PRIORITY_UPDATE_REQUEST_STREAM:
            case HTTP3_PRIORITY_UPDATE_PUSH_STREAM: { /* Priority_Update Frame */
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_priority_update(next_tvb, pinfo,tree, 0, frame_length);
            }
            break;
            case HTTP3_UNIDIRECTIONAL_STREAM:
            case HTTP3_WEBTRANSPORT_STREAM: {
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, (int)frame_length);
                dissect_http3_webtransport_stream(next_tvb, pinfo,tree, 0, frame_length);
            }
            break;
            default: /* TODO: add expert_advise */
            break;
        }

        offset += (int)frame_length;
    }


    return offset;
}

static void
report_unknown_stream_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info_t *h3_stream)
{
    /*
     * "If the stream header indicates a stream type which is not supported by
     * the recipient, the remainder of the stream cannot be consumed as the
     * semantics are unknown."
     * https://tools.ietf.org/html/draft-ietf-quic-http-29#page-28
     */
    proto_tree_add_expert_format(tree, pinfo, &ei_http3_unknown_stream_type, tvb, offset, 0,
                                 "Unknown stream type %#" PRIx64 " on Stream ID %#" PRIx64,
                                 h3_stream->uni_stream_type, stream_info->stream_id);
}

/* Read QPACK varint value, return number of consumed bytes, including the prefix byte */
#define HTTP3_QPACK_MAX_SHIFT 62
#define HTTP3_QPACK_MAX_INT ((1ull << HTTP3_QPACK_MAX_SHIFT) - 1)
static gint
read_qpack_varint(guint8 *buf, guint8 *end, gint prefix, guint64 *out_result, gboolean *out_fin)
{
    guint64 k = (uint8_t)((1 << prefix) - 1);
    guint64 n = 0;
    guint64 add = 0;
    guint64 shift = 0;
    const guint8 *p = buf;

    if (((*p) & k) != k) {
      *out_result = (*p) & k;
      *out_fin = true;
      return 1;
    }

    n = k;

    if (++p == end) {
        *out_result = n;
        *out_fin = false;
        return (gint)(p - buf);
    }

    for (; p != end; ++p, shift += 7) {
        add = (*p) & 0x7f;
        if (shift > HTTP3_QPACK_MAX_SHIFT) {
            return -1;
        }
        if ((HTTP3_QPACK_MAX_INT >> shift) < add) {
            return -1;
        }
        add <<= shift;
        if (HTTP3_QPACK_MAX_INT - add < n) {
            return -1;
        }

        n += add;

        if (((*p) & (1 << 7)) == 0) {
            break;
        }
    }

    *out_result = n;

    /* If we consumed all bytes, return the consumed bytes */
    if (p == end) {
        *out_fin = false;
        return (gint)(p - buf);
    }

    /* Otherwise, consume extra byte and mark the fin output param */
    if (out_fin) {
        *out_fin = true;
    }
    return (gint)(p + 1 - buf);
}

static gint
dissect_http3_qpack_encoder_stream_opcodes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, uint8_t *qpack_buf, guint remaining, http3_stream_info_t *h3_stream)
{
    guint remaining_captured;
    proto_item *qpack_opcode, *ti;
    proto_tree *qpack_opcode_tree;
    guint decoded = 0;
    gint fin = 0, inc = 0;
    guint can_continue = 1;

    uint8_t *end = qpack_buf + remaining;

    remaining_captured = tvb_captured_length_remaining(tvb, offset);
    DISSECTOR_ASSERT(remaining_captured == remaining);

    if (qpack_buf == NULL || remaining <= 0) {
        HTTP3_DISSECTOR_DPRINTF("Exiting qpack_buf=%p remaining=%d", qpack_buf, remaining);
        return 0;
    }

    while (decoded < remaining && can_continue) {
        gint opcode_offset = 0;
        gint opcode_length = 0;
        guint8 opcode = 0;
        fin = 0;

        opcode = qpack_buf[decoded];

        HTTP3_DISSECTOR_DPRINTF("Decoding opcode=%hhu decoded=%d remaining=%d", opcode, decoded, remaining);

        if (opcode & 0x80) {
            gint table_entry_len = 0;
            guint64 table_entry = 0;
            gint value_offset = 0;
            guint64 value_bytes_len = 0;
            gint value_len = 0;

            opcode_offset = offset + decoded;
            inc = read_qpack_varint(
                qpack_buf + decoded, end, 6, &table_entry, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            table_entry_len = inc;
            decoded += inc;

            inc = read_qpack_varint(
                qpack_buf + decoded, end, 7, &value_bytes_len, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            decoded += inc;
            value_offset = offset + decoded;
            HTTP3_DISSECTOR_DPRINTF("fin=%d Decoded=%u value_bytes_len=%lu remaining=%u",
                fin, decoded, value_bytes_len, remaining);
            DISSECTOR_ASSERT(decoded + value_bytes_len <= remaining);
            decoded += value_bytes_len;
            value_len = decoded - value_offset;
            opcode_length = offset + decoded - opcode_offset;

            qpack_opcode = proto_tree_add_item(tree, hf_http3_qpack_encoder_opcode_insert_indexed, tvb, opcode_offset, opcode_length, ENC_NA);
            qpack_opcode_tree = proto_item_add_subtree(qpack_opcode, ett_http3_qpack_opcode);
            ti = proto_tree_add_item(qpack_opcode_tree, hf_http3_qpack_encoder_opcode_insert_indexed_ref, tvb, opcode_offset, table_entry_len, ENC_NA);
            proto_item_set_text(qpack_opcode, "QPACK encoder opcode: INSERT_INDEXED ref_len=%d ref=%lu val_len=%d",
                table_entry_len, table_entry, value_len);

            HTTP3_DISSECTOR_DPRINTF("fin=%d Opcode=%u:INSERT INDEXED ref_len=%d ref=%lu value_len=%d val=[huffman]",
                fin, opcode, table_entry_len, table_entry, value_len);
        } else if (opcode & 0x40) {
            guint64 name_bytes_len = 0;
            gint name_offset, name_len, value_offset, value_len;
            guint64 value_bytes_len = 0;

            opcode_offset = offset + decoded;

            inc = read_qpack_varint(
                qpack_buf + decoded, end, 5, &name_bytes_len, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            decoded += inc;
            name_offset = offset + decoded;
            HTTP3_DISSECTOR_DPRINTF("fin=%d Decoded=%u name_bytes_len=%lu remaining=%u",
                fin, decoded, name_bytes_len, remaining);
            DISSECTOR_ASSERT(decoded + name_bytes_len <= remaining);
            decoded += name_bytes_len;
            name_len = offset + decoded - name_offset;

            inc = read_qpack_varint(
                qpack_buf + decoded, end, 7, &value_bytes_len, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            decoded += inc;
            value_offset = offset + decoded;
            HTTP3_DISSECTOR_DPRINTF("fin=%d Decoded=%u value_bytes_len=%lu remaining=%u",
                fin, decoded, value_bytes_len, remaining);
            DISSECTOR_ASSERT(decoded + value_bytes_len <= remaining);
            decoded += value_bytes_len;
            value_len = offset + decoded - value_offset;

            opcode_length = offset + decoded - opcode_offset;

            qpack_opcode = proto_tree_add_item(tree, hf_http3_qpack_encoder_opcode_insert, tvb, opcode_offset, opcode_length, ENC_NA);
            qpack_opcode_tree = proto_item_add_subtree(qpack_opcode, ett_http3_qpack_opcode);
            proto_item_set_text(qpack_opcode, "QPACK encoder opcode: INSERT name_len=%d val_len=%d",
                name_len, value_len);

            HTTP3_DISSECTOR_DPRINTF("Fin=%d Opcode=%u: INSERT name_len=%d value_len=%d",
                fin, opcode, name_len, value_len);
        } else if (opcode & 0x20) {
            guint64 dynamic_capacity = 0;
            opcode_offset = offset + decoded;

            inc = read_qpack_varint(
                qpack_buf + decoded, end, 5, &dynamic_capacity, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            decoded += inc;
            opcode_length = offset + decoded - opcode_offset;
            qpack_opcode = proto_tree_add_item(tree, hf_http3_qpack_encoder_opcode_dtable_cap, tvb, opcode_offset, opcode_length, ENC_NA);
            proto_item_set_text(qpack_opcode, "QPACK encoder opcode: Set DTable Cap=%lu", dynamic_capacity);
            HTTP3_DISSECTOR_DPRINTF("Fin=%d Opcode=%u: SET DTABLE TABLE CAP capacity=%lu",
                fin, opcode, dynamic_capacity);
        } else if (!(opcode & 0x20)) {
            guint64 duplicate_of = 0;
            opcode_offset = offset + decoded;

            inc = read_qpack_varint(
                qpack_buf + decoded, end, 5, &duplicate_of, &fin);
            DISSECTOR_ASSERT(0 < inc);
            DISSECTOR_ASSERT(decoded + inc <= remaining);
            decoded += inc;

            opcode_length = offset + decoded - opcode_offset;
            qpack_opcode = proto_tree_add_item(tree, hf_http3_qpack_encoder_opcode_duplicate, tvb, opcode_offset, opcode_length, ENC_NA);

            HTTP3_DISSECTOR_DPRINTF("Fin=%d Opcode=%u: DUPLICATE of=%lu",
                fin, opcode, duplicate_of);
        } else {
            HTTP3_DISSECTOR_DPRINTF("Opcode=%hhu: UNKNOWN", opcode);
            can_continue = 0;
        }

        HTTP3_DISSECTOR_DPRINTF("Decoding decoded=%d remaining=%d can_continue=%d", decoded, remaining, can_continue);
    }
    (void)pinfo;
    (void)h3_stream;
    (void)ti;

    return offset + decoded;
}

static gint
dissect_http3_qpack_enc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, http3_stream_info_t *h3_stream)
{
    gint remaining, remaining_captured, retval, decoded = 0;
    proto_item *qpack_update;
    proto_tree *qpack_update_tree;


    http3_session_info_t *h3_session;
    uint8_t *qpack_buf = NULL;

    remaining_captured = tvb_captured_length_remaining(tvb, offset);
    remaining = tvb_reported_length_remaining(tvb, offset);
    DISSECTOR_ASSERT(remaining_captured == remaining);
    retval = remaining;

    h3_session = get_http3_session_info(pinfo);
    DISSECTOR_ASSERT(h3_session);

    if (remaining > 0) {
        qpack_buf = (uint8_t*)tvb_memdup(wmem_packet_scope(), tvb, offset, remaining);
    }

    quic_cid_t quic_cid = {0, {0, }};
    if (!quic_conn_data_get_conn_client_dcid_initial(pinfo, &quic_cid)) {
        quic_cid.len = 0;
    }

    // Add a QPACK encoder tree item
    qpack_update = proto_tree_add_item(tree, hf_http3_qpack_encoder, tvb, offset, remaining, ENC_NA);
    qpack_update_tree = proto_item_add_subtree(qpack_update, ett_http3_qpack_update);
    decoded = dissect_http3_qpack_encoder_stream_opcodes(tvb, pinfo, qpack_update_tree,
            offset, qpack_buf, (guint)remaining, h3_stream);

#ifdef HAVE_NGHTTP3
    if (qpack_buf && 0 < remaining) {
        nghttp3_qpack_decoder *decoder;
        guint32 icnt_before, icnt_after;
        gint qpack_buf_len = 0;
        proto_item *ti;

        http3_stream_dir packet_direction = http3_packet_get_direction(pinfo);
        decoder = h3_session->qpack_decoder[packet_direction];

        // Get the instr count prior to processing the data.
        icnt_after = icnt_before = (guint32)nghttp3_qpack_decoder_get_icnt(decoder);


        qpack_buf_len = decoded - offset;

        HTTP3_DISSECTOR_DPRINTF("decode encoder stream: decoder=%p remaining=%u", decoder, remaining);

        gint32  nread = (gint32)nghttp3_qpack_decoder_read_encoder(decoder, qpack_buf, qpack_buf_len);

        if (nread < 0) {
            proto_tree_add_expert_format(tree, pinfo, &ei_http3_qpack_failed, tvb, offset, 0,
                "QPAC decoder %p DCID %s error %d (%s)",
                decoder, cid_to_string(&quic_cid), nread, nghttp3_strerror((int)nread));
        }

        icnt_after = (guint32)nghttp3_qpack_decoder_get_icnt(decoder);
        proto_item_set_text(qpack_update, "QPACK encoder stream; %d opcodes (%d total)",
            icnt_after - icnt_before, icnt_after);

        ti = proto_tree_add_uint(qpack_update_tree, hf_http3_qpack_encoder_icnt, tvb, offset, 0, icnt_after);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(qpack_update_tree, hf_http3_qpack_encoder_icnt_inc, tvb, offset, 0, icnt_after - icnt_before);
        proto_item_set_generated(ti);
    }
#else
    (void)qpack_buf;
    (void)qpack_update;
    (void)h3_stream;
    (void)decoded;
#endif /* HAVE_NGHTTP3 */


    return retval;
}

static int
dissect_http3_uni_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, quic_stream_info *stream_info, http3_stream_info_t *h3_stream)
{
    guint64 stream_type;
    int lenvar;
    proto_item *pi;

    if (stream_info->offset == 0) {
        pi = proto_tree_add_item_ret_varint(tree, hf_http3_stream_type, tvb, offset, -1, ENC_VARINT_QUIC, &stream_type, &lenvar);
        offset += lenvar;
        if (http3_is_reserved_code(stream_type)) {
            // Reserved to exercise requirement that unknown types are ignored.
            proto_item_set_text(pi, "Stream Type: Reserved (%#" PRIx64 ")", stream_type);
        }
        h3_stream->uni_stream_type = stream_type;
    } else {
        stream_type = h3_stream->uni_stream_type;
    }

    switch (stream_type) {
        case HTTP3_STREAM_TYPE_CONTROL:
            break;
        case HTTP3_STREAM_TYPE_PUSH:
            // The remaining data of this stream consists of HTTP/3 frames.
            if (stream_info->offset == 0) {
                proto_tree_add_item_ret_varint(tree, hf_http3_push_id, tvb, offset, -1, ENC_VARINT_QUIC, NULL, &lenvar);
                offset += lenvar;
            }
            break;
        case HTTP3_STREAM_TYPE_QPACK_ENCODER:
            offset = dissect_http3_qpack_enc(tvb, pinfo, tree, offset, h3_stream);
            break;
        case HTTP3_STREAM_TYPE_QPACK_DECODER:
            // TODO
            offset = tvb_captured_length(tvb);
            break;
        default:
            // Unknown or reserved stream type, consume everything.
            if (!http3_is_reserved_code(stream_type)) {
                if (!PINFO_FD_VISITED(pinfo)) {
                    h3_stream->broken_from_offset = stream_info->offset + offset;
                }
                report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
            }
            offset = tvb_captured_length(tvb);
            break;
    }

    return offset;
}

static int
dissect_http3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    quic_stream_info *stream_info = (quic_stream_info *)data;
    proto_item *ti;
    proto_tree *http3_tree;
    int offset = 0;
    http3_stream_info_t *h3_stream;

    if (!stream_info) {
        return 0;
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            if (!http3_check_frame_size(tvb, pinfo, offset)) {
                return tvb_captured_length(tvb);
            }
            break;
        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            break;
        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP3");
    // Only clear the columns if this is the first HTTP/3 STREAM in the packet.
    if (!proto_is_frame_protocol(pinfo->layers, "http3")) {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    ti = proto_tree_add_item(tree, proto_http3, tvb, 0, -1, ENC_NA);
    http3_tree = proto_item_add_subtree(ti, ett_http3);

    h3_stream = (http3_stream_info_t *)quic_stream_get_proto_data(pinfo, stream_info);
    if (!h3_stream) {
        h3_stream = wmem_new0(wmem_file_scope(), http3_stream_info_t);
        quic_stream_add_proto_data(pinfo, stream_info, h3_stream);

        http3_initailize_qpack_stream_context(stream_info, h3_stream);
    }

    // If a STREAM has unknown data, everything afterwards cannot be dissected.
    if (h3_stream->broken_from_offset && h3_stream->broken_from_offset <= stream_info->offset + offset) {
        report_unknown_stream_type(tvb, pinfo, tree, offset, stream_info, h3_stream);
        return tvb_captured_length(tvb);
    }

    switch (QUIC_STREAM_TYPE(stream_info->stream_id)) {
        case QUIC_STREAM_CLIENT_BIDI:
            /* Used for HTTP requests and responses. */
            break;

        case QUIC_STREAM_SERVER_BIDI:
            /* "HTTP/3 does not use server-initiated bidirectional streams,
             * though an extension could define a use for these streams." */
            // XXX expert info?
            return tvb_captured_length(tvb);

        case QUIC_STREAM_CLIENT_UNI:
        case QUIC_STREAM_SERVER_UNI:
            offset = dissect_http3_uni_stream(tvb, pinfo, http3_tree, offset, stream_info, h3_stream);
            break;
    }

    while (tvb_reported_length_remaining(tvb, offset)) {
        if (!http3_check_frame_size(tvb, pinfo, offset)) {
            return tvb_captured_length(tvb);
        }
        offset = dissect_http3_frame(tvb, pinfo, http3_tree, offset, h3_stream);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_http3(void)
{
    expert_module_t *expert_http3;
    module_t *module_http3;


    static hf_register_info hf[] = {
        { &hf_http3_stream_type,
          { "Stream Type", "http3.stream_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_stream_types), 0x0,
            NULL, HFILL }
        },
        { &hf_http3_push_id,
          { "Push ID", "http3.push_id",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_http3_frame_type,
          { "Type", "http3.frame_type",
            FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_frame_types), 0x0,
            "Frame Type", HFILL }
        },
        { &hf_http3_frame_length,
          { "Length", "http3.frame_length",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            "Length of the Frame Payload", HFILL }
        },
        { &hf_http3_frame_payload,
          { "Frame Payload", "http3.frame_payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* Headers */
        { &hf_http3_headers,
             { "Header", "http3.headers",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_headers_count,
             { "Headers Count", "http3.headers.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header,
             { "Header", "http3.headers.header",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_length,
             { "Header Length", "http3.headers.header.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_name_length,
             { "Name Length", "http3.headers.header.name.length",
               FT_UINT32, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_http3_header_name,
             { "Name", "http3.header.header.name",
               FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_value_length,
            { "Value Length", "http3.headers.header.value.length",
              FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_header_value,
            { "Value", "http3.headers.header.value",
                FT_STRING, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_request_full_uri,
            { "Full request URI", "http3.request.full_uri",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "The full requested URI (including host name)", HFILL }
        },
        { &hf_http3_header_qpack_blocked,
            { "HEADERS head-of-line-blocked on QPACK encoder stream", "http3.header.qpack.blocked",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_qpack_blocked_stream_rcint,
            { "Required instruction count", "http3.header.qpack.blocked.rcint",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
       { &hf_http3_header_qpack_blocked_decoder_wicnt,
            { "Available instruction count", "http3.header.qpack.blocked.wcint",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_header_qpack_fatal,
            { "QPACK decoding error", "http3.header.qpack.fatal",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_qpack,
            { "QPACK", "http3.qpack",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_qpack_encoder,
            { "QPACK encoder", "http3.qpack.encoder",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_length,
            { "QPACK encoder update length", "http3.qpack.encoder.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_icnt,
            { "QPACK encoder instruction count", "http3.qpack.encoder.icnt",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_icnt_inc,
            { "QPACK encoder instruction count increment", "http3.qpack.encoder.icnt.inc",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
       { &hf_http3_qpack_encoder_opcode,
            { "QPACK encoder opcode", "http3.qpack.encoder.opcode",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert_indexed,
            { "QPACK encoder opcode: Insert By Ref", "http3.qpack.encoder.opcode.insert_indexed",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert_indexed_ref,
            { "QPACK encoder opcode: Insert By Ref: Ref", "http3.qpack.encoder.opcode.insert_indexed.ref",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert_indexed_val,
            { "QPACK encoder opcode: Insert By Ref: Val", "http3.qpack.encoder.opcode.insert_indexed.val",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert,
            { "QPACK encoder opcode: Insert", "http3.qpack.encoder.opcode.insert",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert_name,
            { "QPACK encoder opcode: Insert: Name", "http3.qpack.encoder.opcode.insert.name",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_insert_val,
            { "QPACK encoder opcode: Insert: Value", "http3.qpack.encoder.opcode.insert.val",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_duplicate,
            { "QPACK encoder opcode: Duplicate", "http3.qpack.encoder.opcode.duplicate",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_duplicate_val,
            { "QPACK encoder opcode: Duplicate: Value", "http3.qpack.encoder.opcode.duplicate.val",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_dtable_cap,
            { "QPACK encoder opcode: Max DTable Capacity", "http3.qpack.encoder.opcode.dtable_cap",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_qpack_encoder_opcode_dtable_cap_val,
            { "QPACK encoder opcode: Max DTable Capacity: Value", "http3.qpack.encoder.opcode.dtable_cap",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Settings */
        { &hf_http3_settings,
            { "Settings", "http3.settings",
               FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_identifier,
            { "Settings Identifier", "http3.settings.id",
               FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(http3_settings_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_value,
            { "Settings Value", "http3.settings.value",
               FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_qpack_max_table_capacity,
            { "Max Table Capacity", "http3.settings.qpack.max_table_capacity",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_max_field_section_size,
            { "Max header list size", "http3.settings.max_field_section_size",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "The default value is unlimited.", HFILL }
        },
        { &hf_http3_settings_qpack_blocked_streams,
            { "Blocked Streams", "http3.settings.qpack.blocked_streams",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_extended_connect,
            { "Extended CONNECT", "http3.settings.extended_connect",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_enable_webtransport,
            { "Enable webtransport", "http3.settings.enable_webtransport",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_settings_h3_datagram,
            { "H3 Datagram", "http3.settings.h3_datagram",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },

        /* Priority Update */
        { &hf_http3_priority_update_element_id,
            { "Priority Update Element ID", "http3.priority_update_element_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_priority_update_field_value,
            { "Priority Update Field Value", "http3.priority_update_field_value",
              FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },

        /* Webtransport */
        { &hf_http3_wt_session_id,
            { "Session ID", "http3.webtransport.session_id",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              NULL, HFILL }
        },
        { &hf_http3_wt_stream_body,
            { "Stream Body", "http3.webtransport.stream_body",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_http3,
        &ett_http3_settings,
        &ett_http3_headers,
        &ett_http3_headers_qpack_blocked,
        &ett_http3_qpack_update,
        &ett_http3_qpack_opcode
    };

    static ei_register_info ei[] = {
        { &ei_http3_unknown_stream_type,
          { "http3.unknown_stream_type", PI_UNDECODED, PI_WARN,
            "An unknown stream type was encountered", EXPFILL }
        },
        { &ei_http3_data_not_decoded,
            { "http3.data_not_decoded", PI_UNDECODED, PI_WARN,
              "Data not decoded", EXPFILL }
         },
         { &ei_http3_header_decoding_failed ,
           { "http3.header_failed", PI_UNDECODED, PI_WARN,
             "Failed to decode HTTP3 header name/value", EXPFILL }
         },
         { &ei_http3_qpack_enc_update ,
           { "http3.qpack_enc_update", PI_UNDECODED, PI_WARN,
             "Success decoding QPACK buffer", EXPFILL }
         },
         { &ei_http3_qpack_failed,
           { "http3.qpack_enc_failed", PI_UNDECODED, PI_WARN,
             "Error decoding QPACK buffer", EXPFILL }
         },
    };

    proto_http3 = proto_register_protocol("Hypertext Transfer Protocol Version 3", "HTTP3", "http3");

    proto_register_field_array(proto_http3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_http3 = prefs_register_protocol(proto_http3, NULL);
    (void)module_http3;

    expert_http3 = expert_register_protocol(proto_http3);
    expert_register_field_array(expert_http3, ei, array_length(ei));

    /* Fill hash table with static headers */
    register_static_headers();
}

void
proto_reg_handoff_http3(void)
{
    dissector_handle_t http3_handle;

    http3_handle = create_dissector_handle(dissect_http3, proto_http3);
    dissector_add_string("quic.proto", "h3", http3_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
