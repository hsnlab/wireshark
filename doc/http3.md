# Design notes on the HTTP3 dissector for wireshark


## Supported features

The HTTP3 dissector is a work in progress.

At the moment, the following aspects of HTTP3 are supported:

- Stream types
- Frame types
- HTTP header fields
- QPACK insert count

The future plans include adding support to:

- Dissecting the SETTNIGS frames
- Dissecting the QPACK encoder and decoder streams


## Dissecting HTTP3 header fields

HTTP3 headers are compressed with [QPACK](https://datatracker.ietf.org/doc/draft-ietf-quic-qpack/).
Because of that, the dissector needs a way to interpret the QPACK encoding
streams, and to maintain the dynamic compression tables.

Currently, the dissector relies on the QPACK compression implementation from
`nghttp3`, which is a popular open source implementation of HTTP3.

## Managing the dissector state


### Connection-level state

`nghttp3`'s QPACK implementation requires a separate dissector instance per
QPACK encoder stream.

The dissector uses `http3_session_info`, which is associated with conversation
info pointer.

NOTE: this implementation assumes that different QUIC connections will have
different 5-tuples. Different DCIDs that share the same 5-tuple are not
supported.

### Stream-level state

`nghttp3`'s QPACK implementation requires a keeping a separate context per every request stream.

The dissector keeps this state in `http3_stream_info`, which is associated with
every stream (via `quic_stream_get_proto_data`).


### PDU-level state

Finally, the header fields must be stored for reapeting access once decoding
finishes.

The dissector keeps the decoded headers in a `http3_headers_data_t`, which
keeps the count of decoded header fields, the combined length of the fields
after the decoding, and an array of the header fields.

Similarly to the HTTP2 dissector, once the fields are decoded, they are stored in a flat buffer:

```
name_length (uint32)
name (string)
value_length (uint32)
value
```

This allows using the standard Wireshark methods for parsing fields when
constructing the decoded header field.

NOTE: at the moment, header fields are not de-duped across multiple HEADERS
frames. This limitation will be addressed later.


```
+-----------------+
|Packet Info      |
+-----------------+
         |                       +-------------------+
         |                       |http3_session_info |
         |                       |------------------ |
         +---conversation------->|QPACK decoders     |
         |                       |                   |
         |                       +-------------------+
         |
         |                       +--------------------+
         |                       |http3_stream_info   |
         |                       |-----------------   |
         +---stream_proto_data-->|Stream context for  |
         |                       |the QPACK decoder.  |
         |                       |                    |
         |                       +--------------------+
         |                       +-------------------+
         |                       |http3_header_data  |
         |                       |-----------------  |
         +---proto_data--------->|Decompressed header|
                                 |fields.            |
                                 +-------------------+
```

Open questions:
1. Large files can have a lot of sessions/conversations, can use a lot of
   memory. Maybe worth adding a setting to disable the QPACK decoding.
2. Support for PCAPs that contain multiple DCIDs with same 5-tuples.
   [Peter Wu]: this should be possible by somehow accessing the QUIC
               conversation that the HTTP/3 session is layered upon.
3. De-duplicate repeating header fields.


## Using nghttp3 to decode HEADERS frames

### Updating QPACK states

When dissecting QPACK encoder stream, the dissector passes the payload to the
corresponding `nghttp3_qpack_decoder` instance.

On a successful update, the dissector appends the current insert count to the
protocol tree.

On failure, the dissector emits expert info advise.

### Decompressing HTTP3 headers

When dissecting HEADERS frames, the dissector attempts to decode data using the
corresponding `nghttp3_qpack_decoder` and `nghttp3_qpack_stram_context`
instances.

The `nghttp3_qpack_decoder` informs the dissector on the decoding status via a flag word.

If the decoder successfully inflates a header field, as indicated by `EMIT`
flag bit, the output from the decoder is converted into `http3_header_field`
and added to `http3_header_data` that corresponds to the PDU.

Occasionally, the dissector can become blocked on the QPACK stream. This
happens when decoding of the headers field depends on a QPACK update that has
not been seen yet. The dissector indicates such condition via the
`http3.header.qpack.blocked` flag.

In addition, sometimes the decoder does can not proceed with decoding. This can
happen, for example, when the start of the QPACK encoder stream is not present
in the capture file.  The dissector indicates such condition via the
`http3.header.qpack.fatal` flag.


In addition to the flags, the dissector emits appropriate expert info when the
decoding is not possible.

### Fields to expose

- `http3.stream_type`
- `http3.frame_type`
- `http3.frame_length`
- `http3.frame_payload`
- `http3.push_id`
- `http3.header` - flag.
- `http3.header.count` - number of fields in the HEADERS frame.
- `http3.header.length` - the length of the fields after inflation.
- `http3.header.name` - header field's name, after inflation.
- `http3.header.name.length` - length of the header fields's name, after inflation.
- `http3.header.value` - header field's value, after inflation.
- `http3.header.value.length` - length of the header fields's value, after inflation.
- `http3.header.qpack.blocked` - inflation of header fields is blocked on QPACK.
- `http3.header.qpack.fatal` - inflation of header fields is not possible.
- `http3.qpack.enc` - flag.
- `http3.qpack.enc.icnt` - the instruction count after processing the QPACK encoder payload.


## Open questions:
1. Where to store the header data that could not be decoded due to QPACK
   insertion count?  Initially, just indicate that it is blocked and append the
   hex data to the headers dissection tree.
2. What happens if after the decoding has finished successfully, the HEADERS
   frame contains more data? This is more relevant to the protocol developers
   and not to the users. Probably should have an Expert info.
