# rs-ipfixrw

Read-write implementation of the IPFIX Protocol/Netflow v10 [\[RFC7011\]](https://www.rfc-editor.org/rfc/rfc7011).

Roughly based on [rs-ipfix](https://github.com/q6r/rs-ipfix), but using [binrw](https://binrw.rs/) instead of nom for read/write capabilities.

## Features

- Reading and writing of IPFIX formatted packets
- Support for all Information Element types, except structured data
  - based on the [iana IPFIX entities registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-information-elements) CSV

## Unimplemented

- "Structured Data" [\[RFC6313\]](https://www.rfc-editor.org/rfc/rfc6313)
