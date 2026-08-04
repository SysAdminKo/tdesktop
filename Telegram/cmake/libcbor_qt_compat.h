#pragma once

/*
 * Qt Core statically embeds Intel TinyCBOR, which exports cbor_encode_double
 * under the same C symbol as PJK libcbor (used by vendored libfido2).
 * Force-include this header when compiling lib_fido2 so libcbor's definition
 * and all in-tree call sites are renamed; the final link keeps Qt's TinyCBOR.
 */
#define cbor_encode_double td_libcbor_encode_double
