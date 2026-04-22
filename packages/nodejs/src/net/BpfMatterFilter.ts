/**
 * @license
 * Copyright 2022-2026 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Logger } from "@matter/general";
import { createRequire } from "node:module";
import type * as dgram from "node:dgram";

const logger = Logger.get("BpfMatterFilter");

const SOL_SOCKET = 1;
const SO_ATTACH_FILTER = 26;

/**
 * cBPF filter for mDNS packets. Passes Matter-related traffic; drops the rest.
 *
 * At SOCK_DGRAM level, BPF sees: [UDP header (8 bytes)] + [DNS payload].
 * Offset 20 = UDP(8) + DNS-header(12) = first label length byte of the first DNS name.
 * Offset 21 = first character of that label.
 *
 * Pass conditions (evaluated in order):
 *   1. Compressed pointer (high bit of length byte set) — pass unconditionally; these
 *      appear in responses and cannot be inspected without following the pointer.
 *   2. First label length == 33 — pass unconditionally.  Matter operational device
 *      instance names are always exactly 33 characters in the form
 *      XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX (two 16-char zero-padded hex fields separated
 *      by '-').  No common non-Matter mDNS service uses a 33-character label.
 *   3. First label length == 16 — pass unconditionally.  Matter commissionable and
 *      commissioner device instance names are exactly 16 uppercase hex characters
 *      (8 random bytes).  This covers queries and responses for instance SRV/TXT
 *      records such as XXXXXXXXXXXXXXXX._matterc._udp.local.
 *   4. First label '_' + second char uppercase A–Z — pass.  All Matter commissioning
 *      subtypes start with '_' followed by an uppercase letter: _CM, _I<fabric>,
 *      _V<vendor>, _T<devtype>, _S<shortdisc>, _L<longdisc>.  No common non-Matter
 *      service uses this pattern (IANA registry names are lowercase).
 *   5. First label starts with "_mat" — pass.  Matches _matter._tcp and _matterc._udp
 *      (and _matterd._udp).
 *   6. Everything else — drop.  This covers _airplay, _googlecast, _raop, _ipp, etc.
 *
 * 16 instructions, evaluated entirely in the kernel before any recvmsg wakeup.
 */
const FILTER_INSTRUCTIONS: [code: number, jt: number, jf: number, k: number][] = [
    //  n  opcode  jt   jf   k
    [0x30, 0,   0,   20],    //  0: ldb [20]            load first label length byte
    [0x45, 13,  0,   0x80],  //  1: jset 0x80, +13      compressed pointer → PASS (inst 15)
    [0x15, 12,  0,   33],    //  2: jeq 33,  +12         length==33 → PASS (inst 15) — operational instance names
    [0x15, 11,  0,   16],    //  3: jeq 16,  +11         length==16 → PASS (inst 15) — commissionable/commissioner instance names
    [0x30, 0,   0,   21],    //  4: ldb [21]             load first label first char
    [0x15, 0,   8,   0x5f],  //  5: jeq '_', +0, +8     not '_' → DROP (inst 14)
    [0x30, 0,   0,   22],    //  6: ldb [22]             load second char of first label
    [0x35, 0,   6,   0x41],  //  7: jge 'A', +0, +6     < 'A' → DROP (inst 14)
    [0x25, 0,   6,   0x5a],  //  8: jgt 'Z', +0, +6     > 'Z' (lowercase) → continue; ≤ 'Z' → PASS (inst 15)
    [0x15, 0,   4,   0x6d],  //  9: jeq 'm', +0, +4     ≠ 'm' → DROP (inst 14)
    [0x30, 0,   0,   23],    // 10: ldb [23]             load third char
    [0x15, 0,   2,   0x61],  // 11: jeq 'a', +0, +2     ≠ 'a' → DROP (inst 14)
    [0x30, 0,   0,   24],    // 12: ldb [24]             load fourth char
    [0x15, 1,   0,   0x74],  // 13: jeq 't', +1, +0     't' → PASS (inst 15); else DROP (inst 14)
    [0x06, 0,   0,   0],     // 14: ret 0               DROP
    [0x06, 0,   0,   0xffff],// 15: ret 0xffff          PASS
];

// Node.js dgram socket exposes the raw fd via an internal handle not in public typings.
interface SocketWithHandle {
    _handle?: { fd?: number };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyFn = (...args: any[]) => any;

interface KoffiFunctions {
    alloc: (type: string, count: number) => object;
    address: (ptr: object) => bigint;
    free: (ptr: object) => void;
    memcpy: AnyFn;
    setsockopt: AnyFn;
}

let initAttempted = false;
let ffi: KoffiFunctions | undefined;

function initFfi(): KoffiFunctions | undefined {
    if (initAttempted) return ffi;
    initAttempted = true;

    if (process.platform !== "linux") return undefined;

    // TODO: add sock_fprog layout support for 32-bit (arm) — pointer size differs
    if (process.arch !== "x64") return undefined;

    try {
        // koffi is a CJS module; use createRequire for ESM interop
        const _require = createRequire(import.meta.url);
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const koffi = _require("koffi") as any;
        // null = dlopen(NULL): searches already-loaded libs including whichever libc
        // is present (glibc or musl), without naming a specific soname.
        const libc = koffi.load(null);
        ffi = {
            alloc: koffi.alloc.bind(koffi),
            address: koffi.address.bind(koffi),
            free: koffi.free.bind(koffi),
            memcpy: libc.func("void* memcpy(void* dest, const void* src, size_t n)"),
            setsockopt: libc.func("int setsockopt(int fd, int level, int optname, const void* optval, uint32 optlen)"),
        };
        return ffi;
    } catch (error) {
        logger.debug("BPF filter unavailable (koffi load failed):", error);
        return undefined;
    }
}

/**
 * Attach a cBPF socket filter to an mDNS UDP socket.
 *
 * Packets are passed if: the first DNS label is a compressed pointer; the first label
 * is exactly 33 characters long (the fixed format of Matter operational instance names,
 * e.g. XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX._matter._tcp.local); the first label is
 * exactly 16 characters long (Matter commissionable/commissioner instance IDs, e.g.
 * XXXXXXXXXXXXXXXX._matterc._udp.local); the first label starts with '_' followed by
 * an uppercase letter (Matter commissioning subtypes such as _CM, _I*, _V*, _T*, _S*,
 * _L*); or the first label starts with "_mat" (_matter, _matterc, _matterd).  All
 * other mDNS traffic (e.g. _airplay, _googlecast, _raop) is dropped in the kernel,
 * eliminating unnecessary epoll wakeups and recvmsg overhead.
 *
 * This function is a no-op on non-Linux or non-x86-64 platforms, or when koffi is
 * unavailable, so callers need not guard it themselves.
 */
export function attachBpfMatterFilter(socket: dgram.Socket): void {
    const k = initFfi();
    if (k === undefined) return;

    const fd = (socket as unknown as SocketWithHandle)._handle?.fd;
    if (fd === undefined || fd < 0) {
        logger.debug("BPF filter: could not read socket fd");
        return;
    }

    try {
        const numInsns = FILTER_INSTRUCTIONS.length;

        // Build the sock_filter array: numInsns × 8 bytes each
        const filterBuf = Buffer.alloc(numInsns * 8);
        for (let i = 0; i < numInsns; i++) {
            const [code, jt, jf, kVal] = FILTER_INSTRUCTIONS[i];
            filterBuf.writeUInt16LE(code, i * 8 + 0);
            filterBuf.writeUInt8(jt, i * 8 + 2);
            filterBuf.writeUInt8(jf, i * 8 + 3);
            filterBuf.writeUInt32LE(kVal, i * 8 + 4);
        }

        // Copy the filter into koffi-managed memory to obtain a stable pointer
        const filterMem = k.alloc("uint8", filterBuf.length);
        k.memcpy(filterMem, filterBuf, filterBuf.length);

        // Build sock_fprog for x86-64: { uint16 len; uint8[6] pad; uint64 filter_ptr }
        const fprog = Buffer.alloc(16, 0);
        fprog.writeUInt16LE(numInsns, 0);
        fprog.writeBigUInt64LE(k.address(filterMem), 8);

        const rc: number = k.setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, fprog, fprog.length);
        k.free(filterMem);

        if (rc === 0) {
            logger.debug(`BPF matter filter attached (fd=${fd}, ${numInsns} instructions)`);
        } else {
            logger.debug(`BPF filter setsockopt failed: fd=${fd} rc=${rc}`);
        }
    } catch (error) {
        logger.debug("BPF filter attach error:", error);
    }
}
