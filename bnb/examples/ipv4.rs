//! **IPv4 header** — a real wire-format parser, end to end.
//!
//! One `#[bin]` message folds three `#[bitfield]`s and a `#[derive(BitEnum)]`, recomputes
//! the header checksum on write (`calc`), maps the raw address words to real
//! `std::net::Ipv4Addr`s (`map`), and round-trips a captured packet **byte-identically**
//! in both directions. It also shows the dual-use property: an unknown protocol number
//! is preserved, not rejected.
//!
//! The header types below are `no_std`-portable (decode from `&[u8]`, encode to `Vec`);
//! only this `main` (printing + sockets-free) needs `std`.
//!
//! Run with: `cargo run -p bitsandbytes --example ipv4`

use bnb::{BitEnum, bin, bitfield, u2, u4, u6, u13};
use std::net::Ipv4Addr;

// --- sub-byte structure, packed into byte-aligned bitfields ---------------------

/// First byte: 4-bit version + 4-bit header length (IHL), MSB-first.
#[bitfield(u8, bits = msb)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VersionIhl {
    version: u4,
    ihl: u4,
}

/// Type-of-service byte: a 6-bit DSCP class + a 2-bit ECN enum.
#[bitfield(u8, bits = msb)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tos {
    dscp: u6,
    ecn: Ecn,
}

/// 2-bit ECN — a fully-covered enum (all four values), so it needs no `catch_all`.
#[derive(BitEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[bit_enum(u2)]
enum Ecn {
    NotEct,
    Ect1,
    Ect0,
    Ce,
}

/// The flags + 13-bit fragment offset, packed into one 16-bit word (MSB-first).
#[bitfield(u16, bits = msb)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FlagsFrag {
    reserved: bool, // the "evil bit" (RFC 3514), always 0
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u13,
}

/// IP protocol numbers. The `catch_all` preserves any value we don't name (dual-use);
/// the values are non-contiguous, so this needs an explicit `#[repr(u8)]`.
#[derive(BitEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[bit_enum(u8)]
#[repr(u8)]
enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    #[catch_all]
    Other(u8),
}

// --- the whole-message codec ----------------------------------------------------

/// A 20-byte IPv4 header (no options). `#[bin(big)]` because IP is network byte order.
/// The `checksum` is read and kept (so you can validate it), but `calc` recomputes it on
/// every write, so it can never silently drift from the header it protects.
#[bin(big)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ipv4Header {
    ver_ihl: VersionIhl,
    tos: Tos,
    total_length: u16,
    identification: u16,
    flags_frag: FlagsFrag,
    ttl: u8,
    protocol: Protocol,
    // Stored on read so you can inspect/validate the on-wire value, but recomputed on
    // write: `calc` overrides whatever is in the field, so the checksum can't drift.
    #[bw(calc = self.header_checksum())]
    checksum: u16,
    // The wire repr is a big-endian `u32`; `map` turns it into a real `Ipv4Addr`.
    #[br(map = |raw: u32| Ipv4Addr::from(raw))]
    #[bw(map = |ip: &Ipv4Addr| u32::from(*ip))]
    src: Ipv4Addr,
    #[br(map = |raw: u32| Ipv4Addr::from(raw))]
    #[bw(map = |ip: &Ipv4Addr| u32::from(*ip))]
    dst: Ipv4Addr,
}

impl Ipv4Header {
    /// RFC 791 header checksum: the one's-complement of the one's-complement sum of the
    /// header's 16-bit words (the checksum field taken as zero). Computed from the
    /// fields — never by re-encoding, which would recurse back through `calc`.
    fn header_checksum(&self) -> u16 {
        let words = [
            (u16::from(self.ver_ihl.raw()) << 8) | u16::from(self.tos.raw()),
            self.total_length,
            self.identification,
            self.flags_frag.raw(),
            (u16::from(self.ttl) << 8) | u16::from(u8::from(self.protocol)),
            // (checksum word is zero for the computation)
            (u32::from(self.src) >> 16) as u16,
            u32::from(self.src) as u16,
            (u32::from(self.dst) >> 16) as u16,
            u32::from(self.dst) as u16,
        ];
        let mut sum: u32 = words.iter().map(|&w| u32::from(w)).sum();
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The canonical RFC 791 / Wikipedia checksum example header (192.168.0.1 → .199, UDP).
    let wire: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    // Decode the whole header in one call.
    let hdr = Ipv4Header::decode_exact(&wire)?;
    println!("IPv4 {} → {}", hdr.src, hdr.dst);
    println!(
        "  version={} ihl={} ttl={} protocol={:?}",
        hdr.ver_ihl.version(),
        hdr.ver_ihl.ihl(),
        hdr.ttl,
        hdr.protocol,
    );
    println!(
        "  DF={} MF={} fragment_offset={} dscp={} ecn={:?}",
        hdr.flags_frag.dont_fragment(),
        hdr.flags_frag.more_fragments(),
        hdr.flags_frag.fragment_offset(),
        hdr.tos.dscp(),
        hdr.tos.ecn(),
    );
    assert_eq!(hdr.src, Ipv4Addr::new(192, 168, 0, 1)); // the `map` produced a real address
    assert_eq!(hdr.protocol, Protocol::Udp);
    assert!(hdr.flags_frag.dont_fragment());

    // The on-wire checksum is kept (it's a stored field), so we can validate it.
    assert_eq!(hdr.checksum, hdr.header_checksum());
    println!("  on-wire checksum 0x{:04x} is valid ✓", hdr.checksum);

    // Re-encode. The checksum isn't stored — `calc` recomputes it from the other fields —
    // yet we get the exact original bytes back, which proves our checksum equals 0xb861.
    let reencoded = hdr.to_bytes()?;
    assert_eq!(reencoded, wire, "round-trip must be byte-identical");
    println!(
        "  re-encoded byte-identical (checksum 0x{:02x}{:02x} recomputed) ✓",
        wire[10], wire[11],
    );

    // Construct a fresh TCP header. The `checksum` we put here is a placeholder — `calc`
    // recomputes it on encode — so a deliberately-wrong value still produces a correct
    // packet on the wire.
    let built = Ipv4Header {
        ver_ihl: VersionIhl::new()
            .with_version(u4::new(4))
            .with_ihl(u4::new(5)),
        tos: Tos::new(),
        total_length: 40,
        identification: 0,
        flags_frag: FlagsFrag::new().with_dont_fragment(true),
        ttl: 64,
        protocol: Protocol::Tcp,
        checksum: 0xDEAD, // ignored — `calc` overwrites it
        src: Ipv4Addr::new(10, 0, 0, 1),
        dst: Ipv4Addr::new(10, 0, 0, 2),
    };
    let built_bytes = built.to_bytes()?;
    let on_wire = Ipv4Header::decode_exact(&built_bytes)?;
    println!(
        "  built a TCP header with checksum 0xDEAD; on the wire it's 0x{:04x} ✓",
        on_wire.checksum,
    );
    assert_eq!(on_wire.checksum, on_wire.header_checksum()); // the recomputed one is valid
    assert_ne!(on_wire.checksum, 0xDEAD); // the placeholder did not reach the wire

    // Dual-use: an unknown protocol number is preserved, not rejected.
    let mut exotic = wire;
    exotic[9] = 0xFD; // an experimental protocol number not in our enum
    let parsed = Ipv4Header::decode_exact(&exotic)?;
    assert_eq!(parsed.protocol, Protocol::Other(0xFD));
    println!(
        "  unknown protocol 0xFD preserved as {:?} (catch_all) ✓",
        parsed.protocol
    );

    println!("all checks passed ✓");
    Ok(())
}
