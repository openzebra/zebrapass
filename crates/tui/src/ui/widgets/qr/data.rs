//! ISO/IEC 18004 version tables, Byte-mode bitstream packing, and Reed-Solomon
//! GF(2^8) error-correction codeword generation.

#[derive(Clone, Copy)]
pub(super) struct VersionSpec {
    pub version: usize,
    pub total_data: usize,
    pub ec_per_block: usize,
    pub g1_blocks: usize,
    pub g1_data: usize,
    pub g2_blocks: usize,
    pub g2_data: usize,
    pub align: &'static [usize],
}

const ALIGN_V1: &[usize] = &[];
const ALIGN_V2: &[usize] = &[6, 18];
const ALIGN_V3: &[usize] = &[6, 22];
const ALIGN_V4: &[usize] = &[6, 26];
const ALIGN_V5: &[usize] = &[6, 30];
const ALIGN_V6: &[usize] = &[6, 34];
const ALIGN_V7: &[usize] = &[6, 22, 38];
const ALIGN_V8: &[usize] = &[6, 24, 42];
const ALIGN_V9: &[usize] = &[6, 26, 46];
const ALIGN_V10: &[usize] = &[6, 28, 50];

pub(super) const SPECS_LOW: [VersionSpec; 10] = [
    VersionSpec {
        version: 1,
        total_data: 19,
        ec_per_block: 7,
        g1_blocks: 1,
        g1_data: 19,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V1,
    },
    VersionSpec {
        version: 2,
        total_data: 34,
        ec_per_block: 10,
        g1_blocks: 1,
        g1_data: 34,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V2,
    },
    VersionSpec {
        version: 3,
        total_data: 55,
        ec_per_block: 15,
        g1_blocks: 1,
        g1_data: 55,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V3,
    },
    VersionSpec {
        version: 4,
        total_data: 80,
        ec_per_block: 20,
        g1_blocks: 1,
        g1_data: 80,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V4,
    },
    VersionSpec {
        version: 5,
        total_data: 108,
        ec_per_block: 26,
        g1_blocks: 1,
        g1_data: 108,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V5,
    },
    VersionSpec {
        version: 6,
        total_data: 136,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 68,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V6,
    },
    VersionSpec {
        version: 7,
        total_data: 156,
        ec_per_block: 20,
        g1_blocks: 2,
        g1_data: 78,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V7,
    },
    VersionSpec {
        version: 8,
        total_data: 194,
        ec_per_block: 24,
        g1_blocks: 2,
        g1_data: 97,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V8,
    },
    VersionSpec {
        version: 9,
        total_data: 232,
        ec_per_block: 30,
        g1_blocks: 2,
        g1_data: 116,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V9,
    },
    VersionSpec {
        version: 10,
        total_data: 274,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 68,
        g2_blocks: 2,
        g2_data: 69,
        align: ALIGN_V10,
    },
];

pub(super) const SPECS_MED: [VersionSpec; 10] = [
    VersionSpec {
        version: 1,
        total_data: 16,
        ec_per_block: 10,
        g1_blocks: 1,
        g1_data: 16,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V1,
    },
    VersionSpec {
        version: 2,
        total_data: 28,
        ec_per_block: 16,
        g1_blocks: 1,
        g1_data: 28,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V2,
    },
    VersionSpec {
        version: 3,
        total_data: 44,
        ec_per_block: 26,
        g1_blocks: 1,
        g1_data: 44,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V3,
    },
    VersionSpec {
        version: 4,
        total_data: 64,
        ec_per_block: 18,
        g1_blocks: 2,
        g1_data: 32,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V4,
    },
    VersionSpec {
        version: 5,
        total_data: 86,
        ec_per_block: 24,
        g1_blocks: 2,
        g1_data: 43,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V5,
    },
    VersionSpec {
        version: 6,
        total_data: 108,
        ec_per_block: 16,
        g1_blocks: 4,
        g1_data: 27,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V6,
    },
    VersionSpec {
        version: 7,
        total_data: 124,
        ec_per_block: 18,
        g1_blocks: 4,
        g1_data: 31,
        g2_blocks: 0,
        g2_data: 0,
        align: ALIGN_V7,
    },
    VersionSpec {
        version: 8,
        total_data: 154,
        ec_per_block: 22,
        g1_blocks: 2,
        g1_data: 38,
        g2_blocks: 2,
        g2_data: 39,
        align: ALIGN_V8,
    },
    VersionSpec {
        version: 9,
        total_data: 182,
        ec_per_block: 22,
        g1_blocks: 3,
        g1_data: 36,
        g2_blocks: 2,
        g2_data: 37,
        align: ALIGN_V9,
    },
    VersionSpec {
        version: 10,
        total_data: 216,
        ec_per_block: 26,
        g1_blocks: 4,
        g1_data: 43,
        g2_blocks: 1,
        g2_data: 44,
        align: ALIGN_V10,
    },
];

pub(super) fn build_codewords(data: &[u8], spec: VersionSpec) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::with_capacity(spec.total_data * 8);
    push_bits(&mut bits, 0b0100, 4);
    let count_bits = if spec.version >= 10 { 16 } else { 8 };
    push_bits(&mut bits, data.len(), count_bits);
    for &byte in data {
        push_bits(&mut bits, usize::from(byte), 8);
    }
    let capacity_bits = spec.total_data * 8;
    let terminator = capacity_bits.saturating_sub(bits.len()).min(4);
    push_bits(&mut bits, 0, terminator);
    while !bits.len().is_multiple_of(8) {
        bits.push(false);
    }
    let mut data_bytes = Vec::with_capacity(spec.total_data);
    for byte_bits in bits.chunks(8) {
        let mut val = 0u8;
        for &bit in byte_bits {
            val = (val << 1) | u8::from(bit);
        }
        data_bytes.push(val);
    }
    let mut pad_toggle = false;
    while data_bytes.len() < spec.total_data {
        data_bytes.push(if pad_toggle { 0x11 } else { 0xEC });
        pad_toggle = !pad_toggle;
    }

    let divisor = rs_divisor(spec.ec_per_block);
    let total_blocks = spec.g1_blocks + spec.g2_blocks;
    let mut blocks: Vec<&[u8]> = Vec::with_capacity(total_blocks);
    let mut ec_blocks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks);
    let mut offset = 0usize;
    for _ in 0..spec.g1_blocks {
        let slice = data_bytes.get(offset..offset + spec.g1_data).unwrap_or(&[]);
        ec_blocks.push(rs_remainder(slice, &divisor));
        blocks.push(slice);
        offset += spec.g1_data;
    }
    for _ in 0..spec.g2_blocks {
        let slice = data_bytes.get(offset..offset + spec.g2_data).unwrap_or(&[]);
        ec_blocks.push(rs_remainder(slice, &divisor));
        blocks.push(slice);
        offset += spec.g2_data;
    }

    let max_data = spec.g1_data.max(spec.g2_data);
    let mut out = Vec::with_capacity(spec.total_data + total_blocks * spec.ec_per_block);
    for i in 0..max_data {
        for block in &blocks {
            if let Some(&byte) = block.get(i) {
                out.push(byte);
            }
        }
    }
    for i in 0..spec.ec_per_block {
        for ec in &ec_blocks {
            if let Some(&byte) = ec.get(i) {
                out.push(byte);
            }
        }
    }
    out
}

fn push_bits(out: &mut Vec<bool>, val: usize, count: usize) {
    for shift in (0..count).rev() {
        out.push(((val >> shift) & 1) != 0);
    }
}

pub(super) const fn gf_mul(mut x: u8, mut y: u8) -> u8 {
    let mut z = 0u8;
    let mut i = 0;
    while i < 8 {
        if (y & 1) != 0 {
            z ^= x;
        }
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 {
            x ^= 0x1D;
        }
        y >>= 1;
        i += 1;
    }
    z
}

fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    if let Some(last) = result.last_mut() {
        *last = 1;
    }
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            let cur = result.get(j).copied().unwrap_or(0);
            let next = result.get(j + 1).copied().unwrap_or(0);
            if let Some(slot) = result.get_mut(j) {
                *slot = gf_mul(cur, root) ^ next;
            }
        }
        root = gf_mul(root, 2);
    }
    result
}

fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut rem = vec![0u8; divisor.len()];
    for &byte in data {
        let factor = byte ^ rem.first().copied().unwrap_or(0);
        rem.rotate_left(1);
        if let Some(last) = rem.last_mut() {
            *last = 0;
        }
        for (slot, &coef) in rem.iter_mut().zip(divisor.iter()) {
            *slot ^= gf_mul(coef, factor);
        }
    }
    rem
}
