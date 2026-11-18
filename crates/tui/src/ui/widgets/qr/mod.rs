//! Zero-dependency ISO/IEC 18004 QR Code encoder (Versions 1–10, Byte mode).

mod data;
pub mod render;

#[cfg(test)]
mod tests;

use data::{SPECS_LOW, SPECS_MED, VersionSpec, build_codewords};

/// Error-correction level.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ecc {
    /// ~7% recovery capacity.
    Low,
    /// ~15% recovery capacity.
    Medium,
}

impl Ecc {
    const fn format_bits(self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Medium => 0,
        }
    }
}

/// Square QR symbol matrix (`true` = dark module, `false` = light module).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QrMatrix {
    size: usize,
    modules: Box<[bool]>,
}

impl QrMatrix {
    /// Width and height in modules (`21..=57`).
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Module state at `(x, y)` (`false` when out of bounds).
    #[must_use]
    pub fn get(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules
            .get(y * self.size + x)
            .copied()
            .unwrap_or(false)
    }
}

/// Encode `data` in Byte mode at error-correction level `ecc`.
/// Returns `None` if `data` exceeds Version 10 capacity.
#[must_use]
pub fn encode(data: &[u8], ecc: Ecc) -> Option<QrMatrix> {
    let table = match ecc {
        Ecc::Low => &SPECS_LOW,
        Ecc::Medium => &SPECS_MED,
    };
    let spec = table.iter().find(|s| {
        let count_bits = if s.version >= 10 { 16 } else { 8 };
        4 + count_bits + data.len().saturating_mul(8) <= s.total_data * 8
    })?;
    let codewords = build_codewords(data, *spec);
    let size = spec.version * 4 + 17;
    let mut canvas = Canvas::new(size);
    canvas.draw_function_patterns(*spec);
    canvas.draw_codewords(&codewords);
    let mut best_mask = 0u32;
    let mut min_penalty = u32::MAX;
    for mask in 0..8u32 {
        canvas.apply_mask(mask);
        canvas.draw_format_bits(ecc, mask);
        let penalty = canvas.penalty_score();
        if penalty < min_penalty {
            min_penalty = penalty;
            best_mask = mask;
        }
        canvas.apply_mask(mask);
    }
    canvas.apply_mask(best_mask);
    canvas.draw_format_bits(ecc, best_mask);
    Some(QrMatrix {
        size,
        modules: canvas.modules.into_boxed_slice(),
    })
}

struct Canvas {
    size: usize,
    modules: Vec<bool>,
    is_func: Vec<bool>,
}

impl Canvas {
    fn new(size: usize) -> Self {
        Self {
            size,
            modules: vec![false; size * size],
            is_func: vec![false; size * size],
        }
    }

    fn get(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        self.modules
            .get(y * self.size + x)
            .copied()
            .unwrap_or(false)
    }

    fn is_function(&self, x: usize, y: usize) -> bool {
        if x >= self.size || y >= self.size {
            return true;
        }
        self.is_func.get(y * self.size + x).copied().unwrap_or(true)
    }

    fn set_raw(&mut self, x: usize, y: usize, dark: bool) {
        if x < self.size
            && y < self.size
            && let Some(slot) = self.modules.get_mut(y * self.size + x)
        {
            *slot = dark;
        }
    }

    fn set_func(&mut self, x: usize, y: usize, dark: bool) {
        if x < self.size && y < self.size {
            let idx = y * self.size + x;
            if let Some(slot) = self.modules.get_mut(idx) {
                *slot = dark;
            }
            if let Some(slot) = self.is_func.get_mut(idx) {
                *slot = true;
            }
        }
    }

    fn draw_function_patterns(&mut self, spec: VersionSpec) {
        for i in 0..self.size {
            self.set_func(6, i, i % 2 == 0);
            self.set_func(i, 6, i % 2 == 0);
        }
        self.draw_finder(3, 3);
        self.draw_finder(self.size - 4, 3);
        self.draw_finder(3, self.size - 4);
        let last = self.size - 7;
        for &cy in spec.align {
            for &cx in spec.align {
                let overlaps_finder =
                    (cx == 6 && (cy == 6 || cy == last)) || (cx == last && cy == 6);
                if !overlaps_finder {
                    self.draw_alignment(cx, cy);
                }
            }
        }
        self.draw_format_bits(Ecc::Low, 0);
        self.draw_version(spec.version);
    }

    fn draw_finder(&mut self, cx: usize, cy: usize) {
        for dy in -4isize..=4 {
            for dx in -4isize..=4 {
                let dist = dx.abs().max(dy.abs());
                let dark = dist != 2 && dist != 4;
                if let (Ok(x), Ok(y)) = (
                    usize::try_from(cx.cast_signed() + dx),
                    usize::try_from(cy.cast_signed() + dy),
                ) && x < self.size
                    && y < self.size
                {
                    self.set_func(x, y, dark);
                }
            }
        }
    }

    fn draw_alignment(&mut self, cx: usize, cy: usize) {
        for dy in -2isize..=2 {
            for dx in -2isize..=2 {
                let dist = dx.abs().max(dy.abs());
                if let (Ok(x), Ok(y)) = (
                    usize::try_from(cx.cast_signed() + dx),
                    usize::try_from(cy.cast_signed() + dy),
                ) {
                    self.set_func(x, y, dist != 1);
                }
            }
        }
    }

    fn draw_format_bits(&mut self, ecc: Ecc, mask: u32) {
        let data = (ecc.format_bits() << 3) | mask;
        let mut rem = data;
        for _ in 0..10 {
            rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        }
        let bits = ((data << 10) | rem) ^ 0x5412;
        for i in 0..6 {
            self.set_func(8, i, ((bits >> i) & 1) != 0);
        }
        self.set_func(8, 7, ((bits >> 6) & 1) != 0);
        self.set_func(8, 8, ((bits >> 7) & 1) != 0);
        self.set_func(7, 8, ((bits >> 8) & 1) != 0);
        for i in 9..15 {
            self.set_func(14 - i, 8, ((bits >> i) & 1) != 0);
        }
        for i in 0..8 {
            self.set_func(self.size - 1 - i, 8, ((bits >> i) & 1) != 0);
        }
        for i in 8..15 {
            self.set_func(8, self.size - 15 + i, ((bits >> i) & 1) != 0);
        }
        self.set_func(8, self.size - 8, true);
    }

    fn draw_version(&mut self, version: usize) {
        if version < 7 {
            return;
        }
        let data = u32::try_from(version).unwrap_or(0);
        let mut rem = data;
        for _ in 0..12 {
            rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        }
        let bits = (data << 12) | rem;
        for i in 0..18usize {
            let bit = ((bits >> i) & 1) != 0;
            let a = self.size - 11 + i % 3;
            let b = i / 3;
            self.set_func(a, b, bit);
            self.set_func(b, a, bit);
        }
    }

    fn draw_codewords(&mut self, data: &[u8]) {
        let total_bits = data.len() * 8;
        let mut bit_idx = 0usize;
        let mut right = self.size.cast_signed() - 1;
        while right >= 1 {
            if right == 6 {
                right = 5;
            }
            for vert in 0..self.size {
                for j in 0..2isize {
                    let Ok(x) = usize::try_from(right - j) else {
                        continue;
                    };
                    let upward = ((right + 1) & 2) == 0;
                    let y = if upward { self.size - 1 - vert } else { vert };
                    if !self.is_function(x, y) && bit_idx < total_bits {
                        let byte = data.get(bit_idx >> 3).copied().unwrap_or(0);
                        let bit = ((byte >> (7 - (bit_idx & 7))) & 1) != 0;
                        self.set_raw(x, y, bit);
                        bit_idx += 1;
                    }
                }
            }
            right -= 2;
        }
    }

    fn apply_mask(&mut self, mask: u32) {
        for y in 0..self.size {
            for x in 0..self.size {
                if self.is_function(x, y) {
                    continue;
                }
                let invert = match mask {
                    0 => (x + y).is_multiple_of(2),
                    1 => y.is_multiple_of(2),
                    2 => x.is_multiple_of(3),
                    3 => (x + y).is_multiple_of(3),
                    4 => (x / 3 + y / 2).is_multiple_of(2),
                    5 => (x * y) % 2 + (x * y) % 3 == 0,
                    6 => ((x * y) % 2 + (x * y) % 3).is_multiple_of(2),
                    _ => ((x + y) % 2 + (x * y) % 3).is_multiple_of(2),
                };
                if invert {
                    let cur = self.get(x, y);
                    self.set_raw(x, y, !cur);
                }
            }
        }
    }

    fn penalty_score(&self) -> u32 {
        let mut penalty = 0u32;
        for y in 0..self.size {
            penalty += self.line_penalty(|x| self.get(x, y));
        }
        for x in 0..self.size {
            penalty += self.line_penalty(|y| self.get(x, y));
        }
        for y in 0..self.size.saturating_sub(1) {
            for x in 0..self.size.saturating_sub(1) {
                let c = self.get(x, y);
                if c == self.get(x + 1, y) && c == self.get(x, y + 1) && c == self.get(x + 1, y + 1)
                {
                    penalty += 3;
                }
            }
        }
        let dark = self.modules.iter().filter(|&&m| m).count();
        let total = self.size * self.size;
        let k = ((dark * 20).abs_diff(total * 10)) / total;
        penalty += u32::try_from(k).unwrap_or(0) * 10;
        penalty
    }

    fn line_penalty(&self, at: impl Fn(usize) -> bool) -> u32 {
        let mut penalty = 0u32;
        let mut run_color = false;
        let mut run_len = 0u32;
        let mut hist = [0u32; 7];
        for i in 0..self.size {
            let color = at(i);
            if color == run_color {
                run_len += 1;
                if run_len == 5 {
                    penalty += 3;
                } else if run_len > 5 {
                    penalty += 1;
                }
            } else {
                penalty += count_finder_patterns(run_color, run_len, &mut hist);
                run_color = color;
                run_len = 1;
            }
        }
        penalty + count_finder_patterns(run_color, run_len, &mut hist)
    }
}

fn count_finder_patterns(color: bool, len: u32, hist: &mut [u32; 7]) -> u32 {
    if !color {
        hist.rotate_right(1);
        hist[0] = len;
        return check_finder_hist(hist);
    }
    hist.rotate_right(1);
    hist[0] = len;
    0
}

fn check_finder_hist(hist: &[u32; 7]) -> u32 {
    let n = hist[1];
    let ok = n > 0
        && hist[2] == n
        && hist[3] == n * 3
        && hist[4] == n
        && hist[5] == n
        && (hist[0] >= n * 4 || hist[6] >= n * 4);
    u32::from(ok) * 40
}
