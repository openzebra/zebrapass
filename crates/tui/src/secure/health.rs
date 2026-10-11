//! Vault health: weak, reused, and old passwords.
//!
//! Computed in memory only. Reuse is found by grouping passwords of equal
//! length and comparing each pair in constant time; nothing is hashed and
//! the report holds record ids, never passwords.

use subtle::ConstantTimeEq;

use crate::secure::strength::{estimate, WEAK_BITS};

/// A password is "old" after a year without a new revision.
pub const OLD_AFTER_MS: u64 = 365 * 24 * 3600 * 1000;

/// One record's input to the analysis.
#[derive(Clone, Copy, Debug)]
pub struct Candidate<'a> {
    /// Record id.
    pub id: u32,
    /// Advisory time of the current revision.
    pub timestamp_ms: u64,
    /// The password, if the record has one.
    pub password: Option<&'a [u8]>,
}

/// Findings, as record ids.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HealthReport {
    /// Records with a password under [`WEAK_BITS`].
    pub weak: Box<[u32]>,
    /// Groups of records sharing one password.
    pub reused: Box<[Box<[u32]>]>,
    /// Records not changed for [`OLD_AFTER_MS`].
    pub old: Box<[u32]>,
    /// Passwords used by exactly one record.
    pub unique: usize,
    /// Records that have a password.
    pub with_password: usize,
    /// All records.
    pub total: usize,
    /// 0..=100, higher is healthier.
    pub score: u8,
}

impl HealthReport {
    /// Number of records in any reuse group.
    #[must_use]
    pub fn reused_records(&self) -> usize {
        self.reused.iter().map(|group| group.len()).sum()
    }
}

/// Analyze `candidates` as of `now_ms`.
#[must_use]
pub fn analyze(candidates: &[Candidate<'_>], now_ms: u64) -> HealthReport {
    let with_password: Vec<(u32, &[u8])> = candidates
        .iter()
        .filter_map(|candidate| candidate.password.map(|password| (candidate.id, password)))
        .filter(|(_, password)| !password.is_empty())
        .collect();
    let weak: Box<[u32]> = with_password
        .iter()
        .filter(|(_, password)| estimate(password).bits < WEAK_BITS)
        .map(|(id, _)| *id)
        .collect();
    let old: Box<[u32]> = candidates
        .iter()
        .filter(|candidate| now_ms.saturating_sub(candidate.timestamp_ms) > OLD_AFTER_MS)
        .map(|candidate| candidate.id)
        .collect();
    let reused = reuse_groups(&with_password);
    let reused_count: usize = reused.iter().map(|group| group.len()).sum();
    let mut report = HealthReport {
        weak,
        reused,
        old,
        unique: with_password.len() - reused_count,
        with_password: with_password.len(),
        total: candidates.len(),
        score: 100,
    };
    report.score = score(&report);
    report
}

fn reuse_groups(passwords: &[(u32, &[u8])]) -> Box<[Box<[u32]>]> {
    let mut order: Vec<usize> = (0..passwords.len()).collect();
    order.sort_by_key(|index| {
        passwords
            .get(*index)
            .map_or((0, 0), |(id, password)| (password.len(), *id))
    });
    let mut grouped = vec![false; passwords.len()];
    let mut groups = Vec::new();
    for (position, &first) in order.iter().enumerate() {
        let Some((first_id, first_pw)) = passwords.get(first) else {
            continue;
        };
        if grouped.get(first).copied().unwrap_or(true) {
            continue;
        }
        let mut group = vec![*first_id];
        for &other in order.iter().skip(position + 1) {
            let Some((other_id, other_pw)) = passwords.get(other) else {
                continue;
            };
            if other_pw.len() != first_pw.len() {
                break;
            }
            if !grouped.get(other).copied().unwrap_or(true) && bool::from(first_pw.ct_eq(other_pw))
            {
                group.push(*other_id);
                if let Some(flag) = grouped.get_mut(other) {
                    *flag = true;
                }
            }
        }
        if group.len() > 1 {
            group.sort_unstable();
            groups.push(group.into_boxed_slice());
        }
    }
    groups.into_boxed_slice()
}

fn score(report: &HealthReport) -> u8 {
    if report.total == 0 {
        return 100;
    }
    let wide = |count: usize| u64::try_from(count).unwrap_or(u64::MAX);
    let with_password = wide(report.with_password.max(1));
    let penalty = 40 * wide(report.weak.len()) / with_password
        + 40 * wide(report.reused_records()) / with_password
        + 20 * wide(report.old.len()) / wide(report.total);
    u8::try_from(100u64.saturating_sub(penalty)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "tests may index")]

    use super::{analyze, Candidate, OLD_AFTER_MS};

    #[test]
    fn finds_weak_reused_and_old() {
        let now = 10 * OLD_AFTER_MS;
        let strong = b"k7#Qm2^vR9!pLx@4wZ$e8Nb&".as_slice();
        let candidates = [
            Candidate {
                id: 1,
                timestamp_ms: now,
                password: Some(b"123456"),
            },
            Candidate {
                id: 2,
                timestamp_ms: now,
                password: Some(strong),
            },
            Candidate {
                id: 3,
                timestamp_ms: 0,
                password: Some(strong),
            },
            Candidate {
                id: 4,
                timestamp_ms: now,
                password: None,
            },
            Candidate {
                id: 5,
                timestamp_ms: now,
                password: Some(b"another-strong-Pass#77"),
            },
        ];
        let report = analyze(&candidates, now);
        assert_eq!(&*report.weak, &[1]);
        assert_eq!(report.reused.len(), 1);
        assert_eq!(&*report.reused[0], &[2, 3]);
        assert_eq!(&*report.old, &[3]);
        assert_eq!(report.unique, 2);
        assert_eq!(report.with_password, 4);
        assert!(report.score < 100);
    }
}
