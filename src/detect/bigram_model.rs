//! Character-bigram language model.
//!
//! Built once at process start from an embedded English corpus and used by
//! the perplexity detector to score chunks. The model is intentionally
//! tiny — a 27×27 transition table over `[a-z]` plus a "space" bin —
//! which is enough to clearly distinguish ordinary prose / source code
//! from obfuscated, encoded, or random content without shipping a model
//! file.

use std::sync::OnceLock;

const ALPHABET: usize = 27; // 26 letters + space
const TRAINING_CORPUS: &str = include_str!("bigram_corpus.txt");

pub struct BigramModel {
    /// log P(next | prev), one row per `prev` symbol.
    log_prob: Vec<f64>,
}

impl BigramModel {
    pub fn global() -> &'static BigramModel {
        static MODEL: OnceLock<BigramModel> = OnceLock::new();
        MODEL.get_or_init(BigramModel::train_from_corpus)
    }

    fn train_from_corpus() -> BigramModel {
        let mut counts = vec![1.0f64; ALPHABET * ALPHABET]; // Laplace prior
        let bytes = TRAINING_CORPUS.as_bytes();
        if bytes.len() >= 2 {
            let mut prev = symbol(bytes[0]);
            for &b in &bytes[1..] {
                let cur = symbol(b);
                counts[prev * ALPHABET + cur] += 1.0;
                prev = cur;
            }
        }

        let mut log_prob = vec![0.0f64; ALPHABET * ALPHABET];
        for prev in 0..ALPHABET {
            let row_start = prev * ALPHABET;
            let row_end = row_start + ALPHABET;
            let total: f64 = counts[row_start..row_end].iter().sum();
            for cur in 0..ALPHABET {
                log_prob[row_start + cur] = (counts[row_start + cur] / total).ln();
            }
        }
        BigramModel { log_prob }
    }

    /// Average per-symbol negative log-likelihood (nats) of `text` under the
    /// bigram model. Higher values mean the text is *less* like the
    /// training corpus and therefore more suspicious. Returns `None` for
    /// inputs too short to score reliably.
    pub fn score(&self, text: &str) -> Option<f64> {
        let bytes = text.as_bytes();
        if bytes.len() < 2 {
            return None;
        }
        let mut total = 0.0;
        let mut n = 0usize;
        let mut prev = symbol(bytes[0]);
        for &b in &bytes[1..] {
            let cur = symbol(b);
            total -= self.log_prob[prev * ALPHABET + cur];
            n += 1;
            prev = cur;
        }
        if n == 0 {
            None
        } else {
            Some(total / n as f64)
        }
    }
}

fn symbol(b: u8) -> usize {
    let lower = b.to_ascii_lowercase();
    if lower.is_ascii_lowercase() {
        (lower - b'a') as usize
    } else {
        26 // everything else (space, digits, punctuation, non-ASCII) → "space"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_prose_scores_lower_than_random() {
        let m = BigramModel::global();
        let prose = "the quick brown fox jumps over the lazy dog and then naps in the sun";
        let random = "qzj4#xv*pzqx@kj!fz%qx*qzpx&qzpx@!@#qzj4xvpz";
        let prose_score = m.score(prose).unwrap();
        let random_score = m.score(random).unwrap();
        assert!(
            prose_score < random_score,
            "expected prose ({prose_score}) < random ({random_score})"
        );
    }
}
