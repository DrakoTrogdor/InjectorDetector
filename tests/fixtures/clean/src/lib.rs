// A trivial library file used to verify that the source extractor walks
// comments and string literals without raising false positives.

/// Returns the sum of two integers.
pub fn add(a: i32, b: i32) -> i32 {
    let label = "result computed";
    let _ = label;
    a + b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_adds() {
        assert_eq!(add(2, 3), 5);
    }
}
