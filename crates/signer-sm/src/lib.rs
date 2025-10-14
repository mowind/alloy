mod error;
pub use error::SmSignerError;

mod signer;

pub use signer::SmSigner;

#[cfg(test)]
mod tests {
    use super::*;
}
