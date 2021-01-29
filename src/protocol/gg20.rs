pub mod keygen;
mod vss;
mod zkp;

// validate_params helper with custom error type
// TODO enforce a maximum share_count?
pub fn validate_params(
    share_count: usize,
    threshold: usize,
    index: usize,
) -> Result<(), ParamsError> {
    if threshold >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, threshold));
    }
    if index >= share_count {
        return Err(ParamsError::InvalidThreshold(share_count, index));
    }
    Ok(())
}
#[derive(Debug)]
pub enum ParamsError {
    InvalidThreshold(usize, usize), // (share_count, threshold)
    InvalidIndex(usize, usize),     // (share_count, index)
}

impl std::error::Error for ParamsError {}
impl std::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParamsError::InvalidThreshold(share_count, threshold) => write!(
                f,
                "invalid threshold {} for share_count {}",
                threshold, share_count
            ),
            ParamsError::InvalidIndex(share_count, index) => {
                write!(f, "invalid index {} for share_count {}", index, share_count)
            }
        }
    }
}
