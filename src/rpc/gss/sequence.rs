pub const MAX_WINDOW_SIZE: usize = 4096;

/// RFC 2203 replay window. `accept` must be called only after the request
/// header MIC has been verified successfully.
#[derive(Clone, Debug)]
pub struct SequenceWindow {
    seen: Vec<bool>,
    highest: Option<u32>,
}

impl SequenceWindow {
    pub fn new(size: usize) -> Result<Self, SequenceWindowError> {
        if size == 0 || size > MAX_WINDOW_SIZE {
            return Err(SequenceWindowError::InvalidSize);
        }
        Ok(Self {
            seen: vec![false; size],
            highest: None,
        })
    }

    pub fn size(&self) -> usize {
        self.seen.len()
    }

    pub fn highest(&self) -> Option<u32> {
        self.highest
    }

    pub fn accept(&mut self, sequence: u32) -> Result<(), SequenceWindowError> {
        if sequence >= super::MAX_SEQUENCE_NUMBER {
            return Err(SequenceWindowError::ContextProblem);
        }
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen[0] = true;
            return Ok(());
        };

        if sequence > highest {
            let advance = (sequence - highest) as usize;
            if advance >= self.seen.len() {
                self.seen.fill(false);
            } else {
                let retained = self.seen.len() - advance;
                self.seen.copy_within(..retained, advance);
                self.seen[..advance].fill(false);
            }
            self.highest = Some(sequence);
            self.seen[0] = true;
            return Ok(());
        }

        let offset = (highest - sequence) as usize;
        if offset >= self.seen.len() || self.seen[offset] {
            return Err(SequenceWindowError::Discard);
        }
        self.seen[offset] = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SequenceWindowError {
    #[error("RPCSEC_GSS sequence window size is invalid")]
    InvalidSize,
    #[error("RPCSEC_GSS request is a replay or below the sequence window")]
    Discard,
    #[error("RPCSEC_GSS sequence number exhausted the context")]
    ContextProblem,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_out_of_order_once_within_window() {
        let mut window = SequenceWindow::new(4).unwrap();
        window.accept(10).unwrap();
        window.accept(13).unwrap();
        window.accept(12).unwrap();
        window.accept(11).unwrap();
        assert_eq!(window.accept(12), Err(SequenceWindowError::Discard));
        assert_eq!(window.accept(9), Err(SequenceWindowError::Discard));
    }

    #[test]
    fn large_forward_jump_resets_old_window() {
        let mut window = SequenceWindow::new(4).unwrap();
        window.accept(1).unwrap();
        window.accept(100).unwrap();
        assert_eq!(window.accept(1), Err(SequenceWindowError::Discard));
        assert_eq!(window.accept(99), Ok(()));
    }

    #[test]
    fn maximum_sequence_requires_context_refresh() {
        let mut window = SequenceWindow::new(1).unwrap();
        assert_eq!(window.accept(super::super::MAX_SEQUENCE_NUMBER), Err(SequenceWindowError::ContextProblem));
    }
}
