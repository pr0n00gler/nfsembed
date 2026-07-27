use bytes::{Bytes, BytesMut};

static XDR_PADDING: [u8; 3] = [0; 3];

/// An encoded RPC reply composed of immutable buffers in wire order.
///
/// NFSv4 COMPOUND replies may contain more than one large READ payload, so a
/// reply cannot be represented as only `prefix + payload + padding`. Cloning
/// a reply remains shallow regardless of the number of segments.
#[derive(Clone, Debug)]
pub struct EncodedReply {
    segments: Vec<Bytes>,
    len: usize,
    // `Some` means the complete backing allocation is known and safe to
    // charge directly to the replay cache. Unknown `Bytes` owners must first
    // be compacted because a short slice can pin a much larger allocation.
    retained_bytes: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplyBuildError {
    #[error("encoded RPC reply length overflow")]
    LengthOverflow,
}

impl EncodedReply {
    /// Creates a reply whose protocol prefix and opaque payload can be written
    /// as separate buffers. `padding` is the trailing XDR padding byte count.
    pub fn segmented(prefix: Bytes, payload: Bytes, padding: usize) -> Self {
        assert!(padding <= XDR_PADDING.len());
        let mut segments = Vec::with_capacity(if padding == 0 { 2 } else { 3 });
        segments.push(prefix);
        segments.push(payload);
        if padding != 0 {
            segments.push(Bytes::from_static(&XDR_PADDING).slice(..padding));
        }
        Self::try_from_segments(segments).expect("validated RPC reply length")
    }

    /// Creates a reply from an arbitrary number of immutable wire segments.
    ///
    /// Empty segments are retained so callers can keep stable segment
    /// positions while constructing a reply. The transport skips them.
    pub fn try_from_segments(segments: impl IntoIterator<Item = Bytes>) -> Result<Self, ReplyBuildError> {
        let segments: Vec<_> = segments.into_iter().collect();
        let len = segments
            .iter()
            .try_fold(0usize, |len, segment| len.checked_add(segment.len()))
            .ok_or(ReplyBuildError::LengthOverflow)?;
        Ok(Self {
            segments,
            len,
            retained_bytes: None,
        })
    }

    /// Returns the encoded wire length, including XDR padding.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the encoded wire representation is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the immutable buffers in wire order for vectored transport.
    pub fn segments(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.segments.iter().map(Bytes::as_ref)
    }

    /// Returns the number of immutable buffers in the encoded reply.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the protocol prefix used for status extraction and tracing.
    pub fn prefix(&self) -> &[u8] {
        self.segments.first().map_or(&[], Bytes::as_ref)
    }

    pub(crate) fn replay_storage_requires_copy(&self) -> bool {
        self.retained_bytes.is_none()
    }

    /// Produces cache-owned storage with a known allocation charge. Replies
    /// created from an owned `Vec` can remain shallow; replies backed by an
    /// arbitrary `Bytes` owner are compacted so a small slice cannot pin an
    /// unaccounted large allocation for the replay TTL.
    pub(crate) fn replay_storage(&self) -> (Self, usize) {
        if let Some(retained_bytes) = self.retained_bytes {
            return (self.clone(), retained_bytes);
        }

        let mut compacted = Vec::with_capacity(self.segments.len());
        let mut retained_bytes = 0usize;
        for segment in &self.segments {
            let (segment, segment_bytes) = compact_bytes(segment);
            retained_bytes = retained_bytes.saturating_add(segment_bytes);
            compacted.push(segment);
        }
        retained_bytes = retained_bytes.max(self.len);
        (
            Self {
                segments: compacted,
                len: self.len,
                retained_bytes: Some(retained_bytes),
            },
            retained_bytes,
        )
    }

    /// Coalesces the reply when a consumer specifically requires contiguous
    /// storage. The production transport writes `segments` directly.
    pub fn into_bytes(self) -> Bytes {
        let mut segments = self.segments;
        if segments.len() == 1 {
            return segments.pop().expect("one reply segment");
        }
        let mut output = BytesMut::with_capacity(self.len);
        for segment in segments {
            output.extend_from_slice(&segment);
        }
        output.freeze()
    }
}

impl From<Bytes> for EncodedReply {
    fn from(value: Bytes) -> Self {
        Self {
            len: value.len(),
            segments: vec![value],
            retained_bytes: None,
        }
    }
}

impl From<Vec<u8>> for EncodedReply {
    fn from(value: Vec<u8>) -> Self {
        let retained_bytes = value.capacity();
        let len = value.len();
        Self {
            segments: vec![Bytes::from(value)],
            len,
            retained_bytes: Some(retained_bytes),
        }
    }
}

fn compact_bytes(input: &[u8]) -> (Bytes, usize) {
    let mut output = Vec::with_capacity(input.len());
    output.extend_from_slice(input);
    let retained_bytes = output.capacity();
    (Bytes::from(output), retained_bytes)
}

impl PartialEq for EncodedReply {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut left = self.segments().flat_map(|segment| segment.iter());
        let mut right = other.segments().flat_map(|segment| segment.iter());
        left.by_ref().eq(right.by_ref())
    }
}

impl Eq for EncodedReply {}

impl PartialEq<Bytes> for EncodedReply {
    fn eq(&self, other: &Bytes) -> bool {
        self.len() == other.len() && self.segments().flat_map(|segment| segment.iter()).eq(other.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segmented_reply_coalesces_without_changing_wire_bytes() {
        let reply = EncodedReply::segmented(Bytes::from_static(b"prefix"), Bytes::from_static(b"data"), 3);
        assert_eq!(reply.len(), 13);
        assert_eq!(reply.clone().into_bytes(), Bytes::from_static(b"prefixdata\0\0\0"));
        assert_eq!(reply, EncodedReply::from(b"prefixdata\0\0\0".to_vec()));
    }

    #[test]
    fn vec_backing_capacity_is_charged_without_copying() {
        let mut value = Vec::with_capacity(1024);
        value.extend_from_slice(b"data");
        let pointer = value.as_ptr();
        let reply = EncodedReply::from(value);
        let (cached, retained_bytes) = reply.replay_storage();
        assert_eq!(cached.segments().next().unwrap().as_ptr(), pointer);
        assert!(retained_bytes >= 1024);
    }

    #[test]
    fn supports_multiple_read_payload_segments() {
        let reply = EncodedReply::try_from_segments([
            Bytes::from_static(b"rpc+compound"),
            Bytes::from_static(b"read-one"),
            Bytes::from_static(b"middle"),
            Bytes::from_static(b"read-two"),
        ])
        .unwrap();
        assert_eq!(reply.segment_count(), 4);
        assert_eq!(reply.into_bytes(), Bytes::from_static(b"rpc+compoundread-onemiddleread-two"));
    }
}
