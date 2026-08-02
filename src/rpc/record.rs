use std::io::{self, IoSlice};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug)]
pub struct RecordLimits {
    pub max_record_size: usize,
    pub max_fragment_size: usize,
    pub max_fragments: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("RPC fragment of {actual} bytes exceeds limit {limit}")]
    FragmentTooLarge { actual: usize, limit: usize },
    #[error("RPC record exceeds {limit} bytes")]
    RecordTooLarge { limit: usize },
    #[error("RPC record has more than {limit} fragments")]
    TooManyFragments { limit: usize },
    #[error("RPC fragment size must be non-zero")]
    EmptyFragment,
    #[error("RPC record byte budget is closed")]
    BudgetClosed,
}

pub async fn read_record<R: AsyncRead + Unpin>(reader: &mut R, limits: RecordLimits) -> Result<Vec<u8>, RecordError> {
    let mut record = Vec::new();
    for fragment_index in 0..limits.max_fragments {
        let header = reader.read_u32().await?;
        let last = header & 0x8000_0000 != 0;
        let length = (header & 0x7fff_ffff) as usize;
        if length == 0 && !last {
            return Err(RecordError::EmptyFragment);
        }
        if length > limits.max_fragment_size {
            return Err(RecordError::FragmentTooLarge {
                actual: length,
                limit: limits.max_fragment_size,
            });
        }
        let new_length = record.len().checked_add(length).ok_or(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })?;
        if new_length > limits.max_record_size {
            return Err(RecordError::RecordTooLarge {
                limit: limits.max_record_size,
            });
        }
        reserve_record(&mut record, new_length, limits.max_record_size)?;
        let start = record.len();
        record.resize(new_length, 0);
        reader.read_exact(&mut record[start..]).await?;
        if last {
            return Ok(record);
        }
        if fragment_index + 1 == limits.max_fragments {
            return Err(RecordError::TooManyFragments {
                limit: limits.max_fragments,
            });
        }
    }
    Err(RecordError::TooManyFragments {
        limit: limits.max_fragments,
    })
}

/// Reads a record while reserving its maximum aggregate byte budget before
/// the first fragment body is allocated. A whole-record reservation avoids
/// fragmented readers holding partial reservations while waiting on each
/// other. The returned permit keeps the record charged while it is queued or
/// executing.
pub async fn read_record_budgeted<R: AsyncRead + Unpin>(
    reader: &mut R,
    limits: RecordLimits,
    budget: Arc<Semaphore>,
) -> Result<(Vec<u8>, OwnedSemaphorePermit), RecordError> {
    let mut record = Vec::new();
    let mut header = reader.read_u32().await?;
    let first_length = (header & 0x7fff_ffff) as usize;
    if first_length == 0 && header & 0x8000_0000 == 0 {
        return Err(RecordError::EmptyFragment);
    }
    if first_length > limits.max_fragment_size {
        return Err(RecordError::FragmentTooLarge {
            actual: first_length,
            limit: limits.max_fragment_size,
        });
    }
    if first_length > limits.max_record_size {
        return Err(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        });
    }
    let reservation = budget
        .acquire_many_owned(u32::try_from(limits.max_record_size).map_err(|_| RecordError::RecordTooLarge {
            limit: u32::MAX as usize,
        })?)
        .await
        .map_err(|_| RecordError::BudgetClosed)?;
    for fragment_index in 0..limits.max_fragments {
        let last = header & 0x8000_0000 != 0;
        let length = (header & 0x7fff_ffff) as usize;
        if length == 0 && !last {
            return Err(RecordError::EmptyFragment);
        }
        if length > limits.max_fragment_size {
            return Err(RecordError::FragmentTooLarge {
                actual: length,
                limit: limits.max_fragment_size,
            });
        }
        let new_length = record.len().checked_add(length).ok_or(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })?;
        if new_length > limits.max_record_size {
            return Err(RecordError::RecordTooLarge {
                limit: limits.max_record_size,
            });
        }
        reserve_record(&mut record, new_length, limits.max_record_size)?;
        let start = record.len();
        record.resize(new_length, 0);
        reader.read_exact(&mut record[start..]).await?;
        if last {
            return Ok((record, reservation));
        }
        if fragment_index + 1 == limits.max_fragments {
            return Err(RecordError::TooManyFragments {
                limit: limits.max_fragments,
            });
        }
        header = reader.read_u32().await?;
    }
    Err(RecordError::TooManyFragments {
        limit: limits.max_fragments,
    })
}

/// Grows geometrically for fragmented records while never requesting a
/// capacity above the validated record-size limit. This avoids reallocating
/// and copying the full prefix for every fragment.
fn reserve_record(record: &mut Vec<u8>, required: usize, limit: usize) -> Result<(), RecordError> {
    if required <= record.capacity() {
        return Ok(());
    }
    let target = record.capacity().saturating_mul(2).max(required).min(limit);
    record
        .try_reserve_exact(target.saturating_sub(record.len()))
        .map_err(|_| RecordError::RecordTooLarge { limit })
}

pub async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &[u8],
    max_fragment_size: usize,
) -> Result<(), RecordError> {
    write_record_limited(
        writer,
        record,
        RecordLimits {
            max_record_size: usize::MAX,
            max_fragment_size,
            max_fragments: usize::MAX,
        },
    )
    .await
}

/// Writes one record while enforcing aggregate size and fragment-count
/// limits as well as the per-fragment limit.
pub async fn write_record_limited<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &[u8],
    limits: RecordLimits,
) -> Result<(), RecordError> {
    validate_record(record, limits)?;
    write_fragments(writer, record, limits.max_fragment_size).await
}

/// Writes a record held in any number of immutable segments without first
/// coalescing them. Fragment boundaries may cross segment boundaries.
pub async fn write_record_segments_limited<'a, W, I>(
    writer: &mut W,
    segments: I,
    limits: RecordLimits,
) -> Result<(), RecordError>
where
    W: AsyncWrite + Unpin,
    I: IntoIterator<Item = &'a [u8]>,
{
    let segments: Vec<&[u8]> = segments.into_iter().collect();
    let length = segments.iter().try_fold(0usize, |length, segment| {
        length.checked_add(segment.len()).ok_or(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })
    })?;
    validate_record_length(length, limits)?;
    write_segmented_fragments(writer, segments, length, limits.max_fragment_size).await
}

pub fn validate_record(record: &[u8], limits: RecordLimits) -> Result<(), RecordError> {
    validate_record_length(record.len(), limits)
}

/// Validates an outbound record when its payload is segmented and therefore
/// has no single contiguous slice.
pub fn validate_record_length(length: usize, limits: RecordLimits) -> Result<(), RecordError> {
    if length > limits.max_record_size {
        return Err(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        });
    }
    let fragment_count = if length == 0 {
        1
    } else if limits.max_fragment_size == 0 {
        usize::MAX
    } else {
        length.div_ceil(limits.max_fragment_size)
    };
    if fragment_count > limits.max_fragments {
        return Err(RecordError::TooManyFragments {
            limit: limits.max_fragments,
        });
    }
    if limits.max_fragment_size == 0 {
        return Err(RecordError::FragmentTooLarge {
            actual: length,
            limit: 0,
        });
    }
    Ok(())
}

async fn write_segmented_fragments<W: AsyncWrite + Unpin>(
    writer: &mut W,
    segments: Vec<&[u8]>,
    total_length: usize,
    max_fragment_size: usize,
) -> Result<(), RecordError> {
    if total_length == 0 {
        writer.write_all(&0x8000_0000u32.to_be_bytes()).await?;
        return Ok(());
    }
    let mut segment_index = 0usize;
    let mut segment_offset = 0usize;
    let mut remaining_total = total_length;
    while remaining_total > 0 {
        let fragment_length = remaining_total.min(max_fragment_size);
        if fragment_length > 0x7fff_ffff {
            return Err(RecordError::FragmentTooLarge {
                actual: fragment_length,
                limit: 0x7fff_ffff,
            });
        }
        let last = fragment_length == remaining_total;
        let header = (fragment_length as u32 | if last { 0x8000_0000 } else { 0 }).to_be_bytes();
        let mut slices = Vec::with_capacity(segments.len().saturating_add(1));
        slices.push(IoSlice::new(&header));
        let mut current_index = segment_index;
        let mut current_offset = segment_offset;
        let mut remaining_fragment = fragment_length;
        while remaining_fragment > 0 {
            while current_index < segments.len() && current_offset == segments[current_index].len() {
                current_index += 1;
                current_offset = 0;
            }
            let segment = segments
                .get(current_index)
                .ok_or(RecordError::RecordTooLarge { limit: total_length })?;
            let take = remaining_fragment.min(segment.len() - current_offset);
            slices.push(IoSlice::new(&segment[current_offset..current_offset + take]));
            remaining_fragment -= take;
            current_offset += take;
        }
        write_all_slices(writer, &mut slices).await?;
        advance_segments(&segments, &mut segment_index, &mut segment_offset, fragment_length);
        remaining_total -= fragment_length;
    }
    writer.flush().await?;
    Ok(())
}

fn advance_segments(segments: &[&[u8]], index: &mut usize, offset: &mut usize, mut count: usize) {
    // Advance the persistent cursor by exactly the payload bytes written for
    // one fragment. The record-marking header is intentionally not counted.
    while count > 0 {
        while *index < segments.len() && *offset == segments[*index].len() {
            *index += 1;
            *offset = 0;
        }
        let available = segments[*index].len() - *offset;
        let take = available.min(count);
        *offset += take;
        count -= take;
    }
}

async fn write_all_slices<W: AsyncWrite + Unpin>(
    writer: &mut W,
    mut slices: &mut [IoSlice<'_>],
) -> Result<(), RecordError> {
    if writer.is_write_vectored() {
        // Async writers may consume only an arbitrary prefix of the iovec.
        // Advance the slices in place so retries neither duplicate the header
        // nor skip payload bytes.
        while !slices.is_empty() {
            let written = writer.write_vectored(slices).await?;
            if written == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            IoSlice::advance_slices(&mut slices, written);
        }
    } else {
        for slice in slices {
            writer.write_all(slice).await?;
        }
    }
    Ok(())
}

async fn write_fragments<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &[u8],
    max_fragment_size: usize,
) -> Result<(), RecordError> {
    if max_fragment_size == 0 {
        return Err(RecordError::FragmentTooLarge {
            actual: record.len(),
            limit: 0,
        });
    }
    if record.is_empty() {
        writer.write_all(&0x8000_0000u32.to_be_bytes()).await?;
        return Ok(());
    }
    let mut fragments = record.chunks(max_fragment_size).peekable();
    while let Some(fragment) = fragments.next() {
        let end = fragments.peek().is_none();
        if fragment.len() > 0x7fff_ffff {
            return Err(RecordError::FragmentTooLarge {
                actual: fragment.len(),
                limit: 0x7fff_ffff,
            });
        }
        let length = u32::try_from(fragment.len()).map_err(|_| RecordError::FragmentTooLarge {
            actual: fragment.len(),
            limit: 0x7fff_ffff,
        })?;
        let header = length | if end { 0x8000_0000 } else { 0 };
        let header = header.to_be_bytes();
        let mut slices = [IoSlice::new(&header), IoSlice::new(fragment)];
        write_all_slices(writer, &mut slices).await?;
    }
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;

    // A deterministic short-writing sink that exercises the iovec retry path
    // without relying on operating-system socket buffer pressure.
    struct PartialVectoredWriter {
        output: Vec<u8>,
        max_write: usize,
        vectored_writes: usize,
    }

    impl AsyncWrite for PartialVectoredWriter {
        fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
            let written = buffer.len().min(self.max_write);
            self.output.extend_from_slice(&buffer[..written]);
            Poll::Ready(Ok(written))
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffers: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let mut remaining = self.max_write;
            let mut written = 0usize;
            for buffer in buffers {
                let take = buffer.len().min(remaining);
                self.output.extend_from_slice(&buffer[..take]);
                written += take;
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            self.vectored_writes += 1;
            Poll::Ready(Ok(written))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn multi_fragment_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let write = tokio::spawn(async move { write_record(&mut client, b"abcdefgh", 3).await.unwrap() });
        let value = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 8,
                max_fragment_size: 3,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        write.await.unwrap();
        assert_eq!(value, b"abcdefgh");
    }

    #[tokio::test]
    async fn partial_vectored_writes_preserve_fragmented_wire_bytes() {
        let segments = [&b"ab"[..], &b"cdefg"[..], &b"hijk"[..]];
        let limits = RecordLimits {
            max_record_size: 11,
            max_fragment_size: 5,
            max_fragments: 3,
        };
        let mut writer = PartialVectoredWriter {
            output: Vec::new(),
            max_write: 3,
            vectored_writes: 0,
        };

        write_record_segments_limited(&mut writer, segments, limits).await.unwrap();

        let mut expected = Vec::new();
        for (index, fragment) in b"abcdefghijk".chunks(5).enumerate() {
            let last = index == 2;
            let header = fragment.len() as u32 | if last { 0x8000_0000 } else { 0 };
            expected.extend_from_slice(&header.to_be_bytes());
            expected.extend_from_slice(fragment);
        }
        assert_eq!(writer.output, expected);
        assert!(writer.vectored_writes > 3);
    }

    #[tokio::test]
    async fn aggregate_budget_is_reserved_before_fragment_allocation() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(&0x8000_0008u32.to_be_bytes()).await.unwrap();
        client.write_all(b"abcdefgh").await.unwrap();
        let budget = Arc::new(Semaphore::new(4));
        let read_budget = budget.clone();
        let read = tokio::spawn(async move {
            read_record_budgeted(
                &mut server,
                RecordLimits {
                    max_record_size: 8,
                    max_fragment_size: 8,
                    max_fragments: 1,
                },
                read_budget,
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(!read.is_finished());
        budget.add_permits(4);
        let (record, reservation) = read.await.unwrap();
        assert_eq!(record, b"abcdefgh");
        assert_eq!(budget.available_permits(), 0);
        drop(reservation);
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn fragmented_records_do_not_deadlock_on_partial_budget_reservations() {
        let limits = RecordLimits {
            max_record_size: 8,
            max_fragment_size: 4,
            max_fragments: 2,
        };
        let budget = Arc::new(Semaphore::new(8));
        let (mut first_client, mut first_server) = tokio::io::duplex(32);
        first_client.write_all(&4u32.to_be_bytes()).await.unwrap();
        first_client.write_all(b"abcd").await.unwrap();
        let first_budget = budget.clone();
        let first =
            tokio::spawn(async move { read_record_budgeted(&mut first_server, limits, first_budget).await.unwrap() });
        while budget.available_permits() != 0 {
            tokio::task::yield_now().await;
        }

        let (mut second_client, mut second_server) = tokio::io::duplex(32);
        second_client.write_all(&4u32.to_be_bytes()).await.unwrap();
        second_client.write_all(b"ijkl").await.unwrap();
        second_client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        second_client.write_all(b"mnop").await.unwrap();
        let second_budget = budget.clone();
        let second =
            tokio::spawn(async move { read_record_budgeted(&mut second_server, limits, second_budget).await.unwrap() });
        tokio::task::yield_now().await;
        assert!(!second.is_finished());

        first_client.write_all(&0x8000_0004u32.to_be_bytes()).await.unwrap();
        first_client.write_all(b"efgh").await.unwrap();
        let (first_record, first_reservation) = first.await.unwrap();
        assert_eq!(first_record, b"abcdefgh");
        assert!(!second.is_finished());
        drop(first_reservation);

        let (second_record, second_reservation) = second.await.unwrap();
        assert_eq!(second_record, b"ijklmnop");
        drop(second_reservation);
        assert_eq!(budget.available_permits(), 8);
    }

    #[tokio::test]
    async fn oversized_fragment_is_rejected_before_body_read() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&0x8000_1000u32.to_be_bytes()).await.unwrap();
        let error = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 1024,
                max_fragment_size: 512,
                max_fragments: 1,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::FragmentTooLarge { .. }));
    }

    #[tokio::test]
    async fn fragment_count_is_bounded() {
        let (mut client, mut server) = tokio::io::duplex(32);
        client.write_all(&1u32.to_be_bytes()).await.unwrap();
        client.write_all(&[1]).await.unwrap();
        client.write_all(&1u32.to_be_bytes()).await.unwrap();
        client.write_all(&[2]).await.unwrap();
        let error = read_record(
            &mut server,
            RecordLimits {
                max_record_size: 32,
                max_fragment_size: 16,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::TooManyFragments { limit: 2 }));
    }

    #[tokio::test]
    async fn outbound_record_and_fragment_limits_are_enforced() {
        let mut output = Vec::new();
        let error = write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 4,
                max_fragment_size: 4,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::RecordTooLarge { limit: 4 }));

        let error = write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 5,
                max_fragment_size: 2,
                max_fragments: 2,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RecordError::TooManyFragments { limit: 2 }));

        output.clear();
        write_record_limited(
            &mut output,
            b"12345",
            RecordLimits {
                max_record_size: 5,
                max_fragment_size: 2,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            output,
            [
                2u32.to_be_bytes().as_slice(),
                b"12",
                2u32.to_be_bytes().as_slice(),
                b"34",
                0x8000_0001u32.to_be_bytes().as_slice(),
                b"5",
            ]
            .concat()
        );
    }

    #[tokio::test]
    async fn segmented_records_cross_segment_and_fragment_boundaries() {
        let mut output = Vec::new();
        write_record_segments_limited(
            &mut output,
            [&b"abc"[..], &b"defgh"[..], &b"ij"[..]],
            RecordLimits {
                max_record_size: 10,
                max_fragment_size: 4,
                max_fragments: 3,
            },
        )
        .await
        .unwrap();
        let expected = [
            4u32.to_be_bytes().as_slice(),
            b"abcd",
            4u32.to_be_bytes().as_slice(),
            b"efgh",
            0x8000_0002u32.to_be_bytes().as_slice(),
            b"ij",
        ]
        .concat();
        assert_eq!(output, expected);
    }
}
