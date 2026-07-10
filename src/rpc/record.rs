use std::io;
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
        record.try_reserve_exact(length).map_err(|_| RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })?;
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
        record.try_reserve_exact(length).map_err(|_| RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        })?;
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

pub fn validate_record(record: &[u8], limits: RecordLimits) -> Result<(), RecordError> {
    if record.len() > limits.max_record_size {
        return Err(RecordError::RecordTooLarge {
            limit: limits.max_record_size,
        });
    }
    let fragment_count = if record.is_empty() {
        1
    } else if limits.max_fragment_size == 0 {
        usize::MAX
    } else {
        record.len().div_ceil(limits.max_fragment_size)
    };
    if fragment_count > limits.max_fragments {
        return Err(RecordError::TooManyFragments {
            limit: limits.max_fragments,
        });
    }
    if limits.max_fragment_size == 0 {
        return Err(RecordError::FragmentTooLarge {
            actual: record.len(),
            limit: 0,
        });
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
        writer.write_all(&header.to_be_bytes()).await?;
        writer.write_all(fragment).await?;
    }
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
