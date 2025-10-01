use crate::{AuditError, Result};
use std::future::Future;
use tokio::time::{sleep, Duration};
use tracing::debug;

/// Execute an async operation with exponential backoff retry logic
///
/// This is a generic retry mechanism that can wrap any async operation.
/// It implements exponential backoff with configurable parameters.
///
/// # Arguments
/// * `max_retries` - Maximum number of retry attempts (0 = no retries)
/// * `initial_backoff` - Initial backoff duration in seconds
/// * `max_backoff` - Maximum backoff duration in seconds (cap)
/// * `is_retryable` - Function to determine if an error should trigger retry
/// * `operation` - Async operation to execute (can be called multiple times)
/// * `context` - Description of operation for logging
///
/// # Example
/// ```ignore
/// let result = retry_with_backoff(
///     3,  // max retries
///     1,  // 1s initial backoff
///     60, // 60s max backoff
///     |err| matches!(err, AuditError::Http(_)),
///     || async { fetch_data().await },
///     "fetch vulnerability data"
/// ).await;
/// ```
pub async fn retry_with_backoff<F, Fut, T>(
    max_retries: u32,
    initial_backoff: u64,
    max_backoff: u64,
    is_retryable: impl Fn(&AuditError) -> bool,
    mut operation: F,
    context: &str,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempt = 0;

    loop {
        attempt += 1;

        match operation().await {
            Ok(result) => return Ok(result),
            Err(err) if attempt <= max_retries && is_retryable(&err) => {
                let backoff_secs =
                    std::cmp::min(initial_backoff * 2_u64.pow(attempt - 1), max_backoff);

                debug!(
                    "{} failed (attempt {}/{}): {}. Retrying in {}s...",
                    context,
                    attempt,
                    max_retries + 1,
                    err,
                    backoff_secs
                );

                sleep(Duration::from_secs(backoff_secs)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Check if an error is retryable (transient network issues)
///
/// This is the standard retry policy for HTTP operations:
/// - Timeouts (connection or read)
/// - Connection errors
/// - Rate limiting (429)
/// - Service unavailable (503)
pub fn is_http_error_retryable(err: &AuditError) -> bool {
    match err {
        AuditError::Http(e) => {
            e.is_timeout()
                || e.is_connect()
                || e.status()
                    .is_some_and(|s| s.as_u16() == 429 || s.as_u16() == 503)
        }
        _ => false,
    }
}
