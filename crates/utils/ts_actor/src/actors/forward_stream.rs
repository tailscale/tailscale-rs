use alloc::boxed::Box;
use core::any::Any;

use futures_util::{FutureExt, Stream, StreamExt};

use crate::{ProcContext, ProcFut, StaticStorage, ToProcName};

/// Forward elements from the stream `s` to process `name` as messages.
pub fn forward_stream<S>(
    name: &dyn ToProcName,
    s: S,
) -> impl FnOnce(ProcContext) -> StaticStorage<ProcFut> + use<S>
where
    S: Stream + Send + 'static,
    S::Item: Send + Any,
{
    let name = name.to_proc_name();

    move |ctx| {
        StaticStorage::Box(Box::new(async move {
            let mut s = core::pin::pin![s.fuse()];

            loop {
                // Bias towards emptying process mailbox first.
                futures_util::select_biased! {
                    x = ctx.recv().fuse() => {
                        drop(x?);
                        tracing::trace!("forward stream: discard unknown message");
                    },
                    item = s.next() => {
                        match item {
                            Some(t) => {
                                ctx.send(&name, crate::message![t]).await?;
                            },
                            None => {
                                return Ok(())
                            }
                        }
                    }
                }
            }
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{LinkExitReason, SystemMessage, runtime, runtime::Tokio};

    #[tokio::test]
    async fn fwd_once() {
        let rt = runtime::new(Tokio::current());

        let (val, shutdown) = rt
            .run(async |ctx| {
                ctx.trap_exit(true)?;
                ctx.spawn_link(forward_stream(
                    &ctx.pid(),
                    futures_util::stream::once(async move { 4u8 }),
                ))?;

                let val = ctx.recv_downcast::<u8>().await?;
                let shutdown = ctx.recv_downcast::<SystemMessage>().await?;

                Ok((val, shutdown))
            })
            .await
            .unwrap();

        assert_eq!(val, 4);
        assert!(matches!(
            shutdown,
            SystemMessage::LinkExit {
                reason: LinkExitReason::Normal,
                ..
            }
        ));
    }
}
