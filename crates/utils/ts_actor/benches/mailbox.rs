//! Mailbox benchmarks.

use std::sync::Arc;

use divan::counter::ItemsCount;
use ts_actor::Message;

fn main() {
    divan::main();
}

#[divan::bench(args = [16 * 1024, 32 * 1024, 128 * 1024, 1024 * 1024])]
fn async_mailbox(bencher: divan::Bencher, n: usize) {
    let (tx, rx) = ts_actor::mailbox::async_mailbox::<parking_lot::RawMutex>();

    let tokio = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let done = Arc::new(tokio::sync::Notify::new());

    let done_tx = done.clone();
    tokio.spawn(async move {
        loop {
            for _ in 0..n {
                rx.recv().await.unwrap();
            }

            done_tx.notify_one();
        }
    });

    let tx = Arc::new(tx);
    bencher
        .with_inputs(|| {
            let mut v = Vec::with_capacity(n);

            for _ in 0..v.capacity() {
                v.push(Message::default());
            }

            (tx.clone(), done.clone(), v)
        })
        .input_counter(|(_, _, x)| ItemsCount::new(x.len()))
        .bench_local_values(|(tx, done, v)| {
            tokio.block_on(async move {
                for msg in v {
                    tx.send(msg).unwrap();
                }

                done.notified().await;
            })
        });
}
