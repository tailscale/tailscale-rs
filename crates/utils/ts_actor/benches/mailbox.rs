//! Mailbox benchmarks.

use std::sync::Arc;

use divan::counter::ItemsCount;

fn main() {
    divan::main();
}

#[divan::bench(args = [16, 32, 128, 1024])]
fn async_mailbox(bencher: divan::Bencher, n: u16) {
    let mbox = ts_actor::mailbox::Mailbox::new(n);
    let (tx, rx) = ts_actor::mailbox::async_mailbox::<parking_lot::RawMutex>(mbox);

    let tokio = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let done = Arc::new(tokio::sync::Notify::new());

    let msg_count = (n as usize) * 1024;

    let done_tx = done.clone();
    tokio.spawn(async move {
        loop {
            for _ in 0..msg_count {
                rx.recv().await.unwrap();
            }

            done_tx.notify_one();
        }
    });

    let tx = Arc::new(tx);
    bencher
        .with_inputs(|| {
            let mut v = Vec::with_capacity(msg_count);

            for _ in 0..v.capacity() {
                v.push(ts_actor::message![()]);
            }

            (tx.clone(), done.clone(), v)
        })
        .input_counter(|(_, _, x)| ItemsCount::new(x.len()))
        .bench_local_values(|(tx, done, v)| {
            tokio.block_on(async move {
                for msg in v {
                    tx.send(msg).await.unwrap();
                }

                done.notified().await;
            })
        });
}
