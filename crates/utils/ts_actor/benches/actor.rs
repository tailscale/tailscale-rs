//! Actor communication benchmarks.

fn main() {
    divan::main();
}

#[divan::bench(args = [128, 1024, 8 * 1024, 16 * 1024])]
fn echo(bencher: divan::Bencher, n: usize) {
    let tokio = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let rt = ts_actor::runtime::new(ts_actor::runtime::Tokio::new(tokio.handle().clone()));

    let replier = rt
        .spawn(async |ctx| {
            loop {
                let msg = ctx.recv().await?;
                ctx.send(&"bench", msg).await?;
            }
        })
        .unwrap();

    bencher
        .with_inputs(|| {
            let mut v = Vec::with_capacity(n);

            for _ in 0..v.capacity() {
                v.push(ts_actor::message![()]);
            }

            v
        })
        .input_counter(|x| divan::counter::ItemsCount::new(x.len()))
        .bench_local_values(|msgs| {
            let rt = rt.clone();

            tokio
                .block_on(async move {
                    rt.run(async move |ctx| {
                        ctx.register("bench").await?;

                        for msg in msgs {
                            ctx.send(&replier, msg).await?;
                            ctx.recv().await?;
                        }

                        Ok(())
                    })
                    .await
                })
                .unwrap();
        });
}
