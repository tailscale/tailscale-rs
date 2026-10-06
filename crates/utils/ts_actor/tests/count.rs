//! Test of simple communication between two actors.

use core::time::Duration;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use ts_actor::{runtime, runtime::Tokio};

#[tokio::test]
async fn count() -> Result<(), ts_actor::Error> {
    const COUNT_TO: u32 = 32;
    const DELAY: Duration = Duration::from_millis(25);

    let rt = runtime::new(Tokio::current());

    let count = Arc::new(AtomicUsize::new(0));

    let count_move = count.clone();
    let pid = rt.spawn(async move |ctx| {
        println!("receiver started: {}", ctx.pid());

        loop {
            let msg = ctx.recv().await?;

            let value = ts_actor::msg_match! {
                msg,
                u32: msg => msg as usize,
                i32: msg => msg as usize,
                else _msg => 0usize,
            };

            println!("msg: {value}");
            count_move.store(value, Ordering::Release);
        }
    })?;

    rt.spawn(async move |ctx| {
        println!("sender started: {}", ctx.pid());
        ctx.link(&pid).await?;

        let mut timer = tokio::time::interval(DELAY);

        for i in 0u32..=COUNT_TO {
            let msg = if i.is_multiple_of(2) {
                ts_actor::message![i]
            } else {
                ts_actor::message![i as i32]
            };

            ctx.send(&pid, msg).await?;
            timer.tick().await;
        }

        Ok(())
    })?;

    // additional buffer time is to deflake
    tokio::time::timeout((DELAY * COUNT_TO).mul_f32(1.25), rt.wait_all_proc())
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::Acquire), COUNT_TO as usize);

    Ok(())
}
