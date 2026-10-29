//! Example illustrating a simple [`GenServer`] which provides a calculator service.

use ts_actor::{
    Error, ProcContext, gen_server,
    gen_server::{Action, GenServer},
    runtime,
};

struct Calculator;

impl GenServer for Calculator {
    type State = ();
    type Args = ();

    async fn init(
        &self,
        _ctx: &ProcContext,
        _: Self::Args,
    ) -> Result<(Self::State, Option<Action>), Error> {
        Ok(Default::default())
    }

    ts_actor::typed_call!(Add, Sub, Mul, Div, Pow);
}

struct Add(f32, f32);
struct Sub(f32, f32);
struct Mul(f32, f32);
struct Div(f32, f32);
struct Pow(f32, f32);

ts_actor::impl_call!(Calculator, Add, f32, _ctx, _state, Add(a, b), handle, {
    handle.commit(a + b).into()
});

ts_actor::impl_call!(Calculator, Sub, f32, _ctx, _state, Sub(a, b), handle, {
    handle.commit(a - b).into()
});

ts_actor::impl_call!(Calculator, Mul, f32, _ctx, _state, Mul(a, b), handle, {
    handle.commit(a * b).into()
});

ts_actor::impl_call!(Calculator, Div, f32, _ctx, _state, Div(a, b), handle, {
    handle.commit(a / b).into()
});

ts_actor::impl_call!(Calculator, Pow, f32, _ctx, _state, Pow(a, b), handle, {
    handle.commit(a.powf(b)).into()
});

#[tokio::main]
async fn main() -> Result<(), Error> {
    let rt = runtime::new(runtime::Tokio::current());

    let calc = rt.spawn(gen_server::start(Calculator, ()))?;

    rt.run(async move |ctx| {
        let ret = gen_server::call_typed::<_, Calculator>(&ctx, &calc, Add(1., 2.)).await?;
        println!("1 + 2 = {ret}");

        // You can wrap a `GenServer` procname in a handle to make it easier to send calls and casts:
        let handle = gen_server::GenServerHandle::<Calculator>::new(&ctx, &calc);

        let ret = handle.call_typed(Sub(2., 1.)).await?;
        println!("2 - 1 = {ret}");

        Ok(())
    })
    .await?;

    Ok(())
}
