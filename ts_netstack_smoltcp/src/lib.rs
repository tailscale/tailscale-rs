#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

use core::{borrow::Borrow, time::Duration};

pub extern crate ts_netstack_smoltcp_core as netcore;
pub extern crate ts_netstack_smoltcp_socket as netsock;

use netcore::{Channel, smoltcp};
pub use netcore::{HasChannel, Netstack as CoreStack};
pub use netsock::CreateSocket;

mod pipe;
mod run;
#[cfg(feature = "std")]
mod std_clock;
#[cfg(feature = "tun")]
mod tun_rs_device;

pub use pipe::{WakingPipe, WakingPipeDev, WakingPipeReceiver, WakingPipeSender};
pub use run::{run, run_blocking};
#[cfg(feature = "tun")]
pub use tun_rs_device::{TunRsDevice, TunRsDeviceAsync};

/// A function that yields "now" [`Instant`][smoltcp::time::Instant]s.
///
/// Must be monotonic.
pub type Clock = &'static (dyn Fn() -> smoltcp::time::Instant + Send + Sync);

/// A userspace network stack.
///
/// This is a relatively thin shell around [`CoreStack`] to provide convenience runtime
/// features.
pub struct Netstack<D> {
    core: CoreStack,
    dev: D,
    clock: Clock,
}

/// Convenience function to construct a new network stack around a [`WakingPipeDev`].
///
/// Returns the netstack and the remote end of the pipe (from which outgoing packets
/// can be read and to which incoming packets can be transmitted).
#[cfg(feature = "std")]
pub fn piped(config: netcore::Config) -> (Netstack<WakingPipeDev>, WakingPipe) {
    let (pipe1, pipe2) = WakingPipe::unbounded();

    let dev = WakingPipeDev {
        pipe: pipe1,
        mtu: config.mtu,
        medium: smoltcp::phy::Medium::Ip,
    };

    (Netstack::<WakingPipeDev>::new(dev, config), pipe2)
}

/// Convenience function to create a pair of network stacks connected by a point-to-point
/// in-memory link.
#[cfg(feature = "std")]
pub fn piped_pair(config: netcore::Config) -> (Netstack<WakingPipeDev>, Netstack<WakingPipeDev>) {
    let (pipe1, pipe2) = WakingPipe::unbounded();

    let dev1 = WakingPipeDev {
        pipe: pipe1,
        mtu: config.mtu,
        medium: smoltcp::phy::Medium::Ip,
    };

    let dev2 = WakingPipeDev {
        pipe: pipe2,
        mtu: config.mtu,
        medium: smoltcp::phy::Medium::Ip,
    };

    (
        Netstack::<WakingPipeDev>::new(dev1, config.clone()),
        Netstack::<WakingPipeDev>::new(dev2, config),
    )
}

impl<D> Netstack<D> {
    /// Construct a new netstack with the given device and configuration.
    ///
    /// Uses [`std::time::Instant`] as a clock.
    #[cfg(feature = "std")]
    pub fn new(dev: D, config: netcore::Config) -> Self {
        Self::with_clock(dev, config, &|| std_clock::CLOCK.now())
    }

    /// Construct a new netstack with the given device, configuration, and clock.
    pub fn with_clock(dev: D, config: netcore::Config, clock: Clock) -> Self {
        Self {
            core: CoreStack::new(config, clock()),
            dev,
            clock,
        }
    }

    /// Run the netstack, driving the internal event loop to consume commands.
    ///
    /// Runs forever, blocking the current thread.
    ///
    /// `poll_delay` is the amount of time to sleep when we're done with I/O and commands to
    /// process: a smaller delay improves latency at the cost of CPU cycles spent polling.
    /// Consider the async methods for an event-driven approach.
    pub fn run_blocking(&mut self, poll_delay: Duration)
    where
        D: smoltcp::phy::Device,
    {
        run_blocking(&mut self.core, &mut self.dev, self.clock, poll_delay)
    }

    /// Spawn the netstack runner in an OS thread.
    #[cfg(feature = "std")]
    pub fn spawn_threaded(mut self, poll_dur: Duration) -> std::thread::JoinHandle<()>
    where
        D: smoltcp::phy::Device + Send + 'static,
    {
        std::thread::spawn(move || self.run_blocking(poll_dur))
    }

    /// Spawn the netstack runner into a tokio task.
    #[cfg(feature = "tokio")]
    pub fn spawn_tokio(mut self) -> tokio::task::JoinHandle<()>
    where
        D: smoltcp::phy::Device + netcore::AsyncWakeDevice + Send + 'static + Unpin,
    {
        tokio::spawn(async move { self.run_tokio().await })
    }

    /// Run the netstack, driving the internal event loop to consume commands.
    ///
    /// Uses [`tokio::time::sleep`] as the sleep implementation.
    #[cfg(feature = "tokio")]
    pub async fn run_tokio(&mut self)
    where
        D: smoltcp::phy::Device + netcore::AsyncWakeDevice + Unpin,
    {
        run(&mut self.core, &mut self.dev, self.clock, |dur| {
            tokio::time::sleep(dur)
        })
        .await
    }

    /// Run the netstack, driving the internal event loop to consume commands.
    ///
    /// The `sleep` function is the runtime-specific sleep implementation. It has the
    /// `Clone` bound for esoteric async type system reasons (the loop needs to call the
    /// function multiple times, but it doesn't want to reason about `&impl AsyncFn`). A
    /// normal closure or async fn ref will satisfy the bound.
    pub async fn run_with_sleep(&mut self, sleep: impl AsyncFn(Duration) + Clone)
    where
        D: smoltcp::phy::Device + netcore::AsyncWakeDevice + Unpin,
    {
        run(&mut self.core, &mut self.dev, self.clock, sleep).await
    }
}

impl<D> HasChannel for Netstack<D> {
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send {
        self.core.borrow_channel()
    }
}
