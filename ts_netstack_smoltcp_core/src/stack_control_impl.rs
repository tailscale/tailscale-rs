use core::net::IpAddr;

use crate::{Error, HasChannel, Netstack, Response, command::stack_control};

/// Extension methods for control channels ([`HasChannel`]) supporting ergonomic operations
/// around [`stack_control::Command`]s.
pub trait NetstackControl: HasChannel {
    /// Set the IPs for the netstack interface.
    ///
    /// The netstack must have space to store all the provided IPs -- this is controlled
    /// by `smoltcp`'s `iface-max-addr-count-*` features. You must configure this as the end
    /// user because it is global to all usages of this version of `smoltcp`.
    fn set_ips_blocking(&self, ips: impl IntoIterator<Item = IpAddr>) -> Result<(), Error> {
        self.request_blocking(
            None,
            stack_control::Command::SetIps {
                new_ips: ips.into_iter().collect(),
            },
        )?
        .to_ok()
    }

    /// Set the IPs for the netstack interface.
    ///
    /// The netstack must have space to store all the provided IPs -- this is controlled
    /// by `smoltcp`'s `iface-max-addr-count-*` features. You must configure this as the end
    /// user because it is global to all usages of this version of `smoltcp`.
    fn set_ips(
        &self,
        ips: impl IntoIterator<Item = IpAddr>,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let channel = self.command_channel();
        let new_ips = ips.into_iter().collect();

        async move {
            crate::request(channel, None, stack_control::Command::SetIps { new_ips })
                .await?
                .to_ok()
        }
    }
}

impl<T> NetstackControl for T where T: HasChannel {}

impl Netstack {
    #[tracing::instrument(skip(self), level = "debug")]
    pub(crate) fn process_stack_control(&mut self, command: stack_control::Command) -> Response {
        match command {
            stack_control::Command::SetIps { new_ips } => {
                if !self.direct_set_ips(new_ips.iter().copied()) {
                    tracing::error!(
                        ?new_ips,
                        "not enough address storage space configured in smoltcp"
                    );

                    return Error::buffer_full().into();
                }

                Response::Ok
            }
        }
    }
}
