//! Run an SSH server hosting a custom TUI console that lets clients look up info about
//! peers in the tailnet.

use std::{collections::VecDeque, net::IpAddr, path::PathBuf, sync::Arc};

use chrono::Datelike;
use clap::Parser;
use itertools::Itertools;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    macros::span,
    prelude::{Line, Span},
    style::{Style, Stylize},
    text::{Text, ToSpan},
    widgets::{Block, List, ListItem, Paragraph},
};
use russh::keys::Algorithm;
use tailscale::ssh;
use tracing_subscriber::filter::LevelFilter;
use ts_control::Node;

/// Run an SSH server running a custom console over the tailnet supporting peer ip lookups.
///
/// This does _no_ authentication -- anyone on the tailnet permitted to talk to the relevant
/// port can connect.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// Path to a key file to use. Will be created if it doesn't exist.
    #[arg(short = 'c', long, default_value = "tsrs_keys.json")]
    key_file: PathBuf,

    /// The auth key to connect with.
    ///
    /// Can be omitted if the key file is already authenticated.
    #[arg(short = 'k', long)]
    auth_key: Option<String>,

    /// Port to listen on (on tailnet IPv4).
    #[clap(short, long, default_value_t = 1234)]
    listen_port: u16,
}

#[derive(Default)]
struct PeerLookupTui {
    input_state: String,
    messages: VecDeque<(String, Option<Node>)>,
}

impl ssh::RatatuiApp for PeerLookupTui {
    async fn input(&mut self, data: &[u8], env: impl ssh::RatatuiEnv) {
        let new_data = String::from_utf8_lossy(data);

        // NOTE(npry): this is essentially a manual terminal event parser. Ideally we'd hook this up
        // to one of the terminal crates' existing parsers, but none of them expose it. `crossterm`
        // (which we're using as our backend) has all the machinery to do it, but it's not exposed
        // as part of their API; instead, it's hardcoded to a system-specific implementation.
        //
        // Issue tracking this (https://github.com/crossterm-rs/crossterm/issues/694) has been open
        // since 2022.
        for c in new_data.chars() {
            match c {
                // ^C, ^D
                '\u{3}' | '\u{4}' => {
                    tracing::debug!("got ^C or ^D, closing terminal");
                    env.close().await;
                    return;
                }

                // BKSP
                '\u{8}' | '\u{7f}' => {
                    if let Some((idx, _)) = self.input_state.char_indices().next_back() {
                        self.input_state.truncate(idx);
                    }
                }

                // ESC
                '\u{1b}' => {
                    // punt, not implementing a full control sequence parser here
                }

                '\r' | '\n' => {
                    let line = core::mem::take(&mut self.input_state);
                    if line.is_empty() {
                        continue;
                    }

                    tracing::trace!(query = line);

                    let peer = env.tailscale().peer_by_name(&line).await.ok().flatten();

                    self.messages.truncate(31);
                    self.messages.push_front((line, peer));
                }
                c if !c.is_control() => {
                    self.input_state.push(c);
                }
                _ignore => {}
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let layout = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]);

        let [input_area, msg_area] = frame.area().layout(&layout);

        let input = Paragraph::new(Line::from_iter([
            Span::raw(&self.input_state),
            '█'.slow_blink(),
        ]))
        .style(Style::default())
        .block(Block::bordered().title("peer query"));

        frame.render_widget(input, input_area);

        #[allow(unstable_name_collisions)]
        let messages = self
            .messages
            .iter()
            .map(|(query, node)| ListItem::new(render_node(query, node.as_ref())))
            .intersperse(ListItem::new(""))
            .collect::<Vec<_>>();

        let messages = List::new(messages).block(Block::bordered().title("results"));

        frame.render_widget(messages, msg_area);
    }
}

fn render_node<'a>(query: &'a str, node: Option<&'a Node>) -> Text<'a> {
    let Some(node) = node else {
        return Text::from_iter([Line::from_iter([
            span!(Style::new().red().bold(); "{query}"),
            span!(": no match"),
        ])]);
    };

    let mut text = Text::from_iter([
        Line::from_iter([
            span!(Style::new().green().bold(); "{} ", node.fqdn(false)),
            span!("({})", node.stable_id.0),
            ":".into(),
        ]),
        Line::from_iter([
            "ipv4: ".into(),
            node.tailnet_address.ipv4.to_span().light_cyan(),
        ]),
        Line::from_iter([
            "ipv6: ".into(),
            node.tailnet_address.ipv6.to_span().light_cyan(),
        ]),
        Line::from_iter([
            "node key: ".into(),
            node.node_key.to_span().yellow(),
            " (expires ".into(),
            if let Some(nk) = &node.node_key_expiry {
                span!("{}/{}/{}", nk.year(), nk.month(), nk.day())
            } else {
                "never".red()
            },
            ")".into(),
        ]),
    ]);

    if let Some(disco_key) = &node.disco_key {
        text.push_line(Line::from_iter([
            "disco key: ".into(),
            disco_key.to_span().yellow(),
        ]));
    }

    if let Some(derp_region) = &node.derp_region {
        text.push_line(Line::from_iter([
            "derp region: ".into(),
            derp_region.to_span().light_cyan(),
        ]));
    }

    if !node.tags.is_empty() {
        let mut line = Line::raw("tags: ");

        #[allow(unstable_name_collisions)]
        line.extend(
            node.tags
                .iter()
                .map(Span::raw)
                .map(|span| span.light_blue())
                .intersperse(Span::raw(", ")),
        );

        text.push_line(line);
    }

    text
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn core::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let args = Args::parse();

    let dev = tailscale::Device::new(
        &tailscale::Config::default_with_key_file(&args.key_file).await?,
        args.auth_key,
    )
    .await?;

    let ipv4: IpAddr = dev.ipv4_addr().await?.into();
    let dev = Arc::new(dev);

    dev.serve_ssh_tui::<PeerLookupTui>(
        russh::server::Config {
            keys: vec![
                russh::keys::PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap(),
            ],
            methods: russh::MethodSet::from(&[russh::MethodKind::None][..]),
            nodelay: true,
            ..Default::default()
        },
        (ipv4, args.listen_port).into(),
    )
    .await?;

    Ok(())
}
