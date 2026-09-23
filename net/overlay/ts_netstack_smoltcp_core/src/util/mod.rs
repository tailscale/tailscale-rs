use core::fmt::{Debug, Display, Formatter};

mod noop_cap_dev;
pub use noop_cap_dev::NoopCapDev;

/// Utility struct providing [`Debug`] using a type's [`Display`].
pub struct DisplayToDebug<'a>(pub &'a dyn Display);

impl<'a> Debug for DisplayToDebug<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Extension methods for implementors of [`Display`].
pub trait DisplayExt {
    /// Return a wrapper around this value that provides [`Debug`] using its [`Display`]
    /// implementation.
    fn as_display_debug(&self) -> DisplayToDebug<'_>;
}

impl<T> DisplayExt for T
where
    T: Display,
{
    fn as_display_debug(&self) -> DisplayToDebug<'_> {
        DisplayToDebug(self)
    }
}

/// Extension methods for [`Result`].
pub trait ResultExt {
    /// The value type in the result.
    type T;

    /// Convert this result to an [`Option`] using [`Result::ok`], tracing the error if
    /// there was one.
    fn ok_trace(self) -> Option<Self::T>;

    /// Convert this result to an [`Option`] using [`Result::ok`], tracing the error if
    /// there was one, along with the provided context `ctx`.
    fn ok_ctx(self, ctx: impl Display) -> Option<Self::T>;
}

impl<T, E> ResultExt for Result<T, E>
where
    E: Display,
{
    type T = T;

    fn ok_trace(self) -> Option<T> {
        self.inspect_err(|e| tracing::error!(error = %e)).ok()
    }

    fn ok_ctx(self, ctx: impl Display) -> Option<T> {
        self.inspect_err(|e| tracing::error!(error = %e, "{ctx}"))
            .ok()
    }
}

/// Utility struct providing cleaner [`Debug`] formatting for [`Option`].
///
/// Delegates to an inner [`Display`] if this is `Some`, otherwise formats as `None`.
pub struct OptionDisplayDebug<'a, T>(pub &'a Option<T>);

impl<'a, T> Debug for OptionDisplayDebug<'a, T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(t) => t.fmt(f),
            None => write!(f, "None"),
        }
    }
}

/// Extension methods for [`Option`].
pub trait OptionExt {
    /// The type contained in the `Option`.
    type T;

    /// Emit a trace with the given `ctx` if this option is `None`.
    fn trace_none(self, ctx: impl Display) -> Self;

    /// Wrap this option in a [`Debug`] implementation that calls [`Display::fmt`] on the
    /// value if this is `Some`.
    fn map_display(&self) -> impl Debug
    where
        Self::T: Display;
}

impl<T> OptionExt for Option<T> {
    type T = T;

    fn trace_none(self, ctx: impl Display) -> Self {
        if self.is_none() {
            tracing::error!("{ctx}");
        }

        self
    }

    fn map_display(&self) -> impl Debug
    where
        T: Display,
    {
        OptionDisplayDebug(self)
    }
}
