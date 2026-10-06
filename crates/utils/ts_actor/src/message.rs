use alloc::boxed::Box;
use core::{
    any::Any,
    fmt::{Debug, Formatter},
    ops::{Deref, DerefMut},
};

type Space = smallbox::space::S4;

/// Construct a [`Message`].
///
/// This macro is required to handle coercion of your message type `T` to `dyn Any + Send`
/// (which is `?Sized`).
#[macro_export]
macro_rules! message {
    ($t:expr) => {{
        let sbox: $crate::smallbox::SmallBox<dyn ::core::any::Any + ::core::marker::Send, _> =
            $crate::smallbox::smallbox!($t);
        $crate::Message::from(sbox)
    }};
}

/// Polymorphic match which attempts to serially downcast the message to each of the given
/// types, invoking the corresponding handler expression.
///
/// # Examples
///
/// ```rust
/// // `message!` upcasts to a type-erased representation.
/// let msg = ts_actor::message!(1u8);
///
/// // To get the value back out, you can use `msg_match!`
/// ts_actor::msg_match! {
///     msg,
///     u8: msg => println!("was u8: {msg}"),
///     i8: msg => println!("was i8: {msg}"),
/// };
/// ```
///
/// The block also returns the value from each arm, like a regular match expression (the
/// types of each arm must match). You must also provide an `else` branch which is evaluated if
/// no other arm matches:
///
/// ```rust
/// let msg = ts_actor::message!(true);
///
/// let val = ts_actor::msg_match! {
///     msg,
///     bool: msg => msg,
///     else msg => false,
/// };
///
/// assert!(val);
/// ```
#[macro_export]
macro_rules! msg_match {
    ($msg:expr $(, $case:ty : $name:pat => $block:expr)* $(, else $name_else:ident => $block_else:expr)? $(,)?) => {
        {
            let msg = $msg;

            // Makes the repeated blocks below regular `else if`s and allows a plain `else` block
            // with no specific cases
            if false {
                unreachable!()
            }

            $(
                // done in two phases (is() -> downcast()) because
                // `if let Ok($name) = msg.downcast::<$case>()` would consume msg
                else if msg.is::<$case>() {
                    let $name = msg.downcast::<$case>().unwrap();
                    $block
                }
            )*

            $(
                else {
                    let $name_else = msg;
                    $block_else
                }
            )?
        }
    };
}

/// A message which may be sent between processes.
///
/// It is copied by value if the item sent is smaller than `4 * usize`; otherwise it is
/// heap-allocated.
///
/// In general, use the `ts_actor::message!` macro to construct messages (makes trait object
/// coercion straightforward). Where more control is required, you can use `From<SmallBox>`
/// (`smallbox` is reexported from the crate root).
pub struct Message(smallbox::SmallBox<dyn Any + Send, Space>);

impl Default for Message {
    fn default() -> Self {
        message![()]
    }
}

impl Debug for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Message")
    }
}

impl Deref for Message {
    type Target = dyn Any + Send;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl DerefMut for Message {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl Message {
    /// Downcast this message into the specified type, consuming it.
    pub fn downcast<T>(self) -> Result<T, Self>
    where
        T: Any,
    {
        match self.0.downcast::<T>() {
            Ok(x) => Ok(x.into_inner()),
            Err(slf) => Err(Self(slf)),
        }
    }

    /// Report whether this message is allocated on the heap.
    pub fn is_heap(&self) -> bool {
        self.0.is_heap()
    }
}

impl<T> From<Box<T>> for Message
where
    T: Any + Send,
{
    fn from(value: Box<T>) -> Self {
        Self(smallbox::SmallBox::from_box(value))
    }
}

impl From<smallbox::SmallBox<dyn Any + Send, Space>> for Message {
    fn from(value: smallbox::SmallBox<dyn Any + Send, Space>) -> Self {
        Self(value)
    }
}
