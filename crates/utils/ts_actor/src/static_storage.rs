//! Experimental concretization of owned, `'static` lifetime storage, allowing either `Box` or
//! `&'static mut`. The idea is that this is an optional optimization over `Box`, allowing the
//! user to replace it with `&'static mut` via a library like `static_cell` if they are motivated
//! to reduce allocation.

use alloc::boxed::Box;
use core::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
    pin::Pin,
    task::{Context, Poll},
};

/// Abstraction over mutable static storage, either `Box<T>` or `&'static mut T`.
///
/// Provided so that it's possible to use `ts_actor` with static storage (forward-looking
/// to embedded usage).
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StaticStorage<T>
where
    T: ?Sized + 'static,
{
    /// A [`Box`] holding the value.
    Box(Box<T>),

    /// The value as a `&static mut`.
    ///
    /// This works well with libraries like `static_cell`.
    Ref(&'static mut T),
}

impl<T> StaticStorage<T>
where
    T: ?Sized + 'static,
{
    /// Leak this value via [`Box::leak`] if it's a `Box`, or if it's `Ref`, just return it.
    pub fn leak(self) -> &'static mut T {
        match self {
            Self::Ref(x) => x,
            Self::Box(x) => Box::leak(x),
        }
    }

    /// Extract the `Box` variant.
    ///
    /// If it's a `Ref`, return `None`.
    pub fn into_box(self) -> Option<Box<T>> {
        match self {
            Self::Box(x) => Some(x),
            _ => None,
        }
    }

    /// Extract the `Ref` variant.
    ///
    /// If it's a `Box`, return `None`.
    pub fn into_ref(self) -> Option<&'static mut T> {
        match self {
            Self::Ref(x) => Some(x),
            _ => None,
        }
    }

    /// Get a immutable ref to the contained value.
    ///
    /// This is like [`AsRef`] but supports `const` in stable rust.
    pub const fn as_ref(&self) -> &T {
        match self {
            Self::Box(b) => b,
            Self::Ref(r) => r,
        }
    }

    /// Get a mutable ref to the contained value.
    ///
    /// This is like [`AsMut`] but supports `const` in stable rust.
    pub const fn as_mut(&mut self) -> &mut T {
        match self {
            Self::Box(b) => &mut *b,
            Self::Ref(r) => r,
        }
    }

    /// Project a pinned mut ref to a static storage to the inner value.
    pub fn pin_project_mut(self: Pin<&mut Self>) -> Pin<&mut T> {
        // SAFETY: if we're pinned, the value is either a heap value (pinned via box) or a &'static,
        // which its lifetime guarantees won't move.
        //
        // It seems like we should be able to use pin-project here to establish this, but it didn't
        // even work with the trivial case of Box<T>.
        unsafe { self.map_unchecked_mut(|slf| slf.as_mut()) }
    }
}

impl<T> StaticStorage<[T]> {
    /// Get the length of the contained slice.
    pub const fn len(&self) -> usize {
        match self {
            Self::Box(b) => b.len(),
            Self::Ref(r) => r.len(),
        }
    }

    /// Report whether the contained slice is empty.
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T> Clone for StaticStorage<T>
where
    T: Clone + 'static,
{
    fn clone(&self) -> Self {
        match self {
            Self::Box(b) => Self::Box(b.clone()),
            Self::Ref(t) => Self::Box(Box::new((*t).clone())),
        }
    }
}

impl<T> AsRef<T> for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn as_ref(&self) -> &T {
        self.as_ref()
    }
}

impl<T> AsMut<T> for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn as_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}

impl<T> Borrow<T> for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn borrow(&self) -> &T {
        self.as_ref()
    }
}

impl<T> BorrowMut<T> for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn borrow_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}

impl<T> Deref for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> DerefMut for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> From<T> for StaticStorage<T>
where
    T: 'static,
{
    fn from(value: T) -> Self {
        Self::Box(Box::new(value))
    }
}

impl<T> From<&'static mut T> for StaticStorage<T>
where
    T: ?Sized + 'static,
{
    fn from(value: &'static mut T) -> Self {
        Self::Ref(value)
    }
}

impl<T> Future for StaticStorage<T>
where
    T: Future + ?Sized + 'static,
{
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.pin_project_mut().poll(cx)
    }
}
