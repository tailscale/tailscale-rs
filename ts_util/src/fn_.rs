//! Helper functionality around functions.

macro_rules! gen_fn {
    ($name_mut:ident, $name_sync:ident $(, $arg:ident)* $(,)?) => {
        /// Create a [`FnMut`] from an [`FnOnce`], runtime-checking that it's called only once.
        ///
        /// # Panics
        ///
        /// If the returned function is called more than once.
        #[track_caller]
        pub fn $name_mut<$($arg ,)* Ret>(f: impl FnOnce($($arg),*) -> Ret) -> impl FnMut($($arg),*) -> Ret {
            let mut x = Some(f);

            #[allow(non_snake_case)]
            move |$($arg),*| x.take().unwrap()($($arg),*)
        }

        /// Create a [`Fn`] from an [`FnOnce`], runtime-checking that it's called only once.
        ///
        /// This produces a [`Sync`] returned [`Fn`] by using a [`Mutex`][std::sync::Mutex].
        ///
        /// # Panics
        ///
        /// If the returned function is called more than once.
        #[cfg(feature = "std")]
        #[track_caller]
        pub fn $name_sync<$($arg ,)* Ret>(
            f: impl FnOnce($($arg),*) -> Ret + Send,
        ) -> impl Fn($($arg ,)*) -> Ret + Send + Sync {
            use std::sync::Mutex;

            let x = Mutex::new(Some(f));

            #[allow(non_snake_case)]
            move |$($arg),*| {
                let f = x.lock().unwrap().take().unwrap();
                f($($arg),*)
            }
        }
    };
}

gen_fn!(fn_mut0, fn_sync0);
gen_fn!(fn_mut1, fn_sync1, A);
gen_fn!(fn_mut2, fn_sync2, A, B);
gen_fn!(fn_mut3, fn_sync3, A, B, C);
gen_fn!(fn_mut4, fn_sync4, A, B, C, D);
gen_fn!(fn_mut5, fn_sync5, A, B, C, D, E);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_fn_mut0() {
        let mut f = fn_mut0(|| ());
        f();
    }

    #[test]
    #[should_panic]
    fn test_fn_mut0_panics() {
        let mut f = fn_mut0(|| ());
        f();
        f();
    }

    #[test]
    fn test_fn_sync0() {
        let f = fn_sync0(|| ());
        f();
    }

    #[test]
    #[should_panic]
    fn test_fn_sync0_panics() {
        let f = fn_sync0(|| ());
        f();
        f();
    }
}
