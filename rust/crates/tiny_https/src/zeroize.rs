//! Overwriting secrets with zeros when they are dropped. Behind the `net` feature: the volatile
//! writes need `unsafe`, and the pure verification part of the crate handles only public data.

/// Types whose contents can be overwritten with zeros in a way the compiler may not optimise away.
///
/// This is best effort: it clears the value where it lives, but it cannot reach copies the
/// compiler made when moving it, CPU registers, or pages the operating system swapped out.
pub trait Zeroize {
    fn zeroize(&mut self);
}

macro_rules! zeroize_primitive {
    ($($t:ty),*) => {$(
        impl Zeroize for $t {
            #[inline]
            fn zeroize(&mut self) {
                // SAFETY: `self` is a valid, aligned, exclusive reference to a plain integer.
                // A volatile write is not removed even when the value is never read again.
                unsafe { core::ptr::write_volatile(self, 0) }
            }
        }
    )*};
}
zeroize_primitive!(u8, u16, u32, u64, u128, usize);

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        for x in self.iter_mut() {
            x.zeroize();
        }
        // Keep the compiler from moving later reads or frees of this memory before the wipe.
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for Vec<T> {
    /// Overwrites every element, then empties the vector (the allocation is kept).
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
    }
}

/// Owns a secret and zeroizes it when dropped.
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T: Zeroize> std::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Zeroizing<T> {
    fn clone(&self) -> Self {
        Zeroizing(self.0.clone())
    }
}

impl<T: Zeroize> std::fmt::Debug for Zeroizing<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Zeroizing(..)")
    }
}

#[cfg(test)]
mod zeroize_tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn wipes_arrays_slices_and_vectors() {
        let mut a = [0xffu8; 32];
        a.zeroize();
        assert_eq!(a, [0u8; 32]);
        let mut w = [u32::MAX; 8];
        w.zeroize();
        assert_eq!(w, [0u32; 8]);
        let mut nested = vec![[7u8; 16]; 5];
        nested.zeroize();
        assert!(nested.is_empty());
        let mut v = vec![9u8; 100];
        let ptr = v.as_ptr();
        v.zeroize();
        assert!(v.is_empty());
        // The allocation is still ours (clear() keeps it): check the bytes really are zero.
        assert_eq!(v.capacity(), 100);
        // SAFETY: capacity 100, pointer unchanged, we only read bytes that were initialised to 9
        // and then overwritten with 0 by `zeroize`.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, 100) };
        assert!(bytes.iter().all(|&b| b == 0));
        let mut big = 0xdead_beef_u128 << 64;
        big.zeroize();
        assert_eq!(big, 0);
    }

    struct Probe(Rc<Cell<u32>>);

    impl Zeroize for Probe {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn zeroizing_wipes_exactly_once_on_drop_and_hides_contents() {
        let count = Rc::new(Cell::new(0));
        {
            let z = Zeroizing::new(Probe(count.clone()));
            assert_eq!(format!("{:?}", z), "Zeroizing(..)");
            assert_eq!(count.get(), 0);
        }
        assert_eq!(count.get(), 1);
        let kept = Zeroizing::new(vec![1u8, 2, 3]);
        assert_eq!(&kept[..], &[1, 2, 3]); // Deref
        let copy = kept.clone();
        drop(kept);
        assert_eq!(&copy[..], &[1, 2, 3]);
    }
}
