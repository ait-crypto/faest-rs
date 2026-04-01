use generic_array::{ArrayLength, GenericArray};
use vgzzq::memcheck::{make_mem_defined, make_mem_undefined};

/// Defines valgrind wrappers that allow checking constant-time implementation.
pub trait Classifier {
    /// Makes valgrind see underlying memory as addressable but undefined.
    ///
    /// Can be used in combination with valgrind to verify constant-time implementation.
    /// NOTE: this wrapper should mimic behaviors of the VALGRIND_MAKE_MEMORY_UNDEFINED macro (see valgrind/memcheck.h).
    fn classify(&self);

    /// Makes valgrind see underlying memory as addressable and defined.
    ///
    /// Can be used in combination with valgrind to verify constant-time implementation.
    /// NOTE: this wrapper should mimic behaviors of the VALGRIND_MAKE_MEMORY_DEFINED macro (see valgrind/memcheck.h).
    fn declassify(&self);
}

impl<T> Classifier for &[T] {
    #[inline(always)]
    fn classify(&self) {
        unsafe {
            make_mem_undefined(self.as_ptr(), self.len());
        }
    }

    #[inline(always)]
    fn declassify(&self) {
        unsafe {
            make_mem_defined(self.as_ptr(), self.len());
        }
    }
}

impl<T> Classifier for &mut [T] {
    #[inline(always)]
    fn classify(&self) {
        unsafe {
            make_mem_undefined(self.as_ptr(), self.len());
        }
    }

    #[inline(always)]
    fn declassify(&self) {
        unsafe {
            make_mem_defined(self.as_ptr(), self.len());
        }
    }
}

impl<T> Classifier for Vec<T> {
    #[inline(always)]
    fn classify(&self) {
        unsafe {
            make_mem_undefined(self.as_ptr(), self.len());
        }
    }

    #[inline(always)]
    fn declassify(&self) {
        unsafe {
            make_mem_defined(self.as_ptr(), self.len());
        }
    }
}

impl<T, S> Classifier for GenericArray<T, S>
where
    S: ArrayLength,
{
    #[inline(always)]
    fn classify(&self) {
        unsafe {
            make_mem_undefined(self.as_ptr(), self.len());
        }
    }

    #[inline(always)]
    fn declassify(&self) {
        unsafe {
            make_mem_defined(self.as_ptr(), self.len());
        }
    }
}

impl<T, S> Classifier for &GenericArray<T, S>
where
    S: ArrayLength,
{
    #[inline(always)]
    fn classify(&self) {
        unsafe {
            make_mem_undefined(self.as_ptr(), self.len());
        }
    }

    #[inline(always)]
    fn declassify(&self) {
        unsafe {
            make_mem_defined(self.as_ptr(), self.len());
        }
    }
}
