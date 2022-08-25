#![cfg_attr(feature = "realloc", feature(alloc_error_handler))]
#![no_std]

#[cfg(feature = "realloc")]
extern crate alloc;
#[cfg(feature = "realloc")]
use alloc::{
    alloc::{GlobalAlloc, Layout},
    collections::BTreeMap,
    format,
};
use core::panic::PanicInfo;
use core::{mem::transmute, slice::from_raw_parts_mut};
use core::{ops::DerefMut, sync::atomic::AtomicBool};
use rand_chacha::ChaCha20Rng;
use spin::Mutex;

use rand::{Rng, SeedableRng};

use libc::{c_void, getrandom, write, RTLD_NEXT, STDOUT_FILENO};

lazy_static::lazy_static!(
static ref DATA: InitData={
    unsafe{InitData{
               malloc:transmute(get_fn(RTLD_NEXT, b"malloc\0")),
#[cfg(feature="realloc")]
              realloc:transmute(get_fn(RTLD_NEXT, b"realloc\0")),
#[cfg(feature="realloc")]
               reallocarray:transmute(get_fn(RTLD_NEXT, b"reallocarray\0")),
#[cfg(feature="realloc")]
              calloc:transmute(get_fn(RTLD_NEXT, b"calloc\0")),
              aligned_alloc:transmute(get_fn(RTLD_NEXT, b"aligned_alloc\0")),
              posix_memalign:transmute(get_fn(RTLD_NEXT, b"posix_memalign\0")),
               valloc:transmute(get_fn(RTLD_NEXT, b"valloc\0")),
#[cfg(feature="realloc")]
              free:transmute(get_fn(RTLD_NEXT, b"free\0")),
#[cfg(feature="realloc")]
    size_map:Mutex::new(BTreeMap::new()),
        rng:Mutex::new(ChaCha20Rng::from_seed({
            let mut seed:<ChaCha20Rng as SeedableRng>::Seed=Default::default();
            getrandom(seed.as_mut_ptr().cast(),seed.len(),0);
            seed
        }))
}}};
);

struct InitData {
    malloc: extern "C" fn(usize) -> *mut c_void,
    #[cfg(feature = "realloc")]
    realloc: extern "C" fn(*mut c_void, usize) -> *mut c_void,
    #[cfg(feature = "realloc")]
    reallocarray: extern "C" fn(*mut c_void, usize, usize) -> *mut c_void,
    #[cfg(feature = "realloc")]
    calloc: extern "C" fn(usize, usize) -> *mut c_void,
    aligned_alloc: extern "C" fn(usize, usize) -> *mut c_void,
    posix_memalign: extern "C" fn(*mut *mut c_void, usize, usize) -> i32,
    valloc: extern "C" fn(usize) -> *mut c_void,
    #[cfg(feature = "realloc")]
    free: extern "C" fn(*mut c_void) -> (),
    #[cfg(feature = "realloc")]
    size_map: Mutex<BTreeMap<usize, usize>>,
    rng: Mutex<ChaCha20Rng>,
}

//our own allocations must bypass our provided allocation methods and directly use libc.
#[cfg(feature = "realloc")]
struct LibcAllocator {}

#[cfg(feature = "realloc")]
unsafe impl GlobalAlloc for LibcAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        (DATA.aligned_alloc)(layout.align(), layout.size()).cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        (DATA.free)(ptr.cast())
    }
}

#[cfg(feature = "realloc")]
#[global_allocator]
static ALLOC: LibcAllocator = LibcAllocator {};

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut c_void {
    let ptr = (DATA.malloc)(size);
    if !ptr.is_null() {
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
        let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
        rng.fill(slice);

        #[cfg(feature = "realloc")]
        if DATA.size_map.lock().insert(ptr as usize, size).is_some() {
            panic!("Returned ptr is still associated with another size")
        }
    }
    ptr
}

#[cfg(feature = "realloc")]
#[no_mangle]
pub extern "C" fn calloc(num: usize, size: usize) -> *mut c_void {
    let ptr = (DATA.calloc)(num, size);
    if !ptr.is_null() {
        //overflow check done by calloc
        if DATA
            .size_map
            .lock()
            .insert(ptr as usize, num * size)
            .is_some()
        {
            panic!("Returned ptr is still associated with another size")
        }
    }
    ptr
}

#[cfg(feature = "realloc")]
#[no_mangle]
pub extern "C" fn free(ptr: *mut c_void) {
    let size = DATA
        .size_map
        .lock()
        .remove(&(ptr as usize))
        .expect("Invalid free detected");
    let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
    let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
    rng.fill(slice);
    (DATA.free)(ptr)
}

#[cfg(feature = "realloc")]
#[no_mangle]
pub extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let old_size = if ptr.is_null() {
        0
    } else {
        *DATA
            .size_map
            .lock()
            .get(&(ptr as usize))
            .expect("Invalid realloc")
    };
    let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
    if size < old_size {
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), old_size) };
        rng.fill(slice.get_mut(size..).unwrap());
    }
    let ptr = (DATA.realloc)(ptr, size);
    if size > old_size {
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
        rng.fill(slice.get_mut(old_size..).unwrap());
    }
    if old_size != DATA.size_map.lock().insert(ptr as usize, size).unwrap_or(0) {
        panic!("Racy realloc detected")
    }
    ptr
}

#[cfg(feature = "realloc")]
#[no_mangle]
pub extern "C" fn reallocarray(ptr: *mut c_void, num: usize, size: usize) -> *mut c_void {
    if num.checked_mul(size).is_none() {
        (DATA.reallocarray)(ptr, num, size)
    } else {
        let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
        let full_size = num * size;
        let old_size = if ptr.is_null() {
            0
        } else {
            *DATA
                .size_map
                .lock()
                .get(&(ptr as usize))
                .expect("Invalid realloc")
        };
        if full_size < old_size {
            let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), old_size) };
            rng.fill(slice.get_mut(full_size..).unwrap());
        }
        let ptr = (DATA.reallocarray)(ptr, num, size);
        if full_size > old_size {
            let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), full_size) };
            rng.fill(slice.get_mut(old_size..).unwrap());
        }
        if old_size
            != DATA
                .size_map
                .lock()
                .insert(ptr as usize, full_size)
                .unwrap_or(0)
        {
            panic!("Racy realloc detected")
        }
        ptr
    }
}

#[no_mangle]
pub extern "C" fn aligned_alloc(align: usize, size: usize) -> *mut c_void {
    let ptr = (DATA.aligned_alloc)(align, size);
    if !ptr.is_null() {
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
        let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
        rng.fill(slice);
        #[cfg(feature = "realloc")]
        if size != 0 && DATA.size_map.lock().insert(ptr as usize, size).is_some() {
            panic!("Returned ptr is still associated with another size")
        }
    }
    ptr
}

#[no_mangle]
pub extern "C" fn memalign(align: usize, size: usize) -> *mut c_void {
    aligned_alloc(align, size)
}

//only deref if memalign succeeded
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn posix_memalign(ptr: *mut *mut c_void, align: usize, size: usize) -> i32 {
    let result = (DATA.posix_memalign)(ptr, align, size);
    if result != 0 && size != 0 {
        let ptr = unsafe { *ptr };
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
        let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
        rng.fill(slice);
        #[cfg(feature = "realloc")]
        if DATA.size_map.lock().insert(ptr as usize, size).is_some() {
            panic!("Returned ptr is still associated with another size")
        }
    }
    result
}
#[no_mangle]
pub extern "C" fn valloc(size: usize) -> *mut c_void {
    let ptr = (DATA.valloc)(size);
    if !ptr.is_null() {
        let slice = unsafe { from_raw_parts_mut(ptr.cast::<u8>(), size) };
        let mut rng = ChaCha20Rng::from_rng(DATA.rng.lock().deref_mut()).unwrap();
        rng.fill(slice);
        #[cfg(feature = "realloc")]
        if DATA.size_map.lock().insert(ptr as usize, size).is_some() {
            panic!("Returned ptr is still associated with another size")
        }
    }
    ptr
}

#[link(name = "dl")]
extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const u8) -> *const ();
}

unsafe fn get_fn(handle: *mut c_void, symbol: &[u8]) -> *const () {
    let ptr = dlsym(handle as *mut c_void, symbol.as_ptr());
    assert_eq!(Some(&0u8), symbol.last());
    if ptr.is_null() {
        panic!(
            "Unable to find symbol {}",
            core::str::from_utf8(symbol.get(0..(symbol.len() - 1)).unwrap()).unwrap()
        )
    } else {
        ptr
    }
}

static PANIC_GUARD: AtomicBool = AtomicBool::new(true);

#[cfg_attr(not(test), panic_handler)]
#[cfg_attr(test, allow(dead_code))]
fn panic_handler(info: &PanicInfo) -> ! {
    if PANIC_GUARD.swap(false, core::sync::atomic::Ordering::AcqRel) {
        let info = {
            #[cfg(feature = "realloc")]
            {
                format!(
                    "\nmalloc-uninitialized paniced:\n{}:{}\n{}\n",
                    info.location().unwrap().file(),
                    info.location().unwrap().line(),
                    info
                )
            }
            #[cfg(not(feature = "realloc"))]
            {
                if let Some(s) = info.payload().downcast_ref::<&str>() {
                    s
                } else {
                    "Unable to extract panic message"
                }
            }
        };
        unsafe {
            let buf = info.as_bytes();
            let mut position = 0usize;
            let mut counter = 255;
            while position < buf.len() && counter > 0 {
                counter -= 1;
                let buf = buf.get_unchecked(position..);
                let res = write(STDOUT_FILENO, buf.as_ptr().cast(), buf.len());
                if res != -1 {
                    position += usize::try_from(res).unwrap();
                }
            }
        }
    }
    loop {
        unsafe {
            core::arch::asm!("int3", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(feature = "realloc")]
#[cfg_attr(not(test), alloc_error_handler)]
#[cfg_attr(test, allow(dead_code))]
fn alloc_error_handler(_info: Layout) -> ! {
    panic!("internal allocation failure")
}
