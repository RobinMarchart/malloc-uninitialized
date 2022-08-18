#![no_std]

use core::{sync::atomic::AtomicBool, ffi::{c_int, c_void}, mem::transmute, slice::from_raw_parts_mut, panic::PanicInfo};

use rand_chacha::ChaCha20Rng;

use rand::{Rng,SeedableRng};

struct InitData{
    malloc:fn(usize)->*mut c_void,
    rand:ChaCha20Rng
}

static FLAG: AtomicBool = AtomicBool::new(false);
static mut INIT_DATA: Option<InitData> = None;

static RTDL_NEXT: usize = usize::MAX;
static RTDL_DEFAULT: usize = 0;

fn get_init_data()->InitData{
    // lock spinlock
    while FLAG.compare_exchange(false, true, core::sync::atomic::Ordering::Acquire, core::sync::atomic::Ordering::Relaxed).is_err() {}
    let data = unsafe{
      match &mut INIT_DATA {
          Some(data)=>{
              InitData{
                  malloc:data.malloc,
                  rand:ChaCha20Rng::from_rng(&mut data.rand).unwrap()
              }
          }
          None=>{
              let malloc:fn(usize)->*mut c_void=transmute(dlsym(RTDL_NEXT as *mut c_void, b"malloc\0".as_ptr()));
              let read:fn(c_int,*mut u8,usize)->isize=transmute(dlsym(RTDL_DEFAULT as *mut c_void, b"read\0".as_ptr()));
              let open:fn(*const u8,c_int)->c_int=transmute(dlsym(RTDL_DEFAULT as *mut c_void, b"open\0".as_ptr()));
              let mut seed:[u8;32]=[0;32];
              read(open(b"/dev/urandom\0".as_ptr(),0),seed.as_mut_ptr(),seed.len());
              let mut rand=ChaCha20Rng::from_seed(seed);
              let second_rand=ChaCha20Rng::from_rng(&mut rand).unwrap();
              INIT_DATA=Some(InitData{
                  malloc,rand
              });
              InitData{
                  malloc,
                  rand:second_rand
              }
          }
      }
    };
    //unlock spinlock
    FLAG.store(false, core::sync::atomic::Ordering::Release);
    data
}


#[no_mangle]
pub extern "C" fn malloc(size:usize)->*mut c_void{
    let mut init_data=get_init_data();
    unsafe{
        let ptr=(init_data.malloc)(size);
        if !ptr.is_null(){
            let slice=from_raw_parts_mut(ptr.cast::<u8>(), size);
            init_data.rand.fill(slice);
        }
        ptr
    }

}

#[link(name="dl")]
extern {
    fn dlsym(handle:*mut c_void,symbol:*const u8)->*const c_void;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
       transmute::<*const c_void,fn ()->!>(dlsym(RTDL_DEFAULT as *mut c_void, b"abort\0".as_ptr()))();
    }
}
