use std::ffi::{c_void};
use minhook_sys::*;
use windows_sys::w;
use windows::core::{PCWSTR};
use winapi::shared::ntdef::{LPCWSTR};

pub struct ACEbypass;

type FnLoadLibraryW = extern "C" fn(LPCWSTR) -> *const c_void;
static mut ORIGNAL_LOAD_LIBRARY_W: usize = 0;
static mut TARGET_LOAD_LIBRARY_W: usize = 0;

impl ACEbypass {
    pub unsafe fn init() {
        Self::hook_ace_new();
    }

    pub unsafe fn hook_ace_new() {
        MH_Initialize();

        let mut porignal: FnLoadLibraryW = ACEbypass::new_load_library_w;
        let pporignal = &mut porignal as *mut FnLoadLibraryW as *mut *mut c_void;
        let mut ptarget: FnLoadLibraryW = ACEbypass::new_load_library_w;
        let pptarget = &mut ptarget as *mut FnLoadLibraryW as *mut *mut c_void;
        let base = w!("kernelbase");
        let func = c"LoadLibraryW".to_bytes_with_nul().as_ptr() as *const i8;
        if MH_CreateHookApiEx(base, func, ACEbypass::new_load_library_w as *mut c_void, pporignal, pptarget) != MH_OK {
            println!("Failed to create hook for LoadLibraryW function");
            return
        }
        // println!("ptarget = {:?}, porignal = {:?}", ptarget, porignal);

        if MH_EnableHook(ptarget as *mut c_void) != MH_OK {
            println!("Failed to enable hook for LoadLibraryW function");
            return
        }

        ORIGNAL_LOAD_LIBRARY_W = porignal as usize;
        TARGET_LOAD_LIBRARY_W = ptarget as usize;
    }

    #[no_mangle]
    extern "C" fn new_load_library_w(lplibfilename: LPCWSTR) -> *const c_void
    {
        unsafe {
            let name = PCWSTR::from_raw(lplibfilename).to_string().unwrap_or(String::from(""));
            // println!("filename = {}", name);

            if name.contains("ACE-Base64.dll") {
                if MH_DisableHook(TARGET_LOAD_LIBRARY_W as *mut c_void) != MH_OK {
                    println!("Failed to disable hook for LoadLibraryW function");
                }

                println!("ACE has been bypassed, driver: {name}");
                return std::ptr::null();
            }

            let fn_orig = std::mem::transmute::<usize, FnLoadLibraryW>(ORIGNAL_LOAD_LIBRARY_W);
            fn_orig(lplibfilename)
        }
    }
}

