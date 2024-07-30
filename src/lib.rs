#![feature(str_from_utf16_endian)]

use lazy_static::lazy_static;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

mod version;
mod acebypass;

use version::VersionDllProxy;
use acebypass::ACEbypass;

unsafe fn thread_func() {
    Console::AllocConsole().unwrap_or(());

    // minhook ace
    ACEbypass::init();
}

lazy_static! {
    static ref VERSION_DLL_PROXY: version::VersionDllProxy =
        VersionDllProxy::new().expect("Failed to load version.dll");
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        VERSION_DLL_PROXY
            .load_functions()
            .expect("Failed to load functions from version.dll");

        std::thread::spawn(|| thread_func());
    }

    true
}
