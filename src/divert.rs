//! Minimal runtime-loaded WinDivert 2.2 binding.
//!
//! WinDivert.dll and the signed WinDivert64.sys are embedded in the exe and
//! unpacked next to it (or into %LOCALAPPDATA%\ProxyApp) on first start.

use std::ffi::{CString, c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libloading::Library;

static DLL_BYTES: &[u8] = include_bytes!("../vendor/windivert/WinDivert.dll");
static SYS_BYTES: &[u8] = include_bytes!("../vendor/windivert/WinDivert64.sys");

pub type Handle = *mut c_void;
const INVALID: Handle = -1isize as Handle;

pub const MTU_MAX: usize = 40 + 0xFFFF;

pub const PARAM_QUEUE_LENGTH: u32 = 0;
pub const PARAM_QUEUE_TIME: u32 = 1;
pub const PARAM_QUEUE_SIZE: u32 = 2;

/// `WINDIVERT_ADDRESS` (80 bytes). Bitfields of the first dword:
/// Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 IPChecksum:1 TCPChecksum:1 UDPChecksum:1
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub bits: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

const OUTBOUND_BIT: u32 = 1 << 17;

impl Address {
    pub fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
    #[cfg(test)]
    pub fn is_outbound(&self) -> bool {
        self.bits & OUTBOUND_BIT != 0
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.bits |= OUTBOUND_BIT;
        } else {
            self.bits &= !OUTBOUND_BIT;
        }
    }
}

type OpenFn = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> Handle;
type RecvFn = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(Handle, u32) -> i32;
type CloseFn = unsafe extern "C" fn(Handle) -> i32;
type SetParamFn = unsafe extern "C" fn(Handle, u32, u64) -> i32;
type CalcChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

pub struct Api {
    _lib: Library,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    set_param: SetParamFn,
    calc: CalcChecksumsFn,
}

fn write_if_needed(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if std::fs::metadata(path).map(|m| m.len() == bytes.len() as u64).unwrap_or(false) {
        return Ok(());
    }
    std::fs::write(path, bytes).map_err(|e| format!("не удалось записать {}: {e}", path.display()))
}

fn unpack_into(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    write_if_needed(&dir.join("WinDivert.dll"), DLL_BYTES)?;
    write_if_needed(&dir.join("WinDivert64.sys"), SYS_BYTES)?;
    Ok(())
}

/// Folder holding WinDivert.dll + WinDivert64.sys, unpacking them if needed.
fn files_dir() -> Result<PathBuf, String> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    if let Some(dir) = &exe_dir {
        if dir.join("WinDivert.dll").exists() && dir.join("WinDivert64.sys").exists() {
            return Ok(dir.clone());
        }
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or(exe_dir)
        .ok_or("нет папки для WinDivert")?;
    let dir = base.join("ProxyApp").join("windivert");
    unpack_into(&dir)?;
    // Antivirus may delete the files right after they are written.
    if !dir.join("WinDivert64.sys").exists() || !dir.join("WinDivert.dll").exists() {
        return Err(format!(
            "Антивирус удалил WinDivert из {}. Добавь эту папку в исключения Defender.",
            dir.display()
        ));
    }
    Ok(dir)
}

impl Api {
    pub fn load() -> Result<Arc<Api>, String> {
        let dir = files_dir()?;
        unsafe {
            let lib = Library::new(dir.join("WinDivert.dll"))
                .map_err(|e| format!("не удалось загрузить WinDivert.dll: {e}"))?;
            macro_rules! sym {
                ($name:literal) => {
                    *lib.get(concat!($name, "\0").as_bytes())
                        .map_err(|e| format!("WinDivert.dll: нет {}: {e}", $name))?
                };
            }
            let open: OpenFn = sym!("WinDivertOpen");
            let recv: RecvFn = sym!("WinDivertRecv");
            let send: SendFn = sym!("WinDivertSend");
            let shutdown: ShutdownFn = sym!("WinDivertShutdown");
            let close: CloseFn = sym!("WinDivertClose");
            let set_param: SetParamFn = sym!("WinDivertSetParam");
            let calc: CalcChecksumsFn = sym!("WinDivertHelperCalcChecksums");
            Ok(Arc::new(Api { _lib: lib, open, recv, send, shutdown, close, set_param, calc }))
        }
    }

    /// Opens a network-layer handle.
    pub fn open(self: &Arc<Self>, filter: &str, priority: i16) -> Result<Divert, String> {
        let c = CString::new(filter).map_err(|e| e.to_string())?;
        let h = unsafe { (self.open)(c.as_ptr(), 0, priority, 0) };
        if h == INVALID || h.is_null() {
            let e = std::io::Error::last_os_error();
            let hint = match e.raw_os_error() {
                Some(2) => "не найден драйвер WinDivert64.sys",
                Some(5) => "нужны права администратора",
                Some(87) => "неверный фильтр",
                Some(577) => "драйвер не прошёл проверку подписи",
                Some(1275) => "драйвер заблокирован (антивирус / Защита памяти)",
                Some(1753) => "служба Base Filtering Engine выключена",
                _ => "",
            };
            return Err(format!("WinDivert не открылся: {e} {hint}"));
        }
        Ok(Divert { api: self.clone(), h })
    }

    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut Address) {
        unsafe {
            (self.calc)(packet.as_mut_ptr() as *mut c_void, packet.len() as u32, addr, 0);
        }
    }
}

pub struct Divert {
    api: Arc<Api>,
    h: Handle,
}

// The WinDivert handle is a kernel object handle, safe to use from several threads.
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

impl Divert {
    pub fn api(&self) -> &Api {
        &self.api
    }

    pub fn set_param(&self, param: u32, value: u64) {
        unsafe {
            (self.api.set_param)(self.h, param, value);
        }
    }

    /// Blocks until a packet arrives; returns its length, or the Win32 error code
    /// (232 once the handle is shut down).
    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> Result<usize, i32> {
        let mut len = 0u32;
        let ok = unsafe {
            (self.api.recv)(self.h, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, &mut len, addr)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        Ok(len as usize)
    }

    pub fn send(&self, packet: &[u8], addr: &Address) -> bool {
        unsafe {
            (self.api.send)(
                self.h,
                packet.as_ptr() as *const c_void,
                packet.len() as u32,
                std::ptr::null_mut(),
                addr,
            ) != 0
        }
    }

    /// Wakes up a blocked `recv` and stops further packets.
    pub fn shutdown(&self) {
        unsafe {
            (self.api.shutdown)(self.h, 3);
        }
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.h);
        }
    }
}
