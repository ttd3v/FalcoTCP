use std::{
    ffi::CString,
    io::{Error, ErrorKind},
    os::raw::c_ushort,
    str::FromStr,
};

use crate::MessageHeaders;
use crate::falco_pipeline::Var;
/*
typedef struct {
    int fd;
    #if TLS
    SSL* ssl;
    SSL_CTX* ctx;
    #endif
    #if !BLOCKING
    unsigned char *input;
    unsigned char *output;
    MessageHeaders headers[2];
    usize readen;
    usize writen;
    PcAsync processing;
    #endif
} PrimitiveClient;
*/

#[repr(C)]
pub struct Client {
    _fd: i32,
    #[cfg(feature = "tls")]
    _ssl: *mut std::ffi::c_void,
    #[cfg(feature = "tls")]
    _ssl_context: *mut std::ffi::c_void,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            _fd: -1,
            #[cfg(feature = "tls")]
            _ssl: std::ptr::null_mut(),
            #[cfg(feature = "tls")]
            _ssl_context: std::ptr::null_mut(),
        }
    }
}
fn zero() -> Client {
    Client::default()
}

#[repr(C)]
struct Settings {
    host: *mut i8,
    port: c_ushort,
    #[cfg(feature = "tls")]
    domain: *mut i8,
}

/*
*
* typedef struct {
    char* host;
    u_int16_t port;
    #if TLS
        char* domain;
    #endif
} PrimitiveClientSettings;
*/
impl Client {
    pub fn new(host: &str, port: u16, #[cfg(feature = "tls")] domain: &str) -> Result<Self, Error> {
        let host = match CString::from_str(host) {
            Ok(a) => a,
            Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
        };
        #[cfg(feature = "tls")]
        let domain_cstring =
            CString::from_str(domain).map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        let mut settings = Settings {
            host: host.as_ptr() as *mut i8,
            port,
            #[cfg(feature = "tls")]
            domain: domain_cstring.as_ptr() as *mut i8,
        };
        let mut client = zero();
        let a = unsafe { pc_create(&mut client, &mut settings) };
        if a >= 0 {
            #[cfg(not(feature = "async"))]
            unsafe {
                pc_set_timeout(&mut client, 30_000_000)
            }
            #[cfg(feature = "async")]
            unsafe {
                pc_set_timeout(&mut client, 12)
            };
            Ok(client)
        } else {
            Err(Error::from_raw_os_error(a))
        }
    }
    pub fn set_timeout(&mut self, micro_secs: usize) {
        unsafe { pc_set_timeout(self, micro_secs) };
    }
    #[cfg(not(feature = "async"))]
    pub fn request(&mut self, input: &[u8], var: &Var) -> Result<Vec<u8>, Error> {
        use crate::falco_pipeline::{pipeline_receive, pipeline_send};

        let input = input.to_vec();
        let (compression, mut value) = pipeline_send(input, var)?;
        let input_headers = MessageHeaders {
            compr_alg: compression,
            size: value.len() as u64,
        };
        {
            let res = unsafe { pc_input_request(self, value.as_mut_ptr(), input_headers) };
            if res < 0 {
                return Err(Error::from_raw_os_error(-res));
            }
        }
        drop(value);
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut headers: MessageHeaders = MessageHeaders::default();
        {
            let res = unsafe { pc_output_request(self, &raw mut buf, &mut headers) };
            if res < 0 {
                return Err(Error::from_raw_os_error(-res));
            }
        }
        let vec = unsafe { Vec::from_raw_parts(buf, headers.size as usize, headers.size as usize) };
        match pipeline_receive(headers.compr_alg, vec, var) {
            Ok(a) => Ok(a),
            Err(e) => Err(e),
        }
    }
    #[cfg(feature = "async")]
    pub async fn request(&mut self, input: &[u8], var: &Var) -> Result<Vec<u8>, Error> {
        use tokio::task::spawn_blocking;
        let self_ptr = (&raw mut *self) as usize;
        let input = input.to_vec();
        let v_ptr = (var as *const Var) as usize;
        match spawn_blocking(move || -> Result<Vec<u8>, Error> {
            use crate::falco_pipeline::{pipeline_receive, pipeline_send};
            let s = unsafe { &mut *(self_ptr as *mut Client) };
            let input = input;
            let var = unsafe { &*(v_ptr as *const Var) };
            let (compression, mut value) = pipeline_send(input, var)?;
            let input_headers = MessageHeaders {
                compr_alg: compression,
                size: value.len() as u64,
            };
            println!("+++\n");
            {
                let res = unsafe { pc_input_request(s, value.as_mut_ptr(), input_headers) };
                if res < 0 {
                    return Err(Error::from_raw_os_error(-res));
                }
            }
            drop(value);
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut headers: MessageHeaders = MessageHeaders::default();
            println!("---");
            {
                let res = unsafe { pc_output_request(s, &raw mut buf, &mut headers) };
                if res < 0 {
                    return Err(Error::from_raw_os_error(-res));
                }
            }
            println!("---\n+++\n");
            let vec =
                unsafe { Vec::from_raw_parts(buf, headers.size as usize, headers.size as usize) };
            match pipeline_receive(headers.compr_alg, vec, var) {
                Ok(a) => Ok(a),
                Err(e) => Err(e),
            }
        })
        .await
        {
            Ok(a) => a,
            Err(e) => Err(Error::other(e)),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        unsafe { pc_clean(self) };
    }
}

#[link(name = "raw_client")]
unsafe extern "C" {
    fn pc_create(c: &mut Client, settings: *mut Settings) -> i32;
    fn pc_set_timeout(c: &mut Client, micro_secs: usize);
    fn pc_input_request(c: &mut Client, buf: *mut u8, headers: MessageHeaders) -> i32;
    fn pc_output_request(c: &mut Client, buf: *mut *mut u8, headers: &mut MessageHeaders) -> i32;

    fn pc_clean(c: &mut Client);
}
