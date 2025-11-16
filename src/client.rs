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

#[repr(i32)]
#[cfg(feature = "async")]
enum Pcasync {
    Done = 5,
}
#[repr(C)]
#[derive(Default)]
pub struct Client {
    _fd: i32,
    #[cfg(feature = "tls")]
    _ssl: usize,
    #[cfg(feature = "tls")]
    _ssl_context: usize,
    #[cfg(feature = "async")]
    _input: usize,
    #[cfg(feature = "async")]
    _output: usize,
    #[cfg(feature = "async")]
    _msg_headers: [MessageHeaders; 2],
    #[cfg(feature = "async")]
    _readen: usize,
    #[cfg(feature = "async")]
    _writen: usize,
    #[cfg(feature = "async")]
    processing: i32,
    #[cfg(feature = "async")]
    timeout_time: usize,
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
            unsafe { pc_set_timeout(&mut client, 1000000) };
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
        println!("+++\n");
        {
            let res = unsafe { pc_input_request(self, value.as_mut_ptr(), input_headers) };
            if res < 0 {
                return Err(Error::from_raw_os_error(res));
            }
        }
        drop(value);
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut headers: MessageHeaders = MessageHeaders::default();
        println!("---");
        {
            let res = unsafe { pc_output_request(self, &raw mut buf, &mut headers) };
            if res < 0 {
                return Err(Error::from_raw_os_error(res));
            }
        }
        println!("---\n+++\n");
        let vec = unsafe { Vec::from_raw_parts(buf, headers.size as usize, headers.size as usize) };
        match pipeline_receive(headers.compr_alg, vec, var) {
            Ok(a) => Ok(a),
            Err(e) => Err(e),
        }
    }
    #[cfg(feature = "async")]
    pub async fn request(&mut self, input: &[u8], var: &Var) -> Result<Vec<u8>, Error> {
        let cron = self.timeout_time;
        use tokio::time::timeout;

        use crate::falco_pipeline::{pipeline_receive, pipeline_send};
        use std::time::Duration;

        let input = input.to_vec();
        let (compression, mut value) = match pipeline_send(input, var) {
            Ok(a) => a,
            Err(e) => return Err(e),
        };
        let input_headers = MessageHeaders {
            compr_alg: compression,
            size: value.len() as u64,
        };
        let action = async {
            {
                let res = unsafe { pc_async_input(self, input_headers, value.as_mut_ptr()) };
                if res < 0 {
                    return Err(Error::from_raw_os_error(res));
                }
            }
            while self.processing != Pcasync::Done as i32 {
                tokio::task::yield_now().await;
                let res = unsafe { pc_async_step(self) };
                if res < 0 {
                    return Err(Error::from_raw_os_error(res));
                }
            }
            let mut output_headers = MessageHeaders::default();
            let buffer: *mut u8 = std::ptr::null_mut();
            let res = unsafe { pc_async_output(self, &mut output_headers, &buffer) };
            if res < 0 {
                return Err(Error::from_raw_os_error(res));
            }
            let output = unsafe {
                Vec::from_raw_parts(
                    buffer,
                    output_headers.size as usize,
                    output_headers.size as usize,
                )
            };
            let response = match pipeline_receive(output_headers.compr_alg, output, var) {
                Ok(a) => a,
                Err(e) => return Err(e),
            };
            Ok(response)
        };

        match timeout(Duration::from_micros(cron as u64), action).await {
            Ok(result) => result,
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "timeout")),
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
    #[cfg(not(feature = "async"))]
    fn pc_input_request(c: &mut Client, buf: *mut u8, headers: MessageHeaders) -> i32;
    #[cfg(not(feature = "async"))]
    fn pc_output_request(c: &mut Client, buf: *mut *mut u8, headers: &mut MessageHeaders) -> i32;
    #[cfg(feature = "async")]
    fn pc_async_input(c: &mut Client, headers: MessageHeaders, buffer: *mut u8) -> i32;
    #[cfg(feature = "async")]
    fn pc_async_output(c: &mut Client, headers: &mut MessageHeaders, buffer: &*mut u8) -> i32;
    #[cfg(feature = "async")]
    fn pc_async_step(c: &mut Client) -> i32;
    fn pc_clean(c: &mut Client);
}
