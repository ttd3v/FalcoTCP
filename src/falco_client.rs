use crate::{client::Client, falco_pipeline::Var};
use std::io::Error;
use std::time::Instant;

#[cfg(not(feature = "tokio-runtime"))]
use std::sync::{Arc, Mutex, RwLock};

#[cfg(feature = "tokio-runtime")]
use std::sync::Arc;
#[cfg(feature = "tokio-runtime")]
use tokio::sync::{Mutex, RwLock};

pub struct FalcoClient {
    pub var: Var,
    pub pool: Arc<RwLock<Vec<Arc<Mutex<Client>>>>>,
    target: (String, u16),
    clock: Instant,
    timeout: usize,
    #[cfg(feature = "tls")]
    domain: String,
    pool_len: usize,
}

impl FalcoClient {
    pub fn new(
        clients: usize,
        parameters: Var,
        host: &str,
        port: u16,
        #[cfg(feature = "tls")] domain: &str,
    ) -> Result<Self, Error> {
        let mut v = Vec::with_capacity(clients);
        for _ in 0..clients {
            v.push(Arc::new(Mutex::new(Client::new(
                host,
                port,
                #[cfg(feature = "tls")]
                domain,
            )?)));
        }
        #[cfg(feature = "dev-redundancies")]
        v.shrink_to_fit(); // redundant
        Ok(FalcoClient {
            var: parameters,
            pool: Arc::new(RwLock::new(v)),
            target: (host.to_string(), port),
            clock: Instant::now(),
            #[cfg(feature = "tls")]
            domain: domain.to_string(),
            timeout: 1_000_000,
            pool_len: clients,
        })
    }
    #[cfg(not(feature = "async"))]
    fn get_handle(&self) -> (Arc<Mutex<Client>>, usize) {
        let index = self.clock.elapsed().as_nanos() as usize % self.pool_len;
        (self.pool.read().unwrap()[index].clone(), index)
    }
    #[cfg(feature = "async")]
    async fn get_handle(&self) -> (Arc<Mutex<Client>>, usize) {
        let index = self.clock.elapsed().as_nanos() as usize % self.pool_len;
        let arc = { self.pool.read().await[index].clone() };
        (arc, index)
    }
    #[cfg(not(feature = "async"))]
    pub fn request(&self, input: Vec<u8>, allow_mitigation: u8) -> Result<Vec<u8>, Error> {
        let (s, k) = self.get_handle();
        match s.lock().unwrap().request(&input, &self.var) {
            Ok(a) => Ok(a),
            Err(e) => {
                use std::io::ErrorKind;

                if e.kind() == ErrorKind::ConnectionAborted && allow_mitigation > 0 {
                    self.mitigate(input, k, allow_mitigation)
                } else {
                    Err(e)
                }
            }
        }
    }
    #[cfg(feature = "async")]
    pub async fn request(&self, input: Vec<u8>, allow_mitigation: u8) -> Result<Vec<u8>, Error> {
        let (s, k) = self.get_handle().await;
        match s.lock().await.request(&input, &self.var).await {
            Ok(a) => Ok(a),
            Err(e) => {
                use std::io::ErrorKind;

                if e.kind() == ErrorKind::ConnectionAborted && allow_mitigation > 0 {
                    Box::pin(self.mitigate(input, k, allow_mitigation)).await
                } else {
                    Err(e)
                }
            }
        }
    }
    #[cfg(not(feature = "async"))]
    fn mitigate(&self, input: Vec<u8>, key: usize, allow_mitigation: u8) -> Result<Vec<u8>, Error> {
        self.pool.write().unwrap().swap_remove(key);
        self.generate(1)?;
        self.request(input, allow_mitigation - 1)
    }
    #[cfg(not(feature = "async"))]
    pub fn generate(&self, count: usize) -> Result<(), Error> {
        let mut pool = self.pool.write().unwrap();
        #[cfg(not(feature = "dev-redundancies"))]
        pool.reserve(count);
        #[cfg(feature = "dev-redundancies")]
        pool.reserve_exact(count);
        for _ in 0..count {
            let mut c = Client::new(
                &self.target.0,
                self.target.1,
                #[cfg(feature = "tls")]
                &self.domain,
            )?;
            c.set_timeout(self.timeout);
            pool.push(Arc::new(Mutex::new(c)));
        }
        Ok(())
    }

    #[cfg(feature = "async")]
    async fn mitigate(
        &self,
        input: Vec<u8>,
        key: usize,
        allow_mitigation: u8,
    ) -> Result<Vec<u8>, Error> {
        self.pool.write().await.swap_remove(key);
        self.generate(1).await?;
        self.request(input, allow_mitigation - 1).await
    }
    #[cfg(feature = "async")]
    pub async fn generate(&self, count: usize) -> Result<(), Error> {
        let mut pool = self.pool.write().await;
        #[cfg(not(feature = "dev-redundancies"))]
        pool.reserve(count);
        #[cfg(feature = "dev-redundancies")]
        pool.reserve_exact(count);
        for _ in 0..count {
            let mut c = Client::new(
                &self.target.0,
                self.target.1,
                #[cfg(feature = "tls")]
                &self.domain,
            )?;
            c.set_timeout(self.timeout);
            pool.push(Arc::new(Mutex::new(c)));
        }
        Ok(())
    }

    #[cfg(not(feature = "tokio"))]
    pub fn set_timeout(&mut self, new_timeout: usize) {
        self.timeout = new_timeout;
        for i in self.pool.read().unwrap().iter() {
            i.lock().unwrap().set_timeout(new_timeout);
        }
    }
    #[cfg(feature = "tokio")]
    pub async fn set_timeout(&mut self, new_timeout: usize) {
        self.timeout = new_timeout;
        for i in self.pool.read().await.iter() {
            i.lock().await.set_timeout(new_timeout);
        }
    }
    pub fn cheap_set_timeout(&mut self, new_timeout: usize) {
        self.timeout = new_timeout;
    }
}

#[cfg(all(
    feature = "falco-server",
    feature = "falco-client",
    not(feature = "tls"),
    not(feature = "async")
))]
#[test]
fn server_client() {
    #[cfg(not(feature = "heuristics"))]
    use crate::enums::CompressionAlgorithm;
    use crate::networker::Networker;
    #[cfg(feature = "encryption")]
    use aes_gcm::{Aes256Gcm, KeyInit};
    use rand::rngs::OsRng;
    use std::hash::DefaultHasher;
    use std::thread::{sleep, spawn};
    use std::time::Duration;

    #[cfg(feature = "encryption")]
    fn get() -> Aes256Gcm {
        let mut key = [0u8; 32];
        {
            use rand::TryRngCore;
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key).unwrap();
        }
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    const MAX_CLIENTS: usize = 1;
    const NEEDED_REQS: usize = 10;
    let var: Var = Var {
        #[cfg(feature = "encryption")]
        cipher: get(),
        #[cfg(not(feature = "heuristics"))]
        compression: CompressionAlgorithm::None,
    };
    let variable = var.clone();
    let server = Networker::new("127.0.0.1", 9090, 10, (MAX_CLIENTS * 2) as u16).unwrap();
    let you_should_break_yourself_gently = Arc::new(Mutex::new(false));
    let lock = Arc::new(Mutex::new(false));
    let locka = lock.clone();
    let ysbysg = you_should_break_yourself_gently.clone();
    let server_handle = spawn(move || {
        let mut server = server;
        server.cycle();

        {
            let mut a = locka.lock().unwrap();
            *a = true;
        }
        loop {
            use std::thread::yield_now;

            server.cycle();

            if let Some(c) = server.get_client() {
                use crate::falco_pipeline::{pipeline_receive, pipeline_send};

                let (cmpr, value) = c.get_request();
                let payload = pipeline_receive(cmpr.into(), value, &variable).unwrap();

                let res = pipeline_send(payload.iter().map(|f| !*f).collect(), &variable).unwrap();
                c.apply_response(res.1, res.0.into()).unwrap();
                if *ysbysg.lock().unwrap() {
                    break;
                }
            }
            yield_now();
        }
    });

    loop {
        let ready = lock.lock().unwrap();
        if *ready {
            break;
        }
        drop(ready);
        sleep(Duration::from_micros(10));
    }

    println!("Testing direct connection...");
    let test_sock = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:9090".parse().unwrap(),
        Duration::from_secs(1),
    );
    println!("Direct connection result: {:?}", test_sock);

    let mut handlers = vec![];
    for k in 0..MAX_CLIENTS {
        let variable = var.clone();
        handlers.push(spawn(move || {
            let b = FalcoClient::new(1, variable.clone(), "127.0.0.1", 9090).unwrap();
            let n = Instant::now();
            for _ in 0..NEEDED_REQS {
                use std::thread::yield_now;

                let buffer = vec![0u8; 8];
                let response = b.request(buffer, 255).unwrap();
                assert_eq!(response.len(), 8);
                yield_now();
            }
            eprintln!("CLIENT({}) -> {}ns", k, n.elapsed().as_nanos());
        }));
    }

    for i in handlers {
        i.join().unwrap();
    }
    *you_should_break_yourself_gently.lock().unwrap() = true;
    server_handle.join().unwrap();
}
