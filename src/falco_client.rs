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
    use std::thread::{sleep, spawn};
    use std::time::Duration;

    #[cfg(feature = "encryption")]
    fn get() -> Aes256Gcm {
        let mut key = [0u8; 32];
        {
            use rand::TryRngCore;
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key).unwrap();
        }
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    const MAX_CLIENTS: usize = 2;
    const NEEDED_REQS: usize = 100;
    let var: Var = Var {
        #[cfg(feature = "encryption")]
        cipher: get(),
        #[cfg(not(feature = "heuristics"))]
        compression: CompressionAlgorithm::None,
    };
    let variable = var.clone();
    let server = Networker::new("127.0.0.1", 9090, 10, (MAX_CLIENTS * 2) as u16).unwrap();
    let lock = Arc::new(Mutex::new(false));
    let locka = lock.clone();
    let mut requests = 0;
    let server_handle = spawn(move || {
        let mut server = server;
        server.cycle();

        {
            let mut a = locka.lock().unwrap();
            *a = true;
        }
        loop {
            server.cycle();

            if let Some(c) = server.get_client() {
                //println!("[SERVER] request!");
                use crate::falco_pipeline::{pipeline_receive, pipeline_send};
                requests += 1;
                let (cmpr, value) = c.get_request();
                let payload = pipeline_receive(cmpr.into(), value, &variable).unwrap();

                let res = pipeline_send(payload.iter().map(|f| !*f).collect(), &variable).unwrap();
                c.apply_response(res.1, res.0.into()).unwrap();
                //println!("[SERVER] responded!");
                if requests == MAX_CLIENTS * NEEDED_REQS {
                    println!("[SERVER] finishing...");
                    break;
                }
            } else {
                //println!("Sleeeep, requests:{}\n", requests);
                sleep(Duration::from_millis(10));
            }
        }
    });

    loop {
        use std::thread::yield_now;

        let ready = lock.lock().unwrap();
        if *ready {
            break;
        }
        drop(ready);
        yield_now();
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
            sleep(Duration::from_millis(10));
            let b = FalcoClient::new(1, variable.clone(), "127.0.0.1", 9090).unwrap();
            let n = Instant::now();
            for i in 0..=NEEDED_REQS {
                use rand::random_range;
                //println!("client {} is at {}", k, i);
                let len = random_range(1..(1024 * 1024));
                let buffer = vec![0u8; len];
                let response = match b.request(buffer, 1) {
                    Ok(a) => a,
                    Err(e) => {
                        if i + 1 == NEEDED_REQS {
                            return;
                        }
                        panic!("{}", e);
                    }
                };
                assert_eq!(response.len(), len);
                if i + 1 == NEEDED_REQS {
                    break;
                }
            }
            eprintln!("CLIENT({}) -> {}ns", k, n.elapsed().as_nanos());
        }));
    }

    for i in handlers {
        i.join().unwrap();
    }
    server_handle.join().unwrap();
}
#[cfg(all(
    feature = "falco-server",
    feature = "falco-client",
    not(feature = "tls"),
    feature = "async"
))]
#[tokio::test(flavor = "current_thread", start_paused = false)]
async fn server_client() {
    #[cfg(not(feature = "heuristics"))]
    use crate::enums::CompressionAlgorithm;
    use crate::networker::Networker;
    #[cfg(feature = "encryption")]
    use aes_gcm::{Aes256Gcm, KeyInit};
    use std::time::Duration;
    use tokio::{spawn, time::sleep};

    #[cfg(feature = "encryption")]
    fn get() -> Aes256Gcm {
        let mut key = [0u8; 32];
        {
            use rand::TryRngCore;
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key).unwrap();
        }
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    const MAX_CLIENTS: usize = 2;
    const NEEDED_REQS: usize = 100;
    let var: Var = Var {
        #[cfg(feature = "encryption")]
        cipher: get(),
        #[cfg(not(feature = "heuristics"))]
        compression: CompressionAlgorithm::None,
    };
    let variable = var.clone();
    let server = Networker::new("127.0.0.1", 9090, 10, (MAX_CLIENTS * 2) as u16).unwrap();
    let lock = Arc::new(Mutex::new(false));
    let locka = lock.clone();
    let mut requests = 0;
    let server_handle = spawn(async move {
        let mut server = server;
        server.cycle().await.unwrap();

        {
            let mut a = locka.lock().await;
            *a = true;
        }
        loop {
            server.cycle().await.unwrap();

            if let Some(c) = server.get_client().await {
                println!("[SERVER] request!");
                use crate::falco_pipeline::{pipeline_receive, pipeline_send};
                requests += 1;
                let (cmpr, value) = c.get_request().await;
                let payload = pipeline_receive(cmpr.into(), value, &variable).unwrap();

                let res = pipeline_send(payload.iter().map(|f| !*f).collect(), &variable).unwrap();
                c.apply_response(res.1, res.0.into()).await.unwrap();
                println!("[SERVER] responded!");
                if requests == MAX_CLIENTS * NEEDED_REQS {
                    println!("[SERVER] finishing...");
                    break;
                }
            } else {
                use tokio::task::yield_now;
                //println!("Sleeeep, requests:{}\n", requests);
                yield_now().await;
            }
        }
    });

    loop {
        use std::thread::yield_now;

        let ready = lock.lock().await;
        if *ready {
            break;
        }
        drop(ready);
        yield_now();
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
        handlers.push(spawn(async move {
            sleep(Duration::from_millis(10)).await;
            let b = FalcoClient::new(1, variable.clone(), "127.0.0.1", 9090).unwrap();
            let n = Instant::now();
            for i in 0..=NEEDED_REQS {
                use rand::random_range;
                //println!("client {} is at {}", k, i);
                let len = random_range(1..(1024 * 1024));
                let buffer = vec![0u8; len];
                let response = match b.request(buffer, 1).await {
                    Ok(a) => a,
                    Err(e) => {
                        if i + 1 == NEEDED_REQS {
                            return;
                        }
                        panic!("{}", e);
                    }
                };
                assert_eq!(response.len(), len);
                if i + 1 == NEEDED_REQS {
                    break;
                }
            }
            eprintln!("CLIENT({}) -> {}ns", k, n.elapsed().as_nanos());
        }));
    }

    let mut er = Vec::new();
    for i in handlers {
        er.push(i.await);
    }
    if requests != NEEDED_REQS * MAX_CLIENTS {
        for i in er {
            i.unwrap();
        }
    }
    server_handle.await.unwrap();
}

#[cfg(all(
    feature = "falco-server",
    feature = "falco-client",
    feature = "tls",
    not(feature = "async")
))]
#[test]
fn server_client() {
    #[cfg(not(feature = "heuristics"))]
    use crate::enums::CompressionAlgorithm;
    use crate::networker::Networker;
    #[cfg(feature = "encryption")]
    use aes_gcm::{Aes256Gcm, KeyInit};
    use std::thread::{sleep, spawn};
    use std::time::Duration;

    #[cfg(feature = "encryption")]
    fn get() -> Aes256Gcm {
        let mut key = [0u8; 32];
        {
            use rand::TryRngCore;
            use rand::rngs::OsRng;
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut key).unwrap();
        }
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    use rcgen::generate_simple_self_signed;
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let v = generate_simple_self_signed(subject_alt_names).unwrap();

    {
        let _ = std::fs::remove_file("/tmp/cert.pem");
        let _ = std::fs::remove_file("/tmp/key.pem");
    }

    std::fs::write("/tmp/cert.pem", v.cert.pem()).unwrap();
    std::fs::write("/tmp/key.pem", v.signing_key.serialize_pem()).unwrap();

    const MAX_CLIENTS: usize = 2;
    const NEEDED_REQS: usize = 100;
    let var: Var = Var {
        #[cfg(feature = "encryption")]
        cipher: get(),
        #[cfg(not(feature = "heuristics"))]
        compression: CompressionAlgorithm::None,
        password: [
            128u8, 102u8, 30u8, 123u8, 1u8, 10u8, 23u8, 90u8, 255u8, 0u8, 128u8, 127u8, 77u8, 99u8,
            11u8, 22u8, 0u8, 254u8, 100u8, 70u8, 17u8, 91u8, 25u8, 88u8, 1u8, 2u8, 3u8, 9u8, 230u8,
            130u8, 100u8, 33u8,
        ],
    };
    let variable = var.clone();
    let server = Networker::new(
        "127.0.0.1",
        9090,
        10,
        (MAX_CLIENTS * 2) as u16,
        "/tmp/cert.pem",
        "/tmp/key.pem",
    )
    .unwrap();
    let lock = Arc::new(Mutex::new(false));
    let locka = lock.clone();
    let mut requests = 0;
    let server_handle = spawn(move || {
        let mut server = server;
        server.cycle();

        {
            let mut a = locka.lock().unwrap();
            *a = true;
        }
        loop {
            server.cycle();

            if let Some(c) = server.get_client() {
                //println!("[SERVER] request!");
                use crate::falco_pipeline::{pipeline_receive, pipeline_send};
                requests += 1;
                let (cmpr, value) = c.get_request();
                let payload = pipeline_receive(cmpr.into(), value, &variable).unwrap();

                let res = pipeline_send(payload.iter().map(|f| !*f).collect(), &variable).unwrap();
                c.apply_response(res.1, res.0.into()).unwrap();
                //println!("[SERVER] responded!");
                if requests == MAX_CLIENTS * NEEDED_REQS {
                    println!("[SERVER] finishing...");
                    break;
                }
            } else {
                //println!("Sleeeep, requests:{}\n", requests);
                sleep(Duration::from_millis(10));
            }
        }
    });

    loop {
        use std::thread::yield_now;

        let ready = lock.lock().unwrap();
        if *ready {
            break;
        }
        drop(ready);
        yield_now();
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
            sleep(Duration::from_millis(10));
            let b = FalcoClient::new(1, variable.clone(), "127.0.0.1", 9090, "localhost").unwrap();
            let n = Instant::now();
            for i in 0..=NEEDED_REQS {
                use rand::random_range;
                //println!("client {} is at {}", k, i);
                let len = random_range(1..(1024 * 1024));
                let buffer = vec![0u8; len];
                let response = match b.request(buffer, 1) {
                    Ok(a) => a,
                    Err(e) => {
                        if i + 1 == NEEDED_REQS {
                            return;
                        }
                        panic!("{}", e);
                    }
                };
                assert_eq!(response.len(), len);
                if i + 1 == NEEDED_REQS {
                    break;
                }
            }
            eprintln!("CLIENT({}) -> {}ns", k, n.elapsed().as_nanos());
        }));
    }

    for i in handlers {
        i.join().unwrap();
    }
    server_handle.join().unwrap();
}
