fn main() {
    #[cfg(feature = "server")]
    {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rerun-if-changed=native/numbers.h");
        println!("cargo:rerun-if-changed=native/net.h");
        println!("cargo:rerun-if-changed=native/net.c");

        if std::env::var("CARGO_FEATURE_SERVER").is_ok() {
            let mut build = cc::Build::new();
            build.file("native/net.c").include("native");

            build.flag("-O3");
            #[cfg(feature = "native")]
            {
                build.flag("-march=native");
            }
            #[cfg(feature = "tls")]
            {
                build.flag("-D__tls__=1");
                println!("cargo:rustc-link-lib=static=ssl");
                println!("cargo:rustc-link-lib=static=crypto");
            }

            #[cfg(not(feature = "dynamic-uring-link"))]
            println!("cargo:rustc-link-lib=static=uring");
            #[cfg(feature = "dynamic-uring-link")]
            println!("cargo:rustc-link-lib=uring");
            build.compile("networker");
        }
    }
    #[cfg(feature = "client")]
    {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rerun-if-changed=native/numbers.h");
        println!("cargo:rerun-if-changed=native/net.h");
        println!("cargo:rerun-if-changed=native/raw_client.c");
        if std::env::var("CARGO_FEATURE_CLIENT").is_ok() {
            let mut build = cc::Build::new();
            build.file("native/raw_client.c").include("native");

            build.flag("-O3");
            #[cfg(feature = "native")]
            {
                build.flag("-march=native");
            }
            #[cfg(feature = "tls")]
            {
                build.flag("-DTLS=1");
                println!("cargo:rustc-link-lib=ssl");
                println!("cargo:rustc-link-lib=crypto");
            }

            build.compile("raw_client");
        }
    }
}
