use openssl::ssl::{SslMethod, SslStreamBuilder};
use std::{
    io::{Read, Write},
    net::UdpSocket,
    thread,
    time::Duration,
};

use udp_dtls::{Certificate, DtlsAcceptor, DtlsConnector, Identity, SrtpProfile};
use udp_dtls::{DtlsAcceptorBuilder, UdpChannel};

fn main() {
    dtls_listen();
}

pub fn server_client() {
    let buffer = include_bytes!("../test/identity.p12");
    let identity = Identity::from_pkcs12(buffer, "mypass").unwrap();

    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = Certificate::from_der(root_ca).unwrap();

    let acceptor = DtlsAcceptor::builder(identity).build().unwrap();
    let connector = DtlsConnector::builder()
        .add_srtp_profile(SrtpProfile::Aes128CmSha180)
        .add_srtp_profile(SrtpProfile::AeadAes256Gcm)
        .add_root_certificate(root_ca)
        .build()
        .unwrap();

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();

    let server_channel = UdpChannel {
        socket: server,
        remote_addr: Some(client_addr),
    };

    let client_channel = UdpChannel {
        socket: client,
        remote_addr: Some(server_addr),
    };

    let guard = thread::spawn(move || {
        let mut dtls_server = acceptor.accept(server_channel).unwrap();

        let mut count = 0;

        while true {
            let mut received = [0; 5];

            dtls_server.read_exact(&mut received);

            println!(
                "{:?} {:?}",
                count,
                String::from_utf8_lossy(received.as_ref())
            );

            count = count + 1;
            thread::sleep(Duration::from_millis(2));
        }
    });

    let mut dtls_client = connector.connect("foobar.com", client_channel).unwrap();

    while true {
        let mut buf = [0; 5];

        let buf = b"hello";
        dtls_client.write_all(buf);

        thread::sleep(Duration::from_millis(30));
    }
}

pub fn multiple_connections() {
    let buffer = include_bytes!("../test/identity.p12");
    let identity = Identity::from_pkcs12(buffer, "mypass").unwrap();

    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = Certificate::from_der(root_ca).unwrap();

    let connector = DtlsConnector::builder()
        .add_srtp_profile(SrtpProfile::Aes128CmSha180)
        .add_srtp_profile(SrtpProfile::AeadAes256Gcm)
        .add_root_certificate(root_ca)
        .build()
        .unwrap();

    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();

    let server_channel = UdpChannel {
        socket: server,
        remote_addr: None,
    };

    let client_channel = UdpChannel {
        socket: client,
        remote_addr: Some(server.local_addr().unwrap()),
    };

    // start sending with client
    let guard = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));

        let mut dtls_client = connector.connect("foobar.com", client_channel).unwrap();

        while true {
            let mut buf = [0; 5];

            let buf = b"hello";
            dtls_client.write_all(buf);

            thread::sleep(Duration::from_millis(200));
        }
    });

    // listen for incoming connections.
    let result = udp_dtls::dtls_listen(server_channel);

    println!("New connection: {:?}", result);
}
