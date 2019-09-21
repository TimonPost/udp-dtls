#[allow(unused_imports)]

mod tests {
    use std::io::{Read, Write};
    use std::net::UdpSocket;
    use std::thread;
    use std::time::Duration;

    use openssl::ssl::SslMethod;

    use crate::{Certificate, DtlsAcceptor, DtlsConnector, Identity, SrtpProfile};
    use crate::{DtlsAcceptorBuilder, UdpChannel};

    #[test]
    fn test_sync() {
        let buf = include_bytes!("../test/identity.p12");
        let identity = Identity::from_pkcs12(buf, "mypass").unwrap();

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
            remote_addr: client_addr,
        };

        let client_channel = UdpChannel {
            socket: client,
            remote_addr: server_addr,
        };

        let guard = thread::spawn(move || {
            let mut dtls_server = acceptor.accept(server_channel).unwrap();

            let mut count = 0;

            while true {
                let mut buf = [0; 5];

                dtls_server.read_exact(&mut buf);

                println!("{:?} {:?}", count, buf);

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
}
