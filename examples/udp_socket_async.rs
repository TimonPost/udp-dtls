use std::time::Duration;
use futures::pin_mut;
use tokio::{net, time, io::{AsyncReadExt, AsyncWriteExt}};
use udp_dtls::{Certificate, DtlsAcceptor, DtlsConnector, CertificateIdentity, SrtpProfile, AsyncUdpChannel};

#[tokio::main]
async fn main() {
    let buffer = include_bytes!("../test/identity.p12");
    let identity = CertificateIdentity::from_pkcs12(buffer, "mypass").unwrap();

    let root_ca = include_bytes!("../test/root-ca.der");
    let root_ca = Certificate::from_der(root_ca).unwrap();

    let acceptor = DtlsAcceptor::builder(identity).build().unwrap();
    let connector = DtlsConnector::builder()
        .add_srtp_profile(SrtpProfile::Aes128CmSha180)
        .add_srtp_profile(SrtpProfile::AeadAes256Gcm)
        .add_root_certificate(root_ca)
        .build()
        .unwrap();

    let server = net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();

    let server_channel = AsyncUdpChannel {
        socket: server,
        remote_addr: client_addr,
    };

    let client_channel = AsyncUdpChannel {
        socket: client,
        remote_addr: server_addr,
    };

    let connector_task = async move {
        let stream = connector.async_connect("foobar.com", client_channel).await.unwrap();

        pin_mut!(stream);
        loop {
            let buf = b"hello";
            stream.write_all(buf).await.unwrap();

            time::delay_for(Duration::from_millis(30)).await;
        }
    };

    let acceptor_task = async move {
        let stream = acceptor.async_accept(server_channel).await.unwrap();
        let mut count = 0;

        pin_mut!(stream);
        loop {
            let mut received = [0; 5];

            stream.read_exact(&mut received).await.unwrap();

            println!(
                "{:?} {:?}",
                count,
                String::from_utf8_lossy(received.as_ref())
            );

            count = count + 1;

            time::delay_for(Duration::from_millis(2)).await;
        }
    };

    tokio::spawn(connector_task);
    tokio::spawn(acceptor_task).await.unwrap();
}
