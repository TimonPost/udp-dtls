This library is a DTLS abstraction that can be used for `std::net::UdpSocket`. This library is based on tokio-dtls, and is in experiment face for laminar.

The following features are supported

- [x] Dtls Acceptor for accepting incomming connections
- [x] Dtls Connector for connecting to remote hosts
- [x] Dtls Stream for sending receiving encrypted data over udp
- [x] Shutdown connection
- [x] Certificates