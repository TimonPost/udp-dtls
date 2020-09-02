 [![Latest Version][s1]][l1] [![MIT][s2]][l2] [![docs][s3]][l3] 

This library is an DTLS openssl abstraction that can be used with `std::net::UdpSocket`. 
In order to use this library, install openssl.

The following features are supported:

- [x] Dtls Acceptor for accepting incomming connections
- [x] Dtls Connector for connecting to remote hosts
- [x] Dtls Stream for sending receiving encrypted data over udp
- [x] Shutdown connection
- [x] Certificates
- [ ] Multiple connections to one connection (server/client)

[s1]: https://img.shields.io/crates/v/udp-dtls.svg
[l1]: https://crates.io/crates/udp-dtls

[s2]: https://img.shields.io/badge/license-MIT-blue.svg
[l2]: udp-dtls/LICENSE

[s3]: https://docs.rs/udp-dtls/badge.svg
[l3]: https://docs.rs/udp-dtls/
