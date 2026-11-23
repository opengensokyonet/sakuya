//! When the endpoint counts a NEW_TOKEN token as accepted, on the loopback
//! interface.

use super::*;
use frunk_core::coproduct::Coproduct;
use sakuya_endpoint_v1::address_token::{NewTokenAddress, NewTokenIssuer as _};

#[test]
fn a_new_token_of_an_initial_dropped_on_a_full_queue_is_accepted_later() {
    run(async {
        let tokens = aead_tokens();
        let mut config = server_config_with(tokens.clone());
        config.quotas.incoming_queue_capacity = NonZeroUsize::new(2).unwrap();
        let server = server_on(config);
        let mut incoming = server.endpoint.incoming();
        let socket = bind();
        let peer: PeerOf<Udp> = Coproduct::inject(socket.local_address());
        let link = within("a link to the server", socket.connect(server.address))
            .await
            .unwrap();
        let scid = [0x5c; 4];
        let token = AddressTokens::<PeerOf<Udp>>::new_token_issuer(&tokens)
            .issue(&peer, UtcDateTime::now())
            .unwrap();

        // Two incoming connections fill the queue; a Retry to an Initial
        // without a token shows that both wait.
        send_on(&link, long_packet(true, &[0x01; 8], &scid, 1200)).await;
        send_on(&link, long_packet(true, &[0x02; 8], &scid, 1200)).await;
        within("the queue is full", async {
            loop {
                send_on(&link, long_packet(true, &[0x0f; 8], &scid, 1200)).await;
                if tokio::time::timeout(Duration::from_millis(100), link.recv())
                    .await
                    .is_ok()
                {
                    break;
                }
            }
        })
        .await;

        // The Initial with the token is admitted, then dropped on the full
        // queue.
        let with_token = initial_with_token(&[0x03; 8], &scid, &token, 1200);
        send_on(&link, with_token.clone()).await;
        within("the Initial is dropped on the full queue", async {
            while server.endpoint.dropped_input_counts().incoming_queue_full == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        // The client sends its Initial again once there is room: the
        // dropped one did not use the token.
        let Some(Incoming::Terminable(first)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        send_on(&link, with_token).await;
        let mut halves = Vec::new();
        for _ in 0..2 {
            let Some(Incoming::Terminable(half)) =
                within("an incoming connection", incoming.next()).await
            else {
                panic!("the server endpoint ends before a connection comes");
            };
            halves.push(half);
        }
        assert_eq!(halves[0].facts().token, ReturnedToken::Absent);
        assert_eq!(
            halves[1].facts().token,
            ReturnedToken::NewToken(NewTokenAddress::Validated)
        );
        drop((first, halves));
    });
}
