use std::path::PathBuf;

use bytes::Bytes;
use nfsembed::rpc::gss::{
    AcceptContext, GssInitiatorProvider, GssProvider, InitiateContext, ProviderContextId, ProviderError,
    SspiGssInitiator, SspiGssProvider, Version,
};

const SERVER_PRINCIPAL: &str = "nfs/server.nfsembed.test@NFSEMBED.TEST";
const CLIENT_PRINCIPAL: &str = "client@NFSEMBED.TEST";

struct EstablishedPair {
    acceptor: SspiGssProvider,
    initiator: SspiGssInitiator,
    acceptor_context: ProviderContextId,
    initiator_context: ProviderContextId,
}

async fn establish(version: Version) -> EstablishedPair {
    let server_keytab = required_path("NFSEMBED_GSS_SERVER_KEYTAB");
    let client_keytab = required_path("NFSEMBED_GSS_CLIENT_KEYTAB");
    let acceptor = SspiGssProvider::from_keytab_path(SERVER_PRINCIPAL, server_keytab)
        .await
        .expect("load server keytab");
    let initiator = SspiGssInitiator::from_keytab_path(CLIENT_PRINCIPAL, client_keytab)
        .await
        .expect("load client keytab");

    let mut client = initiator
        .initiate_security_context(None, version, SERVER_PRINCIPAL, Bytes::new())
        .await
        .expect("start Kerberos initiator");
    let mut server_continuation: Option<AcceptContext> = None;
    let mut client_continuation: Option<InitiateContext>;

    for _ in 0..8 {
        let server = acceptor
            .accept_security_context(server_continuation.take(), version, client.output_token.clone())
            .await
            .expect("accept Kerberos token");
        server_continuation = Some(server.context.clone());
        assert!(matches!(server.major_status, 0 | 1), "unexpected GSS major status {}", server.major_status);

        client_continuation = Some(client.context.clone());
        client = initiator
            .initiate_security_context(
                client_continuation.take(),
                version,
                SERVER_PRINCIPAL,
                server.output_token.clone(),
            )
            .await
            .expect("continue Kerberos initiator");

        if server.is_complete() && client.complete {
            assert!(
                server
                    .complete_identity
                    .as_ref()
                    .expect("completed acceptor identity")
                    .principal
                    .eq_ignore_ascii_case(CLIENT_PRINCIPAL),
                "acceptor returned an unexpected client principal"
            );
            assert!(client.output_token.is_empty(), "completed initiator emitted an unexpected final token");
            return EstablishedPair {
                acceptor,
                initiator,
                acceptor_context: server.context.provider_context,
                initiator_context: client.context.provider_context,
            };
        }
        assert!(!client.output_token.is_empty(), "incomplete Kerberos exchange emitted no continuation token");
    }

    panic!("Kerberos context establishment exceeded the bounded continuation count");
}

fn required_path(name: &str) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| panic!("{name} is required for the real-KDC test"));
    let path = PathBuf::from(value);
    assert!(path.is_file(), "{name} does not identify a keytab file");
    path
}

async fn assert_protection(pair: &EstablishedPair) {
    let message = Bytes::from_static(b"nfsembed real-KDC RPCSEC_GSS protection");

    let client_mic = pair
        .initiator
        .get_mic(pair.initiator_context, message.clone())
        .await
        .expect("initiator MIC");
    pair.acceptor
        .verify_mic(pair.acceptor_context, message.clone(), client_mic.clone())
        .await
        .expect("acceptor verifies initiator MIC");
    let mut tampered_mic = client_mic.to_vec();
    *tampered_mic.last_mut().expect("MIC is non-empty") ^= 0x80;
    assert!(matches!(
        pair.acceptor
            .verify_mic(pair.acceptor_context, message.clone(), Bytes::from(tampered_mic))
            .await,
        Err(ProviderError::Integrity | ProviderError::InvalidToken)
    ));

    let server_mic = pair
        .acceptor
        .get_mic(pair.acceptor_context, message.clone())
        .await
        .expect("acceptor MIC");
    pair.initiator
        .verify_mic(pair.initiator_context, message.clone(), server_mic)
        .await
        .expect("initiator verifies acceptor MIC");

    for confidentiality in [false, true] {
        let client_token = pair
            .initiator
            .wrap(pair.initiator_context, message.clone(), confidentiality)
            .await
            .expect("initiator wrap");
        assert_eq!(
            pair.acceptor
                .unwrap(pair.acceptor_context, client_token)
                .await
                .expect("acceptor unwrap"),
            message
        );

        let server_token = pair
            .acceptor
            .wrap(pair.acceptor_context, message.clone(), confidentiality)
            .await
            .expect("acceptor wrap");
        assert_eq!(
            pair.initiator
                .unwrap(pair.initiator_context, server_token)
                .await
                .expect("initiator unwrap"),
            message
        );
    }
}

async fn assert_wrap_tampering_is_rejected(pair: &EstablishedPair, confidentiality: bool) {
    let message = Bytes::from_static(b"nfsembed tamper detection");
    let mut client_token = pair
        .initiator
        .wrap(pair.initiator_context, message, confidentiality)
        .await
        .expect("initiator wrap for tampering")
        .to_vec();
    *client_token.last_mut().expect("wrap token is non-empty") ^= 0x80;
    assert!(matches!(
        pair.acceptor.unwrap(pair.acceptor_context, Bytes::from(client_token)).await,
        Err(ProviderError::Privacy | ProviderError::Integrity | ProviderError::InvalidToken)
    ));
}

async fn delete_pair(pair: EstablishedPair) {
    let deleted_probe = Bytes::from_static(b"deleted context probe");
    pair.initiator
        .delete_security_context(pair.initiator_context)
        .await
        .expect("delete initiator context");
    assert!(matches!(
        pair.initiator.get_mic(pair.initiator_context, deleted_probe.clone()).await,
        Err(ProviderError::UnknownContext)
    ));
    pair.acceptor
        .delete_security_context(pair.acceptor_context)
        .await
        .expect("delete acceptor context");
    assert!(matches!(
        pair.acceptor.get_mic(pair.acceptor_context, deleted_probe).await,
        Err(ProviderError::UnknownContext)
    ));
}

#[tokio::test]
#[ignore = "requires the Docker Compose NFSEMBED.TEST KDC and mounted keytabs"]
async fn portable_sspi_round_trips_against_real_kdc_for_rpcsec_gss_v1_and_v2() {
    for version in [Version::V1, Version::V2] {
        let pair = establish(version).await;
        assert_protection(&pair).await;
        delete_pair(pair).await;

        for confidentiality in [false, true] {
            let pair = establish(version).await;
            assert_wrap_tampering_is_rejected(&pair, confidentiality).await;
            delete_pair(pair).await;
        }
    }
}
