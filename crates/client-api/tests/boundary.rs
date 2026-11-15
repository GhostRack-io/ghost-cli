use ghostrack_client_api::api::{ALL, Access, Endpoint, GetOffering};

#[test]
fn customer_routes_are_unique_and_escape_parameters() {
    assert!(!ALL.is_empty());
    let mut seen = std::collections::BTreeSet::new();
    for listing in ALL {
        assert!(
            matches!(
                listing.access,
                Access::Public | Access::User | Access::Wallet
            ),
            "{}",
            listing.route
        );
        assert!(seen.insert((listing.method.as_str(), listing.route)));
    }
    assert_eq!(
        GetOffering {
            offering_id: "../a?b".to_owned()
        }
        .path(),
        "/v1/catalog/offerings/..%2Fa%3Fb"
    );
}

mod external_macro_consumer {
    ghostrack_client_api::endpoints! {
        Probe { name: String } = user GET "/probe/{name}" => String;
    }
}

#[test]
fn endpoint_macro_uses_its_own_trait_and_escapes_caller_parameters() {
    let probe = external_macro_consumer::Probe {
        name: "../a?b".to_owned(),
    };
    assert_eq!(Endpoint::path(&probe), "/probe/..%2Fa%3Fb");
    assert_eq!(external_macro_consumer::DECLARED.len(), 1);
    assert_eq!(external_macro_consumer::DECLARED[0].access, Access::User);
}

/// A request that drops `limit_mbit` is refused, not read as `null`: a
/// client that lost the field must never lift the limit its renter set
/// (item 284). `null` clears it, and the field is always written.
#[test]
fn a_bandwidth_limit_request_names_its_limit() {
    use ghostrack_client_api::website::SetInstanceBandwidthLimitRequest as Request;
    let read = |text: &str| serde_json::from_str::<Request>(text);
    assert_eq!(read(r#"{"limit_mbit": 40}"#).unwrap().limit_mbit, Some(40));
    assert_eq!(read(r#"{"limit_mbit": null}"#).unwrap().limit_mbit, None);
    assert!(read("{}").is_err());
    assert!(read(r#"{"limit":40}"#).is_err());
    assert!(read(r#"{"limit_mbit": 40, "other": 1}"#).is_err());
    assert_eq!(
        serde_json::to_string(&Request { limit_mbit: None }).unwrap(),
        r#"{"limit_mbit":null}"#
    );
}
