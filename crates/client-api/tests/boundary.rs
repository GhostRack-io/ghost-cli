use gigahost_client_api::api::{ALL, Access, Endpoint, GetOffering};

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
    gigahost_client_api::endpoints! {
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
