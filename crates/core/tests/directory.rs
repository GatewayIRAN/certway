use certway_core::{Client, Json, Method};

#[test]
#[ignore]
fn fetches_letsencrypt_directory() {
    let client = Client::new().expect("client construction with embedded root");
    let response = client
        .request(
            Method::Get,
            "https://acme-v02.api.letsencrypt.org/directory",
            None,
            None,
        )
        .expect("request to the letsencrypt directory endpoint");

    assert_eq!(response.status, 200);

    let json = Json::parse(&response.body).expect("directory response is valid json");
    assert!(json.has("newNonce"));
    assert!(json.has("newAccount"));
    assert!(json.has("newOrder"));
}
