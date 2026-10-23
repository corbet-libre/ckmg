#![no_main]
//! Bytes another member or device hands over: a peer's lineage read capability and the lineage wire documents
//! (lineage, pairing request and grant, root envelope, rotation, key certificate). Decoding, and every check that
//! needs no private context, must return an error and never panic.
use ckmg::{
    Binding, KeyCertificate, Lineage, LineageReadCustody, PairingGrant, PairingRequest,
    RootEnvelope, Rotation,
};
use libfuzzer_sys::fuzz_target;

const NOW: u64 = 1_800_000_000;

fuzz_target!(|data: &[u8]| {
    let expected = Binding::new("community", "member").expect("a fixed valid binding");
    let _ = LineageReadCustody::from_capability(data, &expected);

    // The first half is read as a lineage, the second half as the document that is checked against it.
    let (first, second) = data.split_at(data.len() / 2);
    let lineage = serde_json::from_slice::<Lineage>(first).ok();
    if let Some(lineage) = &lineage {
        let _ = lineage.verify();
    }
    if let Ok(request) = serde_json::from_slice::<PairingRequest>(data) {
        let _ = request.verify(NOW);
    }
    let _ = serde_json::from_slice::<PairingGrant>(data);
    let _ = serde_json::from_slice::<RootEnvelope>(data);
    if let (Ok(rotation), Some(lineage)) = (serde_json::from_slice::<Rotation>(second), &lineage) {
        let _ = rotation.verify(lineage);
    }
    let _ = serde_json::from_slice::<KeyCertificate>(second);
});
