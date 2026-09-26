//! WebAuthn calls with the PRF extension, for a window context (the vault iframe).
//!
//! The option objects are built with `js-sys` because `web-sys` does not model the PRF
//! extension. Errors are coarse: the browser's own error text never leaves this module.

use super::{
    Assertion, COSE_ALGORITHMS, LoginRequest, PrfOutput, Registration, RegistrationRequest,
    unlock_prf_input,
};
use crate::Error;
use js_sys::{Array, ArrayBuffer, Function, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

fn set(target: &Object, key: &str, value: &JsValue) -> Result<(), Error> {
    Reflect::set(target, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|_| Error::Browser)
}

fn get(target: &JsValue, key: &str) -> Result<JsValue, Error> {
    Reflect::get(target, &JsValue::from_str(key)).map_err(|_| Error::Browser)
}

fn bytes(value: &[u8]) -> JsValue {
    Uint8Array::from(value).into()
}

fn read_bytes(value: &JsValue) -> Result<Vec<u8>, Error> {
    if value.is_instance_of::<ArrayBuffer>() {
        return Ok(Uint8Array::new(value).to_vec());
    }
    if let Some(view) = value.dyn_ref::<Uint8Array>() {
        return Ok(view.to_vec());
    }
    Err(Error::Browser)
}

fn credential_list(ids: &[Vec<u8>]) -> Result<JsValue, Error> {
    let list = Array::new();
    for id in ids {
        let descriptor = Object::new();
        set(&descriptor, "type", &JsValue::from_str("public-key"))?;
        set(&descriptor, "id", &bytes(id))?;
        list.push(&descriptor);
    }
    Ok(list.into())
}

fn prf_extension() -> Result<Object, Error> {
    let first = Object::new();
    set(&first, "first", &bytes(&unlock_prf_input()))?;
    let prf = Object::new();
    set(&prf, "eval", &first)?;
    let extensions = Object::new();
    set(&extensions, "prf", &prf)?;
    Ok(extensions)
}

fn credentials() -> Result<web_sys::CredentialsContainer, Error> {
    // Workers have no `window`: WebAuthn is unavailable there by design.
    let window = web_sys::window().ok_or(Error::NoWindow)?;
    Ok(window.navigator().credentials())
}

/// The PRF result, when the authenticator evaluated it.
fn prf_result(credential: &JsValue) -> Result<(bool, Option<PrfOutput>), Error> {
    let method = get(credential, "getClientExtensionResults")?
        .dyn_into::<Function>()
        .map_err(|_| Error::Browser)?;
    let results = method.call0(credential).map_err(|_| Error::Browser)?;
    let prf = get(&results, "prf")?;
    if prf.is_undefined() || prf.is_null() {
        return Ok((false, None));
    }
    let enabled = get(&prf, "enabled")?.as_bool().unwrap_or(false);
    let evaluated = get(&prf, "results")?;
    if evaluated.is_undefined() || evaluated.is_null() {
        return Ok((enabled, None));
    }
    let first = read_bytes(&get(&evaluated, "first")?)?;
    Ok((true, Some(PrfOutput::from_bytes(&first)?)))
}

/// Create a passkey. Returns the registration for `cpky` and, if the authenticator
/// evaluated the PRF at creation, the unlock secret (otherwise call [`login`] next).
pub async fn register(
    request: &RegistrationRequest,
) -> Result<(Registration, Option<PrfOutput>), Error> {
    request.validate()?;
    let rp = Object::new();
    set(&rp, "id", &JsValue::from_str(&request.rp.id))?;
    set(&rp, "name", &JsValue::from_str(&request.rp.name))?;
    let user = Object::new();
    set(&user, "id", &bytes(&request.user_id))?;
    set(&user, "name", &JsValue::from_str(&request.user_name))?;
    set(
        &user,
        "displayName",
        &JsValue::from_str(&request.user_display_name),
    )?;
    let params = Array::new();
    for alg in COSE_ALGORITHMS {
        let param = Object::new();
        set(&param, "type", &JsValue::from_str("public-key"))?;
        set(&param, "alg", &JsValue::from_f64(f64::from(alg)))?;
        params.push(&param);
    }
    let selection = Object::new();
    set(&selection, "residentKey", &JsValue::from_str("required"))?;
    set(
        &selection,
        "userVerification",
        &JsValue::from_str("required"),
    )?;

    let public_key = Object::new();
    set(&public_key, "rp", &rp)?;
    set(&public_key, "user", &user)?;
    set(&public_key, "challenge", &bytes(&request.challenge))?;
    set(&public_key, "pubKeyCredParams", &params)?;
    set(&public_key, "authenticatorSelection", &selection)?;
    set(
        &public_key,
        "excludeCredentials",
        &credential_list(&request.exclude_credentials)?,
    )?;
    set(
        &public_key,
        "timeout",
        &JsValue::from_f64(f64::from(request.timeout_ms)),
    )?;
    set(&public_key, "attestation", &JsValue::from_str("none"))?;
    set(&public_key, "extensions", &prf_extension()?)?;
    let options = Object::new();
    set(&options, "publicKey", &public_key)?;

    let promise = credentials()?
        .create_with_options(options.unchecked_ref::<web_sys::CredentialCreationOptions>())
        .map_err(|_| Error::Browser)?;
    let credential = JsFuture::from(promise)
        .await
        .map_err(|_| Error::Cancelled)?;
    if credential.is_null() || credential.is_undefined() {
        return Err(Error::Cancelled);
    }
    let response = get(&credential, "response")?;
    let (prf_enabled, prf) = prf_result(&credential)?;
    Ok((
        Registration {
            credential_id: read_bytes(&get(&credential, "rawId")?)?,
            client_data_json: read_bytes(&get(&response, "clientDataJSON")?)?,
            attestation_object: read_bytes(&get(&response, "attestationObject")?)?,
            prf_enabled,
        },
        prf,
    ))
}

/// Sign a login challenge with a passkey and evaluate the unlock PRF.
pub async fn login(request: &LoginRequest) -> Result<(Assertion, Option<PrfOutput>), Error> {
    request.validate()?;
    let public_key = Object::new();
    set(&public_key, "rpId", &JsValue::from_str(&request.rp_id))?;
    set(&public_key, "challenge", &bytes(&request.challenge))?;
    set(
        &public_key,
        "allowCredentials",
        &credential_list(&request.allow_credentials)?,
    )?;
    set(
        &public_key,
        "userVerification",
        &JsValue::from_str("required"),
    )?;
    set(
        &public_key,
        "timeout",
        &JsValue::from_f64(f64::from(request.timeout_ms)),
    )?;
    set(&public_key, "extensions", &prf_extension()?)?;
    let options = Object::new();
    set(&options, "publicKey", &public_key)?;

    let promise = credentials()?
        .get_with_options(options.unchecked_ref::<web_sys::CredentialRequestOptions>())
        .map_err(|_| Error::Browser)?;
    let credential = JsFuture::from(promise)
        .await
        .map_err(|_| Error::Cancelled)?;
    if credential.is_null() || credential.is_undefined() {
        return Err(Error::Cancelled);
    }
    let response = get(&credential, "response")?;
    let user_handle = get(&response, "userHandle")?;
    let (_, prf) = prf_result(&credential)?;
    Ok((
        Assertion {
            credential_id: read_bytes(&get(&credential, "rawId")?)?,
            client_data_json: read_bytes(&get(&response, "clientDataJSON")?)?,
            authenticator_data: read_bytes(&get(&response, "authenticatorData")?)?,
            signature: read_bytes(&get(&response, "signature")?)?,
            user_handle: if user_handle.is_null() || user_handle.is_undefined() {
                None
            } else {
                Some(read_bytes(&user_handle)?)
            },
        },
        prf,
    ))
}

/// Unlock: a login whose only purpose is the PRF secret. Fails with
/// [`Error::PrfUnsupported`] when the authenticator does not evaluate the PRF.
pub async fn unlock(request: &LoginRequest) -> Result<(Assertion, PrfOutput), Error> {
    let (assertion, prf) = login(request).await?;
    Ok((assertion, prf.ok_or(Error::PrfUnsupported)?))
}
