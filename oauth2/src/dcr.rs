use crate::basic::BasicErrorResponseType;
use crate::endpoint::{endpoint_request, endpoint_response};
use crate::types::{ClientName, DynamicClientRegistrationUrl, VerificationUriComplete};
use crate::{
    AsyncHttpClient, AuthType, Client, EndUserVerificationUrl, EndpointNotSet, ErrorResponse,
    ErrorResponseType, HttpRequest, RequestTokenError, RevocableToken, Scope,
    StandardErrorResponse, SyncHttpClient, TokenIntrospectionResponse, TokenResponse, UserCode,
};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::borrow::Cow;
use std::error::Error;
use std::fmt::Error as FormatterError;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;

impl<TE, TR, TIR, RT, TRE>
    Client<
        TE,
        TR,
        TIR,
        RT,
        TRE,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
    >
where
    TE: ErrorResponse + 'static,
    TR: TokenResponse,
    TIR: TokenIntrospectionResponse,
    RT: RevocableToken,
    TRE: ErrorResponse + 'static,
{
    pub(crate) fn dynamic_client_registration_impl<'a>(
        client_name: Cow<'a, ClientName>,
        scopes: Vec<Cow<'a, Scope>>,
        dynamic_client_registration_url: &'a DynamicClientRegistrationUrl,
    ) -> DynamicClientRegistrationRequest<'a, TE> {
        DynamicClientRegistrationRequest {
            client_name,
            extra_params: Vec::new(),
            scopes,
            dynamic_client_registration_url,
            _phantom: PhantomData,
        }
    }
}

/// The request for a set of verification codes from the authorization server.
///
/// See <https://tools.ietf.org/html/rfc8628#section-3.1>.
#[derive(Debug)]
pub struct DynamicClientRegistrationRequest<'a, TE>
where
    TE: ErrorResponse,
{
    pub(crate) client_name: Cow<'a, ClientName>,
    pub(crate) extra_params: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub(crate) scopes: Vec<Cow<'a, Scope>>,
    pub(crate) dynamic_client_registration_url: &'a DynamicClientRegistrationUrl,
    pub(crate) _phantom: PhantomData<TE>,
}

impl<'a, TE> DynamicClientRegistrationRequest<'a, TE>
where
    TE: ErrorResponse + 'static,
{
    /// Appends an extra param to the token request.
    ///
    /// This method allows extensions to be used without direct support from
    /// this crate. If `name` conflicts with a parameter managed by this crate, the
    /// behavior is undefined. In particular, do not set parameters defined by
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749) or
    /// [RFC 7636](https://tools.ietf.org/html/rfc7636).
    ///
    /// # Security Warning
    ///
    /// Callers should follow the security recommendations for any OAuth2 extensions used with
    /// this function, which are beyond the scope of
    /// [RFC 6749](https://tools.ietf.org/html/rfc6749).
    pub fn add_extra_param<N, V>(mut self, name: N, value: V) -> Self
    where
        N: Into<Cow<'a, str>>,
        V: Into<Cow<'a, str>>,
    {
        self.extra_params.push((name.into(), value.into()));
        self
    }

    /// Appends a new scope to the token request.
    pub fn add_scope(mut self, scope: Scope) -> Self {
        self.scopes.push(Cow::Owned(scope));
        self
    }

    /// Appends a collection of scopes to the token request.
    pub fn add_scopes<I>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = Scope>,
    {
        self.scopes.extend(scopes.into_iter().map(Cow::Owned));
        self
    }

    fn prepare_request<RE>(self) -> Result<HttpRequest, RequestTokenError<RE, TE>>
    where
        RE: Error + 'static,
    {
        endpoint_request(
            &AuthType::BasicAuth,
            None,
            None,
            &self.extra_params,
            None,
            Some(&self.scopes),
            self.dynamic_client_registration_url.url(),
            vec![],
        )
        .map_err(|err| RequestTokenError::Other(format!("failed to prepare request: {err}")))
    }

    /// Synchronously sends the request to the authorization server and awaits a response.
    pub fn request<C, EF>(
        self,
        http_client: &C,
    ) -> Result<
        DynamicClientRegistrationResponse<EF>,
        RequestTokenError<<C as SyncHttpClient>::Error, TE>,
    >
    where
        C: SyncHttpClient,
        EF: ExtraDeviceAuthorizationFields,
    {
        endpoint_response(http_client.call(self.prepare_request()?)?)
    }

    /// Asynchronously sends the request to the authorization server and returns a Future.
    pub fn request_async<'c, C, EF>(
        self,
        http_client: &'c C,
    ) -> impl Future<
        Output = Result<
            DynamicClientRegistrationResponse<EF>,
            RequestTokenError<<C as AsyncHttpClient<'c>>::Error, TE>,
        >,
    > + 'c
    where
        Self: 'c,
        C: AsyncHttpClient<'c>,
        EF: ExtraDeviceAuthorizationFields,
    {
        Box::pin(async move { endpoint_response(http_client.call(self.prepare_request()?).await?) })
    }
}

/// The minimum amount of time in seconds that the client SHOULD wait
/// between polling requests to the token endpoint.  If no value is
/// provided, clients MUST use 5 as the default.
fn default_devicecode_interval() -> u64 {
    5
}

fn deserialize_devicecode_interval<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    struct NumOrNull;

    impl<'de> serde::de::Visitor<'de> for NumOrNull {
        type Value = u64;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("non-negative integer or null")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(v)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(default_devicecode_interval())
        }
    }

    deserializer.deserialize_any(NumOrNull)
}

/// Trait for adding extra fields to the `DynamicClientRegistrationResponse`.
pub trait ExtraDeviceAuthorizationFields: DeserializeOwned + Debug + Serialize {}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// Empty (default) extra token fields.
pub struct EmptyExtraDeviceAuthorizationFields {}
impl ExtraDeviceAuthorizationFields for EmptyExtraDeviceAuthorizationFields {}

/// Standard OAuth2 device authorization response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DynamicClientRegistrationResponse<EF>
where
    EF: ExtraDeviceAuthorizationFields,
{
    /// The end-user verification code.
    user_code: UserCode,

    /// The end-user verification URI on the authorization The URI should be
    /// short and easy to remember as end users will be asked to manually type
    /// it into their user agent.
    ///
    /// The `verification_url` alias here is a deviation from the RFC, as
    /// implementations of device authorization flow predate RFC 8628.
    #[serde(alias = "verification_url")]
    verification_uri: EndUserVerificationUrl,

    /// A verification URI that includes the "user_code" (or other information
    /// with the same function as the "user_code"), which is designed for
    /// non-textual transmission.
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri_complete: Option<VerificationUriComplete>,

    /// The lifetime in seconds of the "device_code" and "user_code".
    expires_in: u64,

    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.  If no value is
    /// provided, clients MUST use 5 as the default.
    #[serde(
        default = "default_devicecode_interval",
        deserialize_with = "deserialize_devicecode_interval"
    )]
    interval: u64,

    #[serde(bound = "EF: ExtraDeviceAuthorizationFields", flatten)]
    extra_fields: EF,
}

impl<EF> DynamicClientRegistrationResponse<EF>
where
    EF: ExtraDeviceAuthorizationFields,
{
    /// The end-user verification code.
    pub fn user_code(&self) -> &UserCode {
        &self.user_code
    }

    /// The end-user verification URI on the authorization The URI should be
    /// short and easy to remember as end users will be asked to manually type
    /// it into their user agent.
    pub fn verification_uri(&self) -> &EndUserVerificationUrl {
        &self.verification_uri
    }

    /// A verification URI that includes the "user_code" (or other information
    /// with the same function as the "user_code"), which is designed for
    /// non-textual transmission.
    pub fn verification_uri_complete(&self) -> Option<&VerificationUriComplete> {
        self.verification_uri_complete.as_ref()
    }

    /// The lifetime in seconds of the "device_code" and "user_code".
    pub fn expires_in(&self) -> Duration {
        Duration::from_secs(self.expires_in)
    }

    /// The minimum amount of time in seconds that the client SHOULD wait
    /// between polling requests to the token endpoint.  If no value is
    /// provided, clients MUST use 5 as the default.
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval)
    }

    /// Any extra fields returned on the response.
    pub fn extra_fields(&self) -> &EF {
        &self.extra_fields
    }
}

/// Standard implementation of DynamicClientRegistrationResponse which throws away
/// extra received response fields.
pub type StandardDynamicClientRegistrationResponse =
    DynamicClientRegistrationResponse<EmptyExtraDeviceAuthorizationFields>;

/// Basic access token error types.
///
/// These error types are defined in
/// [Section 5.2 of RFC 6749](https://tools.ietf.org/html/rfc6749#section-5.2) and
/// [Section 3.5 of RFC 6749](https://tools.ietf.org/html/rfc8628#section-3.5)
#[derive(Clone, PartialEq, Eq)]
pub enum DynamicClientRegistrationErrorResponseType {
    /// The authorization request is still pending as the end user hasn't
    /// yet completed the user-interaction steps.  The client SHOULD repeat the
    /// access token request to the token endpoint.  Before each new request,
    /// the client MUST wait at least the number of seconds specified by the
    /// "interval" parameter of the device authorization response, or 5 seconds
    /// if none was provided, and respect any increase in the polling interval
    /// required by the "slow_down" error.
    AuthorizationPending,
    /// A variant of "authorization_pending", the authorization request is
    /// still pending and polling should continue, but the interval MUST be
    /// increased by 5 seconds for this and all subsequent requests.
    SlowDown,
    /// The authorization request was denied.
    AccessDenied,
    /// The "device_code" has expired, and the device authorization session has
    /// concluded.  The client MAY commence a new device authorization request
    /// but SHOULD wait for user interaction before restarting to avoid
    /// unnecessary polling.
    ExpiredToken,
    /// A Basic response type
    Basic(BasicErrorResponseType),
}
impl DynamicClientRegistrationErrorResponseType {
    fn from_str(s: &str) -> Self {
        match BasicErrorResponseType::from_str(s) {
            BasicErrorResponseType::Extension(ext) => match ext.as_str() {
                "authorization_pending" => {
                    DynamicClientRegistrationErrorResponseType::AuthorizationPending
                }
                "slow_down" => DynamicClientRegistrationErrorResponseType::SlowDown,
                "access_denied" => DynamicClientRegistrationErrorResponseType::AccessDenied,
                "expired_token" => DynamicClientRegistrationErrorResponseType::ExpiredToken,
                _ => DynamicClientRegistrationErrorResponseType::Basic(
                    BasicErrorResponseType::Extension(ext),
                ),
            },
            basic => DynamicClientRegistrationErrorResponseType::Basic(basic),
        }
    }
}
impl AsRef<str> for DynamicClientRegistrationErrorResponseType {
    fn as_ref(&self) -> &str {
        match self {
            DynamicClientRegistrationErrorResponseType::AuthorizationPending => {
                "authorization_pending"
            }
            DynamicClientRegistrationErrorResponseType::SlowDown => "slow_down",
            DynamicClientRegistrationErrorResponseType::AccessDenied => "access_denied",
            DynamicClientRegistrationErrorResponseType::ExpiredToken => "expired_token",
            DynamicClientRegistrationErrorResponseType::Basic(basic) => basic.as_ref(),
        }
    }
}
impl<'de> serde::Deserialize<'de> for DynamicClientRegistrationErrorResponseType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let variant_str = String::deserialize(deserializer)?;
        Ok(Self::from_str(&variant_str))
    }
}
impl serde::ser::Serialize for DynamicClientRegistrationErrorResponseType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl ErrorResponseType for DynamicClientRegistrationErrorResponseType {}
impl Debug for DynamicClientRegistrationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        Display::fmt(self, f)
    }
}

impl Display for DynamicClientRegistrationErrorResponseType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
        write!(f, "{}", self.as_ref())
    }
}

/// Error response specialization for device code OAuth2 implementation.
pub type DynamicClientRegistrationErrorResponse =
    StandardErrorResponse<DynamicClientRegistrationErrorResponseType>;
