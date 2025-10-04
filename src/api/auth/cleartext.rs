use std::fmt::Debug;

use async_trait::async_trait;
use futures::sink::{Sink, SinkExt};

use super::{
    AuthSource, ClientInfo, LoginInfo, PgWireConnectionState, ServerParameterProvider,
    StartupHandler,
};
use crate::error::{PgWireError, PgWireResult};
use crate::messages::startup::Authentication;
use crate::messages::{PgWireBackendMessage, PgWireFrontendMessage};

#[derive(new)]
pub struct CleartextPasswordAuthStartupHandler<A, P> {
    auth_source: A,
    parameter_provider: P,
}

#[async_trait]
impl<V: AuthSource, P: ServerParameterProvider> StartupHandler
    for CleartextPasswordAuthStartupHandler<V, P>
{
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo + Sink<PgWireBackendMessage> + Unpin + Send,
        C::Error: Debug,
        PgWireError: From<<C as Sink<PgWireBackendMessage>>::Error>,
    {
        match message {
            PgWireFrontendMessage::Startup(ref startup) => {
                super::protocol_negotiation(client, startup).await?;
                super::save_startup_parameters_to_metadata(client, startup);
                client.set_state(PgWireConnectionState::AuthenticationInProgress);
                client
                    .send(PgWireBackendMessage::Authentication(
                        Authentication::CleartextPassword,
                    ))
                    .await?;
            }
            PgWireFrontendMessage::PasswordMessageFamily(_pwd) => {
                // Cleartext authentication is insecure and doesn't work with SCRAM verifiers
                panic!("Cleartext authentication is not supported with SCRAM verifiers. Use SCRAM-SHA-256 instead.");
            }
            _ => {}
        }
        Ok(())
    }
}
