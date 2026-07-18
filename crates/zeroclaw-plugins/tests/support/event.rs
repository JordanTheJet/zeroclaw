use std::sync::Arc;

use zeroclaw_plugins::event::{
    PluginEventDispatcher, PluginEventEnvelope, PluginEventError, PluginEventResolution,
    PluginEventRouteResolver, PluginEventRouter, ResolvedPluginEventRoute,
};

struct TestDispatcher {
    sender: Option<tokio::sync::mpsc::Sender<zeroclaw_api::channel::ChannelMessage>>,
}

#[async_trait::async_trait]
impl PluginEventDispatcher for TestDispatcher {
    async fn dispatch(
        &self,
        _route: ResolvedPluginEventRoute,
        event: PluginEventEnvelope,
    ) -> Result<(), PluginEventError> {
        if let Some(sender) = &self.sender {
            sender.send(event.into_message()).await.map_err(|_| {
                PluginEventError::DispatchFailed("test receiver closed".to_string())
            })?;
        }
        Ok(())
    }
}

/// Production-shaped event router for component-boundary fixtures.
pub fn event_router(
    sender: Option<tokio::sync::mpsc::Sender<zeroclaw_api::channel::ChannelMessage>>,
    authorized: bool,
) -> PluginEventRouter {
    let resolver = PluginEventRouteResolver::new(move |instance, _| {
        if authorized {
            Ok(PluginEventResolution::Authorized(
                ResolvedPluginEventRoute::agent(instance, "fixture-agent")?,
            ))
        } else {
            Ok(PluginEventResolution::Denied)
        }
    });
    PluginEventRouter::new(resolver, Arc::new(TestDispatcher { sender }))
}
