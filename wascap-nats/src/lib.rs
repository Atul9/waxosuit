// Copyright 2015-2018 Capital One Services, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and 
// limitations under the License.

#[macro_use]
extern crate wascap_codec;

#[macro_use]
extern crate log;

use natsclient as nats;
use std::error::Error;
use std::sync::Arc;
use std::sync::RwLock;
use wascap_codec as codec;
use wascap_codec::capabilities::{CapabilityProvider, Dispatcher, NullDispatcher};
use wascap_codec::core::{Command, Event};
use wascap_codec::messaging::{
    BrokerMessage, DeliverMessage, PublishMessage, TYPE_URL_PUBLISH_MESSAGE,
};
use wascap_codec::AsCommand;

capability_provider!(NatsProvider, NatsProvider::new);

const ENV_NATS_SUBSCRIPTION: &'static str = "NATS_SUBSCRIPTION";
const ENV_NATS_URL: &'static str = "NATS_URL";

pub struct NatsProvider {
    dispatcher: Arc<RwLock<Box<Dispatcher>>>,
    client: nats::Client,
}

impl NatsProvider {
    pub fn new() -> NatsProvider {
        env_logger::init();

        let nats_url = match std::env::var(ENV_NATS_URL) {
            Ok(v) => v,
            Err(_) => "nats://localhost:4222".to_string(),
        };

        info!("Attempting to establish NATS connection to URL: {}", nats_url);

        let opts = nats::ClientOptions::builder()
            .cluster_uris(vec![nats_url])
            .authentication(nats::AuthenticationStyle::Anonymous)
            .build()
            .unwrap();
        let c = nats::Client::from_options(opts).unwrap();
        c.connect().unwrap();

        NatsProvider {
            dispatcher: Arc::new(RwLock::new(Box::new(NullDispatcher::new()))),
            client: c,
        }
    }

    fn handle_command(&self, cmd: &prost_types::Any) -> Result<Event, Box<dyn Error>> {
        match cmd.type_url.as_ref() {
            TYPE_URL_PUBLISH_MESSAGE => self.publish_message(&cmd.value),
            _ => Ok(Event::bad_dispatch("unsupported type url")),
        }
    }

    fn publish_message(&self, msg: impl Into<PublishMessage>) -> Result<Event, Box<dyn Error>> {
        let msg = msg.into();

        match msg.message {
            Some(m) => {
                self.client
                    .publish(
                        &m.subject,
                        &m.body,
                        if m.reply_to.len() > 0 {
                            Some(&m.reply_to)
                        } else {
                            None
                        },
                    )
                    .unwrap(); // TODO- get rid of unwrap
                Ok(Event {
                    success: true,
                    ..Default::default()
                })
            }
            None => Ok(Event {
                success: false,
                payload: None,
                error: Some(codec::core::Error {
                    code: 0,
                    description: "No message to publish".to_string(),
                }),
            }),
        }
    }
}

impl CapabilityProvider for NatsProvider {
    fn capability_id(&self) -> &'static str {
        "wascap:messaging"
    }

    fn configure_dispatch(
        &self,
        dispatcher: Box<Dispatcher>,
        _id: codec::capabilities::ModuleIdentity,
    ) -> Result<(), Box<dyn Error>> {
        info!("Dispatcher received.");
        let mut lock = self.dispatcher.write().unwrap();
        *lock = dispatcher;

        let disp = self.dispatcher.clone();

        match std::env::var(ENV_NATS_SUBSCRIPTION) {
            Ok(ref sub) => {
                info!("Subscribing to '{}'", sub);
                self.client
                    .subscribe(&sub, move |msg| {
                        let dm = DeliverMessage {
                            message: Some(BrokerMessage {
                                subject: msg.subject.clone(),
                                reply_to: msg.reply_to.clone().unwrap_or("".to_string()),
                                body: msg.payload.clone(),
                            }),
                        };

                        let _evt = {
                            let d = disp.read().unwrap();
                            d.dispatch(&dm.as_command("wascap:messaging", "guest"))
                                .unwrap();
                        };

                        Ok(())                
                    })
                    .unwrap();
            },
            Err(_) => {},
        };
        
        Ok(())
    }

    fn name(&self) -> &'static str {
        "NATS Messaging Provider"
    }

    fn handle_call(&self, cmd: &Command) -> Result<Event, Box<dyn Error>> {
        info!(
            "Received host call, command - {}",
            cmd.payload
                .as_ref()
                .map_or("(no payload)".to_string(), |p| format!("{}", p.type_url))
        );

        match cmd.payload {
            Some(ref p) => self.handle_command(p),
            None => {
                eprint!("No payload in host call to NATS");
                Ok(Event {
                    success: false,
                    payload: None,
                    error: Some(codec::core::Error {
                        code: 0,
                        description: "No command payload".to_string(),
                    }),
                })
            }
        }
    }
}
