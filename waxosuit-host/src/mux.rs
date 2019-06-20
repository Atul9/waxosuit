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

use crate::wasm::ModuleHost;
use crate::Result;
use crossbeam::atomic::AtomicCell;
use crossbeam_channel::{Receiver, Select, Sender};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use wascap_codec::core::{Command, Event};
use wasmer_runtime::Instance;

type ChannelPair = (Receiver<Command>, Sender<Event>);

/// The multiplexer starts a thread that performs a `select` in an infinite loop, waiting for
/// commands to come in from the various dispatchers being held by capability providers. For each
/// command, the muxer will invoke the appropriate wasm function in the encapsulated wasm instance,
/// and return the result on the appropriate response channel
pub struct Multiplexer {
    cap_channels: RwLock<HashMap<String, ChannelPair>>,
    running: Arc<AtomicCell<bool>>,
}

impl Multiplexer {
    pub fn new() -> Self {
        Multiplexer {
            cap_channels: RwLock::new(HashMap::new()),
            running: Arc::new(AtomicCell::new(false)),
        }
    }

    pub fn register_capability(
        &self,
        cap_id: impl Into<String>,
        commands_in: Receiver<Command>,
        events_out: Sender<Event>,
    ) -> Result<()> {
        let mut channels = self.cap_channels.write().unwrap();
        channels.insert(cap_id.into(), (commands_in, events_out));
        Ok(())
    }

    pub fn run<F>(&self, host_factory: F) -> Result<()>
    where
        F: Fn() -> Result<ModuleHost> + Sync + Send,
        F: 'static,
    {
        let running = self.running.clone();

        let channels: Vec<ChannelPair> = {
            let lock = self.cap_channels.read().unwrap();
            lock.iter().map(|(_, v)| v.clone()).collect()
        };

        running.store(true);

        thread::spawn(move || {
            let mut sel = Select::new();
            for capability in channels.iter() {
                sel.recv(&capability.0); // receiver - 0
            }

            let mut modhost = (host_factory)().unwrap();

            while running.load() {
                let oper = sel.select();
                let index = oper.index();
                let cmd = oper.recv(&channels[index].0);
                // deliver command to the wasm module
                if let Ok(cmd) = cmd {
                    let result = modhost.call(&cmd).unwrap();
                    channels[index].1.send(result).unwrap();
                }
            }
        });

        Ok(())
    }
}
