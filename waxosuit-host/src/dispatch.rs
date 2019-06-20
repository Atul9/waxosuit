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

use crossbeam_channel::{Receiver, Select, Sender};
use std::error::Error;
use wascap_codec::capabilities::Dispatcher;
use wascap_codec::core::{Command, Event};

/// A dispatcher is given to each capability provider, allowing it to send
/// commands in to the guest module (via the muxer) and await replies. This dispatch
/// is one way, and is _not_ used for the guest module to send commands to capabilities
#[derive(Clone)]
pub(crate) struct WaxosuitDispatcher {
    evt_r: Receiver<Event>,
    cmd_s: Sender<Command>,
}

impl WaxosuitDispatcher {
    pub fn new(evt_r: Receiver<Event>, cmd_s: Sender<Command>) -> WaxosuitDispatcher {
        WaxosuitDispatcher { evt_r, cmd_s }
    }
}

impl Dispatcher for WaxosuitDispatcher {
    /// Sends the command to the muxer from the capability plugin,
    /// awaits a reply, and then sends the response back.
    fn dispatch(&self, cmd: &Command) -> Result<Event, Box<dyn Error>> {
        info!(
            "Dispatching {} from {} to guest",
            cmd.payload
                .as_ref()
                .map_or("(no payload)".to_string(), |p| format!("{}", p.type_url)),
            cmd.source
        );
        self.cmd_s.send(cmd.clone()).unwrap();
        let evt = self.evt_r.recv().unwrap();

        Ok(evt)
    }
}
