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

use crate::dispatch::WaxosuitDispatcher;
use crate::errors;
use crate::mux::Multiplexer;
use crate::wasm::ModuleHost;
use crate::Result;
use crossbeam_channel as channel;
use libloading::{Library, Symbol};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::RwLock;
use wascap_codec as codec;
use wascap_codec::capabilities::{CapabilityProvider, Dispatcher, ModuleIdentity};
use wascap_codec::core::{Command, Event};

lazy_static! {
    pub static ref CAPMAN: RwLock<CapabilityManager> = { RwLock::new(CapabilityManager::new()) };
}

pub struct CapabilityManager {
    plugins: HashMap<String, Box<dyn CapabilityProvider>>,
    loaded_libraries: Vec<Library>,
    muxer: Multiplexer,
    claims: Option<wascap::jwt::Claims>,
}

impl CapabilityManager {
    pub fn new() -> CapabilityManager {
        CapabilityManager {
            plugins: HashMap::new(),
            loaded_libraries: Vec::new(),
            muxer: Multiplexer::new(),
            claims: None,
        }
    }

    pub fn empty(&self) -> bool {
        self.loaded_libraries.len() == 0
    }

    pub fn call(&self, cmd: &Command) -> Result<Event> {
        let capability = self.plugins.get(&cmd.target_cap).unwrap();

        match capability.handle_call(cmd) {
            Ok(evt) => Ok(evt),
            Err(e) => Err(errors::new(errors::ErrorKind::HostCallFailure(e))),
        }
    }

    pub fn start_mux<F>(&self, factory: F) -> Result<()>
    where
        F: Fn() -> Result<ModuleHost> + Sync + Send,
        F: 'static,
    {
        self.muxer.run(factory)
    }

    pub fn set_claims(&mut self, claims: wascap::jwt::Claims) {
        self.claims = Some(claims)
    }

    fn module_id_for_claims(&self) -> codec::capabilities::ModuleIdentity {
        match self.claims {
            Some(ref c) => codec::capabilities::ModuleIdentity {
                issuer: c.issuer.clone(),
                module: c.subject.clone(),
                capabilities: c.caps.as_ref().map_or(vec![], |cps| cps.clone()),
            },
            None => codec::capabilities::ModuleIdentity {
                issuer: "invalid".to_string(),
                module: "invalid".to_string(),
                capabilities: vec![],
            },
        }
    }

    pub fn load_plugin<P: AsRef<OsStr>>(&mut self, filename: P) -> Result<String> {
        type PluginCreate = unsafe fn() -> *mut dyn CapabilityProvider;

        let lib = Library::new(filename.as_ref())?;

        // We need to keep the library around otherwise our plugin's vtable will
        // point to garbage. We do this little dance to make sure the library
        // doesn't end up getting moved.
        self.loaded_libraries.push(lib);

        let lib = self.loaded_libraries.last().unwrap();

        let plugin = unsafe {
            let constructor: Symbol<PluginCreate> = lib.get(b"__capability_provider_create")?;
            let boxed_raw = constructor();

            Box::from_raw(boxed_raw)
        };
        info!(
            "Loaded capability: {}, provider: {}",
            plugin.capability_id(),
            plugin.name()
        );

        let capid = plugin.capability_id().to_string();

        if self.plugins.contains_key(&capid) {
            panic!(
                "Duplicate providers attempted to register for {}",
                plugin.capability_id()
            );
        }

        if let Some(ref claims) = self.claims {
            if let Some(ref caps) = claims.caps {
                if !caps.contains(&capid) {
                    let lib = self.loaded_libraries.pop();
                    drop(plugin);
                    drop(lib); 
                    info!(
                        "Capability provider for {} not claimed by guest module. Unloading.",
                        &capid
                    );
                    return Err(errors::new(errors::ErrorKind::WascapViolation(format!(
                        "Unauthorized capability: {}",
                        &capid
                    ))));
                }
            }
        }

        let (evt_s, evt_r) = channel::unbounded();
        let (cmd_s, cmd_r) = channel::unbounded();
        let spatch = WaxosuitDispatcher::new(evt_r, cmd_s);

        self.muxer
            .register_capability(plugin.capability_id(), cmd_r, evt_s)?;

        plugin
            .configure_dispatch(Box::new(spatch), self.module_id_for_claims())
            .unwrap();
        //plugin.on_plugin_load();
        self.plugins
            .insert(plugin.capability_id().to_string(), plugin);

        Ok(capid)
    }
    /// Unload all plugins and loaded plugin libraries, making sure to fire
    /// their `on_plugin_unload()` methods so they can do any necessary cleanup.
    pub fn unload(&mut self) {
        info!("Unloading plugins");

        //for (_k, plugin) in self.plugins.drain() {
        //println!("Firing on_plugin_unload for {:?}", plugin.name());
        //plugin.on_plugin_unload();
        //}

        for lib in self.loaded_libraries.drain(..) {
            drop(lib);
        }
    }
}

impl Drop for CapabilityManager {
    fn drop(&mut self) {
        if !self.plugins.is_empty() || !self.loaded_libraries.is_empty() {
            self.unload();
        }
    }
}
