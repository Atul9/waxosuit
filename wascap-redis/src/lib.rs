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

use keyvalue::{
    AddRequest, AddResponse, DelRequest, GetRequest, GetResponse, ListClearRequest,
    ListPushRequest, ListRangeRequest, ListRangeResponse, ListResponse, SetRequest,
};
use prost::Message;
use redis::{self, Commands};
use std::error::Error;
use std::sync::Arc;
use std::sync::RwLock;
use wascap_codec as codec;
use wascap_codec::capabilities::{CapabilityProvider, Dispatcher, NullDispatcher};
use wascap_codec::core::{Command, Event};
use wascap_codec::keyvalue;
use wascap_codec::AsEvent;

const ENV_REDIS_URL: &'static str = "REDIS_URL";

capability_provider!(RedisKVProvider, RedisKVProvider::new);

pub struct RedisKVProvider {
    dispatcher: Arc<RwLock<Box<Dispatcher>>>,
    client: redis::Client,
}

impl RedisKVProvider {
    pub fn new() -> Self {
        env_logger::init();

        let redis_url = match std::env::var(ENV_REDIS_URL) {
            Ok(v) => v,
            Err(_) => "redis://127.0.0.1/".to_string(),
        };

        let client = redis::Client::open(redis_url.as_ref()).unwrap(); // TODO: get from dispatch options
        RedisKVProvider {
            dispatcher: Arc::new(RwLock::new(Box::new(NullDispatcher::new()))),
            client,
        }
    }

    fn handle_command(&self, cmd: &prost_types::Any) -> Result<Event, Box<dyn Error>> {
        match cmd.type_url.as_ref() {
            keyvalue::TYPE_URL_ADD_REQUEST => self.add(AddRequest::decode(&cmd.value).unwrap()),
            keyvalue::TYPE_URL_DEL_REQUEST => self.del(DelRequest::decode(&cmd.value).unwrap()),
            keyvalue::TYPE_URL_GET_REQUEST => self.get(GetRequest::decode(&cmd.value).unwrap()),
            keyvalue::TYPE_URL_LIST_CLEAR_REQUEST => {
                self.list_clear(ListClearRequest::decode(&cmd.value).unwrap())
            }
            keyvalue::TYPE_URL_LIST_RANGE_REQUEST => {
                self.list_range(ListRangeRequest::decode(&cmd.value).unwrap())
            }
            keyvalue::TYPE_URL_LIST_PUSH_REQUEST => {
                self.list_push(ListPushRequest::decode(&cmd.value).unwrap())
            }
            keyvalue::TYPE_URL_SET_REQUEST => self.set(SetRequest::decode(&cmd.value).unwrap()),
            _ => Ok(Event::bad_dispatch(&cmd.type_url)),
        }
    }

    fn add(&self, req: AddRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        let res: i32 = con.incr(req.key, req.value)?;

        Ok(AddResponse { value: res }.as_event(true, None))
    }

    fn del(&self, req: DelRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        con.del(req.key)?;

        Ok(Event {
            success: true,
            ..Default::default()
        })
    }

    fn get(&self, req: GetRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        let v: redis::RedisResult<String> = con.get(req.key);
        Ok(match v {
            Ok(s) => GetResponse{value: s, exists: true},
            Err(_) => GetResponse{value: "".to_string(), exists: false}
        }.as_event(true, None))
    }

    fn list_clear(&self, req: ListClearRequest) -> Result<Event, Box<dyn Error>> {
        self.del(DelRequest { key: req.key })
    }

    fn list_range(&self, req: ListRangeRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        let result: Vec<String> = con.lrange(req.key, req.start as _, req.stop as _)?;
        Ok(ListRangeResponse { values: result }.as_event(true, None))
    }

    fn list_push(&self, req: ListPushRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        let result: i32 = con.lpush(req.key, req.value)?;
        Ok(ListResponse { new_count: result }.as_event(true, None))
    }

    fn set(&self, req: SetRequest) -> Result<Event, Box<dyn Error>> {
        let con = self.client.get_connection()?;
        con.set(req.key, req.value)?;

        Ok(Event {
            success: true,
            ..Default::default()
        })
    }
}

impl CapabilityProvider for RedisKVProvider {
    fn capability_id(&self) -> &'static str {
        "wascap:keyvalue"
    }

    fn configure_dispatch(
        &self,
        dispatcher: Box<Dispatcher>,
        _id: codec::capabilities::ModuleIdentity,
    ) -> Result<(), Box<dyn Error>> {
        info!("Dispatcher received.");

        let mut lock = self.dispatcher.write().unwrap();
        *lock = dispatcher;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Redis Key-Value Provider"
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
                eprint!("No payload in __host_call sent to Redis");
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
