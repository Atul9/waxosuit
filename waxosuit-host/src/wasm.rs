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

use crate::capabilities::CAPMAN;
use crate::errors;
use crate::Result;
use prost::Message;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wascap_codec as codec;
use wascap_codec::core::{Command, Event};
use wasmer_runtime::{error, func, imports, instantiate, Ctx, Func, Instance, Memory, Value};
use wasmer_runtime_core::Module;

const HOST_NAMESPACE: &'static str = "wascap";
const HOST_THROW: &'static str = "__throw";
const HOST_CONSOLE_LOG: &'static str = "__console_log";
const HOST_CALL: &'static str = "__host_call";

const GUEST_FREE: &'static str = "__wascap_free";
const GUEST_MALLOC: &'static str = "__wascap_malloc";
const GUEST_REALLOC: &'static str = "__wascap_realloc";
const GUEST_CALL: &'static str = "__guest_call";
const GUEST_GLOBAL_ARGUMENT_POINTER: &'static str = "__wascap_global_argument_ptr";

pub struct ModuleHost {
    // TODO: make this a pool of instances so we can deliver dispatch messages
    // round-robin to them
    instance: Instance,
}

impl ModuleHost {
    pub fn new(buf: &[u8]) -> Result<ModuleHost> {
        let import_object = imports! {
            HOST_NAMESPACE => {
                HOST_CONSOLE_LOG => func!(console_log),
                HOST_THROW => func!(throw),
                HOST_CALL => func!(host_call),
            },
        };

        let mh = ModuleHost {
            instance: instantiate(&buf, &import_object)?,
        };

        Ok(mh)
    }

    /// Invokes the __guest_call function within the guest module instance
    /// by encoding the command and decoding the result as an `Event`
    pub fn call(&mut self, cmd: &Command) -> Result<Event> {
        if is_live_update(cmd) {
            return self.swap_module(cmd);
        }
        let ptr = pass_message_to_wasm(&mut self.instance, cmd)?;
        let lenresult = self.guest_call_fn()?.call(ptr, cmd.encoded_len() as i32)?;

        let resvec = self.get_vec_at_gp(lenresult);
        let res_event = codec::core::Event::decode(&resvec)?;

        Ok(res_event)
    }

    fn swap_module(&mut self, cmd: &Command) -> Result<Event> {
        match cmd.payload {
            Some(ref p) => {
                let hotswap = codec::core::LiveUpdate::decode(&p.value)?;
                info!(
                    "HOT SWAP - Replacing existing WebAssembly module with new buffer, {} bytes",
                    hotswap.new_module.len()
                );
                self.instance = create_instance_from_buf(&hotswap.new_module)?;
                info!("HOT SWAP - Success");
                Ok(Event {
                    success: true,
                    ..Default::default()
                })
            }
            None => Err(errors::new(errors::ErrorKind::WascapViolation(
                "Attempt to hot swap with no payload".to_string(),
            ))),
        }
    }

    fn guest_call_fn(&self) -> Result<Func<(i32, i32), i32>> {
        let f: Func<(i32, i32), i32> = self.instance.func(GUEST_CALL)?;
        Ok(f)
    }

    fn guest_free_fn(&self) -> Result<Func<(i32, i32)>> {
        let f: Func<(i32, i32)> = self.instance.func(GUEST_FREE)?;
        Ok(f)
    }

    pub fn get_vec_at_gp(&self, len: i32) -> Vec<u8> {
        get_vec_from_wasm_gp(&self.instance, len)
    }
}

fn create_instance_from_buf(buf: &[u8]) -> Result<Instance> {
    let import_object = imports! {
        HOST_NAMESPACE => {
            HOST_CONSOLE_LOG => func!(console_log),
            HOST_THROW => func!(throw),
            HOST_CALL => func!(host_call),
        },
    };

    match instantiate(&buf, &import_object) {
        Ok(instance) => Ok(instance),
        Err(e) => Err(errors::new(errors::ErrorKind::WasmMisc(e))),
    }
}

fn is_live_update(cmd: &Command) -> bool {
    cmd.payload
        .as_ref()
        .map_or(false, |p| p.type_url == codec::core::TYPE_URL_LIVE_UPDATE)
}

fn pass_message_to_wasm(mut wasm: &mut Instance, msg: &impl prost::Message) -> Result<i32> {
    let mut indata = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut indata)?;
    let ptr = pass_slice_to_wasm(&mut wasm, &indata)?;
    Ok(ptr)
}

fn pass_slice_to_wasm(wasm: &mut Instance, slice: &[u8]) -> Result<i32> {
    let ptr = wasm_malloc(wasm, slice.len() as _)?;
    let ctx = wasm.context_mut();
    let memory = ctx.memory(0);
    let start: usize = ptr as usize;
    let finish: usize = start + slice.len();
    for (&byte, cell) in slice
        .to_vec()
        .iter()
        .zip(memory.view()[start..finish].iter())
    {
        cell.set(byte);
    }
    Ok(ptr)
}

fn wasm_malloc(wasm: &Instance, len: i32) -> Result<i32> {
    // TODO: make result
    let malloc: Func<i32, i32> = wasm.func(GUEST_MALLOC)?;
    match malloc.call(len) {
        Ok(ptr) => Ok(ptr),
        Err(e) => Err(errors::new(errors::ErrorKind::WasmRuntime(e))),
    }
}

fn get_vec_from_wasm_gp(wasm: &Instance, vec_size: i32) -> Vec<u8> {
    let start = global_arg_pointer(wasm);
    let vec_ptr = get_i32_from_bytewindow(&wasm, start as _);
    let vec_bytes = get_bytes(&wasm, vec_ptr as _, vec_ptr as usize + vec_size as usize);

    // let free: Func<(i32, i32)> = wasm.func(GUEST_FREE).unwrap();
    //free.call(vec_ptr, vec_size).unwrap(); // TODO make result

    vec_bytes
}

fn get_i32_from_bytewindow(wasm: &Instance, start: usize) -> i32 {
    let mut size_array = [0u8; 4];
    let size_vec: Vec<_> = wasm.context().memory(0).view()[start..(start + 4) as usize]
        .iter()
        .map(|cell| cell.get())
        .collect();
    size_array.copy_from_slice(&size_vec);
    i32::from_le_bytes(size_array)
}

fn global_arg_pointer(wasm: &Instance) -> i32 {
    let argptr: Func<(), i32> = wasm.func(GUEST_GLOBAL_ARGUMENT_POINTER).unwrap();
    argptr.call().unwrap()
}

fn get_bytes(wasm: &Instance, start: usize, finish: usize) -> Vec<u8> {
    wasm.context().memory(0).view()[start..finish]
        .iter()
        .map(|cell| cell.get())
        .collect()
}

fn get_vec_from_memory(mem: &Memory, ptr: i32, len: i32) -> Vec<u8> {
    let vec = mem.view()[ptr as usize..(ptr + len) as usize]
        .iter()
        .map(|cell| cell.get())
        .collect();
    vec
}

fn write_bytes_to_memory(memory: &Memory, ptr: i32, slice: &[u8]) {
    let start: usize = ptr as usize;
    let finish: usize = start + slice.len();
    for (&byte, cell) in slice
        .to_vec()
        .iter()
        .zip(memory.view()[start..finish].iter())
    {
        cell.set(byte);
    }
}

// -- Host Functions Follow --

/// Invoked by the guest module when it wants to make a call to a capability
fn host_call(ctx: &mut Ctx, ptr: i32, len: i32, retptr: i32) -> i32 {
    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);
    let cmd = Command::decode(&vec).unwrap();
    info!("Guest module invoking host call for {}", cmd.target_cap);

    let result = {
        let lock = CAPMAN.read().unwrap();
        lock.call(&cmd)
    };
    let event = match result {
        Ok(evt) => evt,
        Err(e) => Event {
            success: false,
            payload: None,
            error: Some(codec::core::Error {
                code: 500,
                description: format!("Host call failure: {}", e),
            }),
        },
    };

    let mut buf = Vec::new();
    event.encode(&mut buf).unwrap();
    write_bytes_to_memory(&ctx.memory(0), retptr, &buf);

    buf.len() as i32
}

fn console_log(ctx: &mut Ctx, ptr: i32, len: i32) {
    let vec = get_vec_from_memory(&ctx.memory(0), ptr, len);

    info!("Wasm Guest: {}", std::str::from_utf8(&vec).unwrap());
}

fn throw(ctx: &mut Ctx, ptr: i32, b: i32) -> () {
    println!("Module threw an exception!");
    std::process::abort();
}
