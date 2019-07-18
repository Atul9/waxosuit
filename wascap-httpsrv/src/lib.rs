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

use actix_multipart::{Field, Multipart, MultipartError};
use actix_web::dev::Body;
use actix_web::http::StatusCode;
use actix_web::{middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use bytes::Bytes;
use futures::{Future, Stream};
use prost::Message;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::RwLock;
use wascap_codec as codec;
use wascap_codec::capabilities::{CapabilityProvider, Dispatcher, NullDispatcher};
use wascap_codec::core::{Command, Event};
use wascap_codec::AsCommand;

const CAPABILITY_ID: &'static str = "wascap:http_server";

capability_provider!(HttpServerProvider, HttpServerProvider::new);

pub struct HttpServerProvider {
    dispatcher: Arc<RwLock<Box<dyn Dispatcher>>>,
}

impl HttpServerProvider {
    pub fn new() -> Self {
        env_logger::init();
        HttpServerProvider {
            dispatcher: Arc::new(RwLock::new(Box::new(NullDispatcher::new()))),
        }
    }
}

impl CapabilityProvider for HttpServerProvider {
    fn capability_id(&self) -> &'static str {
        CAPABILITY_ID
    }

    fn configure_dispatch(
        &self,
        dispatcher: Box<dyn Dispatcher>,
        module_id: codec::capabilities::ModuleIdentity,
    ) -> Result<(), Box<dyn StdError>> {
        info!("Dispatcher received.");

        let mut lock = self.dispatcher.write().unwrap();
        *lock = dispatcher;

        let disp = self.dispatcher.clone();

        let bind_addr = match std::env::var("PORT") {
            Ok(v) => format!("0.0.0.0:{}", v),
            Err(_) => "0.0.0.0:8080".to_string(),
        };

        std::thread::spawn(move || {
            HttpServer::new(move || {
                App::new()
                    .wrap(middleware::Logger::default())
                    .data(disp.clone())
                    .data(module_id.clone())
                    .service(web::resource("/healthz").to(health_check))
                    .service(web::resource("/id").to(show_claims))
                    .service(web::resource("/liveupdate").route(web::post().to_async(upload)))
                    .default_service(web::route().to(request_handler))
            })
            .bind(bind_addr)
            .unwrap()
            .disable_signals()
            .run()
            .unwrap();
        });

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Actix-Web HTTP Server"
    }

    fn handle_call(&self, _cmd: &Command) -> Result<Event, Box<dyn StdError>> {
        Ok(Event {
            success: false,
            payload: None,
            error: Some(codec::core::Error {
                code: 0,
                description: "HTTP server does not accept host calls".to_string(),
            }),
        })
    }
}

fn health_check(state: web::Data<Arc<RwLock<Box<dyn Dispatcher>>>>) -> HttpResponse {
    let check = codec::core::HealthRequest { placeholder: true }.as_command(CAPABILITY_ID, "guest");
    let evt = {
        let lock = (*state).read().unwrap();
        lock.dispatch(&check)
    };

    match evt {
        Ok(event) => {
            if event.success {
                HttpResponse::Ok().body("OK\n")
            } else {
                HttpResponse::ExpectationFailed()
                    .body(event.error.map_or("".to_string(), |e| e.description))
            }
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("{}", e)),
    }
}

fn show_claims(
    state: web::Data<codec::capabilities::ModuleIdentity>,
    _req: HttpRequest,
) -> HttpResponse {
    HttpResponse::Ok().json(state.get_ref())
}

fn upload(
    multipart: Multipart,
    state: web::Data<Arc<RwLock<Box<dyn Dispatcher>>>>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    multipart
        .map_err(actix_web::error::ErrorInternalServerError)
        .map(move |field| save_file(field, &state).into_stream())
        .flatten()
        .collect()
        .map(|sizes| HttpResponse::Ok().json(sizes))
        .map_err(|e| {
            println!("failed: {}", e);
            e
        })
}

fn save_file(
    field: Field,
    state: &web::Data<Arc<RwLock<Box<dyn Dispatcher>>>>,
) -> impl Future<Item = i64, Error = Error> {
    let ns = state.clone();
    field
        .fold(
            (Vec::<u8>::new(), 0i64),
            move |(mut buf, mut acc), bytes| {
                // fs operations are blocking, we have to execute writes
                // on threadpool
                web::block(move || {
                    buf.extend(&bytes);
                    acc += bytes.len() as i64;
                    Ok((buf, acc))
                })
                .map_err(|e: actix_web::error::BlockingError<MultipartError>| {
                    match e {
                        actix_web::error::BlockingError::Error(e) => e,
                        actix_web::error::BlockingError::Canceled => MultipartError::Incomplete,
                    }
                })
            },
        )
        .map(move |(buf, acc)| {
            dispatch_module(&buf, &ns);
            acc
        })
        .map_err(|e| {
            println!("save_file failed, {:?}", e);
            actix_web::error::ErrorInternalServerError(e)
        })
}

fn dispatch_module(newmodule: &[u8], state: &web::Data<Arc<RwLock<Box<dyn Dispatcher>>>>) {
    let update = codec::core::LiveUpdate {
        new_module: newmodule.to_vec(),
    };
    let cmd = update.as_command(CAPABILITY_ID, "guest");
    let _evt = {
        let lock = (*state).read().unwrap();
        lock.dispatch(&cmd).unwrap()
    };
}

fn request_handler(
    req: HttpRequest,
    payload: Bytes,
    state: web::Data<Arc<RwLock<Box<dyn Dispatcher>>>>,
) -> HttpResponse {
    let request = codec::http::Request {
        method: req.method().as_str().to_string(),
        path: req.uri().path().to_string(),
        query_string: req.query_string().to_string(),
        header: extract_headers(&req),
        body: payload.to_vec(),
    };
    let cmd = request.as_command(CAPABILITY_ID, "guest");

    let evt = {
        let lock = (*state).read().unwrap();
        lock.dispatch(&cmd).unwrap()
    };
    let r = codec::http::Response::decode(evt.payload.unwrap().value).unwrap();

    HttpResponse::with_body(
        StatusCode::from_u16(r.status_code as _).unwrap(),
        Body::from_slice(&r.body),
    )
}

fn extract_headers(req: &HttpRequest) -> HashMap<String, String> {
    let mut hm = HashMap::new();

    for (hname, hval) in req.headers().iter() {
        hm.insert(
            hname.as_str().to_string(),
            hval.to_str().unwrap().to_string(),
        );
    }

    hm
}
