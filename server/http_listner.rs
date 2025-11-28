use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use actix_web::dev::ServerHandle;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, Actix-web!")
}

#[derive(Serialize, Deserialize)]
struct Info {
    name: String,
    age: u8,
}

#[post("/echo")]
async fn echo(info: web::Json<Info>) -> impl Responder {
    HttpResponse::Ok().json(info.into_inner())
}

// A wrapper to hold the server handle for stopping later
pub struct HttpListener {
    handle: Option<ServerHandle>,
    server: Option<actix_web::dev::Server>,
}

impl HttpListener {
    pub fn new() -> Self {
        Self { handle: None, server: None }
    }

    // Start the server and save the handle
    pub async fn start(&mut self, address: &str) -> std::io::Result<()> {
        
        // Check if server is already running
        if self.server.is_some() {
            println!("HTTP server is already running!");
            return Ok(()); // Return immediately
        }

        let server = HttpServer::new(|| {
            App::new()
                .service(index)
                .service(echo)
        })
        .bind(address)?
        .run();

        self.handle = Some(server.handle());
        self.server = Some(server);

        println!("HTTP server running on {}", address);

        // Run server in background
        let server_clone = self.server.as_ref().unwrap().clone();
        tokio::spawn(async move {
            server_clone.await.unwrap();
        });

        Ok(())
    }

    // Stop the server
    pub async fn stop(&self) {
        if let Some(handle) = &self.handle {
            println!("Stopping HTTP server...");
            handle.stop(true).await;
        }
    }
}
