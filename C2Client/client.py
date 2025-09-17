
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime, timedelta
from queue import Queue

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

class C2Client:
    def __init__(self, root):
        self.root = root
        self.root.title("C2 Server Client")
        self.root.geometry("800x600")
        self.root.configure(bg="#2e2e2e")
        
        # Connection variables
        self.server_ip = tk.StringVar(value="127.0.0.1")
        self.server_port = tk.IntVar(value=7777)
        self.connected = False
        self.socket = None
        self.receive_thread = None
        
        # Target tracking
        self.targets = {}  # {target_id: {"last_seen": timestamp, "socket": socket_info}}
        self.target_lock = threading.Lock()
        
        # Interaction state
        self.interacting_with_target = None
        
        # GUI update queue
        self.gui_queue = Queue()
        
        # Setup GUI
        self.setup_gui()
        
        # Start the cleanup thread
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
        self.cleanup_thread.start()
        
        # Start processing GUI updates
        self.process_gui_updates()

    def setup_gui(self):
        # Connection frame
        connection_frame = ttk.Frame(self.root, padding="10")
        connection_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(connection_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(connection_frame, textvariable=self.server_ip, width=15).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(connection_frame, textvariable=self.server_port, width=10).grid(row=0, column=3, sticky=tk.W)
        
        self.connect_btn = ttk.Button(connection_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=4, padx=5)
        
        # Targets frame
        targets_frame = ttk.LabelFrame(self.root, text="Connected Targets", padding="10")
        targets_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Treeview for targets
        columns = ("target_id", "last_seen", "status")
        self.targets_tree = ttk.Treeview(targets_frame, columns=columns, show="headings")
        self.targets_tree.heading("target_id", text="Target ID")
        self.targets_tree.heading("last_seen", text="Last Seen")
        self.targets_tree.heading("status", text="Status")
        
        self.targets_tree.column("target_id", width=200)
        self.targets_tree.column("last_seen", width=150)
        self.targets_tree.column("status", width=100)
        
        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(targets_frame, orient=tk.VERTICAL, command=self.targets_tree.yview)
        self.targets_tree.configure(yscrollcommand=tree_scroll.set)
        
        self.targets_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Right-click menu for targets
        self.target_menu = tk.Menu(self.root, tearoff=0)
        self.target_menu.add_command(label="Interact", command=self.interact_with_target)
        
        # Bind right-click to treeview
        self.targets_tree.bind("<Button-3>", self.show_target_menu)
        
        # Messages frame
        messages_frame = ttk.LabelFrame(self.root, text="Messages", padding="10")
        messages_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        self.messages_text = scrolledtext.ScrolledText(messages_frame, width=70, height=15)
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        
        # Command frame
        command_frame = ttk.Frame(self.root, padding="10")
        command_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))

        # Mode row frame
        mode_frame = ttk.Frame(command_frame)
        mode_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

        # Command row frame
        cmd_frame = ttk.Frame(command_frame)
        cmd_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))

        # Mode row content
        self.interaction_status = ttk.Label(mode_frame, text="Mode: C2")
        self.interaction_status.grid(row=0, column=0, sticky=tk.W)

        self.normal_mode_btn = ttk.Button(mode_frame, text="C2 mode", 
                                        command=self.switch_to_normal_mode, state=tk.DISABLED)
        self.normal_mode_btn.grid(row=0, column=1, padx=5, sticky=tk.W)

        # Command row content
        ttk.Label(cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W)
        self.command_entry = ttk.Entry(cmd_frame, width=50)
        self.command_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        self.command_entry.bind("<Return>", self.send_command)

        ttk.Button(cmd_frame, text="Send", command=self.send_command).grid(row=0, column=2, padx=5)

        # Configure column weights for each sub-frame
        mode_frame.columnconfigure(0, weight=1)
        mode_frame.columnconfigure(1, weight=0)

        cmd_frame.columnconfigure(0, weight=0)
        cmd_frame.columnconfigure(1, weight=1)
        cmd_frame.columnconfigure(2, weight=0)

        # Configure main command frame
        command_frame.columnconfigure(0, weight=1)

        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=1)
        targets_frame.columnconfigure(0, weight=1)
        targets_frame.rowconfigure(0, weight=1)
        messages_frame.columnconfigure(0, weight=1)
        messages_frame.rowconfigure(0, weight=1)
        #command_frame.columnconfigure(1, weight=1)

    def process_gui_updates(self):
        """Process all pending GUI updates from the queue"""
        try:
            while True:
                # Get all pending updates (non-blocking)
                callback, args = self.gui_queue.get_nowait()
                callback(*args)
        except:
            pass  # Queue is empty
        
        # Schedule next check
        self.root.after(100, self.process_gui_updates)

    def show_target_menu(self, event):
        """Show context menu on right-click"""
        item = self.targets_tree.identify_row(event.y)
        if item:
            self.targets_tree.selection_set(item)
            self.target_menu.post(event.x_root, event.y_root)

    def interact_with_target(self):
        """Set interaction with selected target"""
        selected = self.targets_tree.selection()
        if selected:
            target_id = self.targets_tree.item(selected[0], "values")[0]
            self.interacting_with_target = target_id
            self.interaction_status.config(text=f"Mode: Interacting with {target_id}")
            self.normal_mode_btn.config(state=tk.NORMAL)
            self.log_message(f"Now interacting with target: {target_id}")

    def switch_to_normal_mode(self):
        """Switch back to normal command mode"""
        self.interacting_with_target = None
        self.interaction_status.config(text="Mode: C2")
        self.normal_mode_btn.config(state=tk.DISABLED)
        self.log_message("Switched back to normal mode")

    def toggle_connection(self):
        if not self.connected:
            self.connect_to_server()
        else:
            self.disconnect_from_server()

    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip.get(), self.server_port.get()))
            self.connected = True
            self.connect_btn.config(text="Disconnect")
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            
            self.log_message("Connected to server")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")

    def disconnect_from_server(self):
        self.connected = False
        if self.socket:
            self.socket.close()
            self.socket = None
        
        self.connect_btn.config(text="Connect")
        self.log_message("Disconnected from server")
        
        # Clear targets
        with self.target_lock:
            self.targets.clear()
            # Queue the treeview clearing operation
            self.gui_queue.put((self._clear_targets_tree, ()))
        
        # Reset interaction state
        self.switch_to_normal_mode()

    def send_command(self, event=None):
        if not self.connected:
            messagebox.showwarning("Not Connected", "Not connected to server")
            return
            
        command = self.command_entry.get()
        if not command:
            return
            
        try:
            # Format command based on interaction mode
            if self.interacting_with_target:
                formatted_command = f"TARGET:{self.interacting_with_target}:{command}"
            else:
                formatted_command = command
                
            self.socket.sendall((formatted_command + "\n").encode())
            self.command_entry.delete(0, tk.END)
            self.log_message(f"Sent: {formatted_command}")
        except Exception as e:
            self.log_message(f"Error sending command: {str(e)}")

    def receive_messages(self):
        buffer = ""
        while self.connected:
            try:
                data = self.socket.recv(4096).decode()
                if not data:
                    break
                    
                buffer += data
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self.process_message(line)
                    
            except Exception as e:
                if self.connected:  # Only log if we're supposed to be connected
                    self.log_message(f"Error receiving data: {str(e)}")
                break
                
        # If we get here, we've been disconnected
        if self.connected:
            self.gui_queue.put((self.disconnect_from_server, ()))

    def process_message(self, message):

        # if message.startswith("OUTPUT:"):
        #     self.gui_queue.put((self.log_message, (f" {message}", "green")))
        # else:
        self.gui_queue.put((self.log_message, (f"Received: {message}",)))
        
        # Check if this is a target registration message
        if message.startswith("TARGET:"):
            # Extract target ID from previous command
            target_id = message[7:].strip()
            self.add_target(target_id)
        
        # Check if this is a message from a target
        elif "TARGET:" in message and "registered" not in message:
            # Look for target ID in the message
            parts = message.split(":")
            if len(parts) >= 2:
                target_id = parts[1].strip()
                self.update_target(target_id)

    def add_target(self, target_id):
        with self.target_lock:
            if target_id not in self.targets:
                self.targets[target_id] = {
                    "last_seen": datetime.now(),
                    "status": "Active"
                }
                
                # Add to treeview via queue
                self.gui_queue.put((self._add_target_to_tree, (target_id,)))
                self.gui_queue.put((self.log_message, (f"New target connected: {target_id}",)))

    def update_target(self, target_id):
        with self.target_lock:
            if target_id in self.targets:
                self.targets[target_id]["last_seen"] = datetime.now()
                self.targets[target_id]["status"] = "Active"
                
                # Update treeview via queue
                self.gui_queue.put((self._update_target_in_tree, (target_id,)))

    def remove_target(self, target_id):
        with self.target_lock:
            if target_id in self.targets:
                del self.targets[target_id]
                
                # Remove from treeview via queue
                self.gui_queue.put((self._remove_target_from_tree, (target_id,)))
                self.gui_queue.put((self.log_message, (f"Target removed: {target_id}",)))
                
                # If we were interacting with this target, switch to normal mode
                if self.interacting_with_target == target_id:
                    self.gui_queue.put((self.switch_to_normal_mode, ()))

    def _clear_targets_tree(self):
        """Clear all items from the targets treeview"""
        for item in self.targets_tree.get_children():
            self.targets_tree.delete(item)

    def _add_target_to_tree(self, target_id):
        with self.target_lock:
            if target_id in self.targets:
                target = self.targets[target_id]
                self.targets_tree.insert("", "end", values=(
                    target_id, 
                    target["last_seen"].strftime("%H:%M:%S"),
                    target["status"]
                ))

    def _update_target_in_tree(self, target_id):
        with self.target_lock:
            if target_id in self.targets:
                target = self.targets[target_id]
                
                # Find the item in the treeview
                for item in self.targets_tree.get_children():
                    if self.targets_tree.item(item, "values")[0] == target_id:
                        self.targets_tree.item(item, values=(
                            target_id,
                            target["last_seen"].strftime("%H:%M:%S"),
                            target["status"]
                        ))
                        break

    def _remove_target_from_tree(self, target_id):
        # Find and remove the item from the treeview
        for item in self.targets_tree.get_children():
            if self.targets_tree.item(item, "values")[0] == target_id:
                self.targets_tree.delete(item)
                break

    def cleanup_old_targets(self):
        """Remove targets that haven't been seen in 5 minutes"""
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            if not self.connected:
                continue
                
            now = datetime.now()
            to_remove = []
            
            with self.target_lock:
                for target_id, target_info in self.targets.items():
                    if now - target_info["last_seen"] > timedelta(minutes=5):
                        to_remove.append(target_id)
            
            for target_id in to_remove:
                self.remove_target(target_id)

    
    def log_message(self, message, color="black"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Configure tag for the specified color if it doesn't exist
        if color not in self.messages_text.tag_names():
            self.messages_text.tag_configure(color, foreground=color)
        
        # Insert timestamp in default color
        self.messages_text.insert(tk.END, f"[{timestamp}] ")
        
        # Insert message with specified color
        self.messages_text.insert(tk.END, f"{message}\n", color)
        
        self.messages_text.see(tk.END)


    def __del__(self):
        self.connected = False
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = C2Client(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()