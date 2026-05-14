# """
# Venex C2 Mobile - Modern Kivy Application
# Compatible with Python 3.11+
# """
# import socket
# import threading
# import hashlib
# import time
# import os
# from datetime import datetime, timedelta
# from queue import Queue
# import ipaddress
# import shutil

# from kivy.app import App
# from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
# from kivy.uix.boxlayout import BoxLayout
# from kivy.uix.gridlayout import GridLayout
# from kivy.uix.scrollview import ScrollView
# from kivy.uix.label import Label
# from kivy.uix.button import Button
# from kivy.uix.textinput import TextInput
# from kivy.uix.popup import Popup
# from kivy.clock import Clock
# from kivy.core.window import Window
# from kivy.metrics import dp
# from kivy.properties import StringProperty, BooleanProperty, ListProperty
# from kivy.graphics import Color, RoundedRectangle, Line
# from kivy.uix.recycleview import RecycleView
# from kivy.uix.recycleview.views import RecycleDataViewBehavior
# from kivy.uix.behaviors import ButtonBehavior


# # --- Color Palette ---
# class Colors:
#     PRIMARY = [0.0, 0.47, 0.83, 1]  # #0078d4
#     PRIMARY_DARK = [0.0, 0.35, 0.62, 1]  # #005a9e
#     BG_DARK = [0.13, 0.13, 0.13, 1]  # #202020
#     CARD_DARK = [0.17, 0.17, 0.17, 1]  # #2b2b2b
#     CARD_DARKER = [0.10, 0.10, 0.10, 1]  # #1a1a1a
#     TEXT_PRIMARY = [1, 1, 1, 1]  # #ffffff
#     TEXT_SECONDARY = [0.63, 0.63, 0.63, 1]  # #a0a0a0
#     SUCCESS = [0.13, 0.87, 0.13, 1]  # #22DD22
#     DANGER = [0.82, 0.20, 0.22, 1]  # #d13438
#     INPUT_BG = [0.24, 0.24, 0.24, 1]  # #3d3d3d


# # --- Custom Widgets ---
# class RoundedButton(Button):
#     """Modern rounded button with gradient effect"""
#     def __init__(self, bg_color=Colors.PRIMARY, **kwargs):
#         super().__init__(**kwargs)
#         self.background_normal = ''
#         self.background_color = bg_color
#         self.color = Colors.TEXT_PRIMARY
#         self.size_hint_y = None
#         self.height = dp(48)
#         self.bold = True
        
#         with self.canvas.before:
#             self.bg_color = Color(*bg_color)
#             self.bg_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(12)])
        
#         self.bind(pos=self.update_rect, size=self.update_rect)
    
#     def update_rect(self, *args):
#         self.bg_rect.pos = self.pos
#         self.bg_rect.size = self.size


# class ModernTextInput(TextInput):
#     """Styled text input with rounded corners"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.background_normal = ''
#         self.background_active = ''
#         self.background_color = Colors.INPUT_BG
#         self.foreground_color = Colors.TEXT_PRIMARY
#         self.cursor_color = Colors.PRIMARY
#         self.size_hint_y = None
#         self.height = dp(48)
#         self.padding = [dp(15), dp(12)]
#         self.multiline = False
        
#         with self.canvas.before:
#             Color(*Colors.INPUT_BG)
#             self.bg_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
        
#         self.bind(pos=self.update_rect, size=self.update_rect)
    
#     def update_rect(self, *args):
#         self.bg_rect.pos = self.pos
#         self.bg_rect.size = self.size

# # class ModernTextInput(TextInput):
# #     def __init__(self, **kwargs):
# #         super().__init__(**kwargs)

# #         # Remove all custom canvas drawings ❗
# #         self.canvas.before.clear()
# #         self.canvas.after.clear()

# #         # Use only Kivy's built-in background
# #         self.background_normal = ''
# #         self.background_active = ''
# #         self.background_color = Colors.INPUT_BG

# #         # Make text visible
# #         self.foreground_color = Colors.TEXT_PRIMARY
# #         self.cursor_color = Colors.TEXT_PRIMARY
# #         self.hint_text_color = Colors.TEXT_SECONDARY

# #         self.size_hint_y = None
# #         self.height = dp(48)
# #         self.padding = [dp(12), dp(12)]
# #         self.multiline = False


# class ModernCard(BoxLayout):
#     """Card container with rounded corners and shadow effect"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.orientation = 'vertical'
#         self.size_hint_y = None
#         self.padding = dp(20)
#         self.spacing = dp(10)
        
#         with self.canvas.before:
#             Color(*Colors.CARD_DARK)
#             self.bg_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(15)])
        
#         self.bind(pos=self.update_rect, size=self.update_rect)
    
#     def update_rect(self, *args):
#         self.bg_rect.pos = self.pos
#         self.bg_rect.size = self.size


# class TargetItem(RecycleDataViewBehavior, ButtonBehavior, BoxLayout):
#     """Individual target item in the list"""
#     target_id = StringProperty()
#     last_seen = StringProperty()
#     status = StringProperty()
    
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.orientation = 'vertical'
#         self.size_hint_y = None
#         self.height = dp(80)
#         self.padding = dp(15)
        
#         with self.canvas.before:
#             Color(*Colors.CARD_DARK)
#             self.bg_rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(10)])
        
#         self.bind(pos=self.update_rect, size=self.update_rect)
        
#         # Target ID
#         self.add_widget(Label(
#             text=f"[b]{self.target_id}[/b]",
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             size_hint_y=None,
#             height=dp(25),
#             halign='left',
#             valign='middle'
#         ))
        
#         # Status row
#         status_row = BoxLayout(size_hint_y=None, height=dp(20))
#         status_row.add_widget(Label(
#             text=f"Last: {self.last_seen}",
#             color=Colors.TEXT_SECONDARY,
#             font_size=dp(12),
#             halign='left',
#             valign='middle'
#         ))
#         status_row.add_widget(Label(
#             text=f"● {self.status}",
#             color=Colors.SUCCESS if self.status == "Active" else Colors.DANGER,
#             font_size=dp(12),
#             halign='right',
#             valign='middle'
#         ))
#         self.add_widget(status_row)
    
#     def update_rect(self, *args):
#         self.bg_rect.pos = self.pos
#         self.bg_rect.size = self.size
    
#     def on_press(self):
#         app = App.get_running_app()
#         app.interact_with_target(self.target_id)


# class TargetsRecycleView(RecycleView):
#     """RecycleView for displaying targets"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.data = []


# # --- Main Screens ---
# class DashboardScreen(Screen):
#     """Main dashboard with targets and output"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.name = 'dashboard'
        
#         main_layout = BoxLayout(orientation='vertical', padding=dp(15), spacing=dp(15))
        
#         # Header
#         header = BoxLayout(size_hint_y=None, height=dp(60), spacing=dp(10))
#         header.add_widget(Label(
#             text='[b]Dashboard[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(24),
#             halign='left',
#             valign='middle'
#         ))
#         main_layout.add_widget(header)
        
#         # Targets Card
#         targets_card = ModernCard()
#         targets_card.height = dp(300)
#         targets_card.add_widget(Label(
#             text='[b]Active Targets[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(16),
#             size_hint_y=None,
#             height=dp(30),
#             halign='left',
#             valign='middle'
#         ))
        
#         self.targets_view = TargetsRecycleView()
#         targets_card.add_widget(self.targets_view)
#         main_layout.add_widget(targets_card)
        
#         # Output Card
#         output_card = ModernCard()
#         output_card.add_widget(Label(
#             text='[b]Terminal Output[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(16),
#             size_hint_y=None,
#             height=dp(30),
#             halign='left',
#             valign='middle'
#         ))
        
#         scroll = ScrollView()
#         self.output_label = Label(
#             text='',
#             color=Colors.SUCCESS,
#             font_name='RobotoMono-Regular',
#             font_size=dp(12),
#             size_hint_y=None,
#             halign='left',
#             valign='top',
#             markup=True
#         )
#         self.output_label.bind(texture_size=self.output_label.setter('size'))
#         scroll.add_widget(self.output_label)
#         output_card.add_widget(scroll)
#         main_layout.add_widget(output_card)
        
#         self.add_widget(main_layout)
    
#     def update_targets(self, targets_data):
#         """Update targets list"""
#         self.targets_view.data = targets_data
    
#     def add_output(self, text):
#         """Add text to output"""
#         self.output_label.text += f"{text}\n"


# class ConnectionScreen(Screen):
#     """Connection configuration screen"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.name = 'connection'
        
#         main_layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))
        
#         # Header
#         main_layout.add_widget(Label(
#             text='[b]Server Connection[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(24),
#             size_hint_y=None,
#             height=dp(60),
#             halign='center',
#             valign='middle'
#         ))
        
#         # Connection Card
#         conn_card = ModernCard()
#         conn_card.height = dp(400)
        
#         # Server IP
#         conn_card.add_widget(Label(
#             text='Server IP/Hostname',
#             color=Colors.TEXT_SECONDARY,
#             size_hint_y=None,
#             height=dp(25),
#             halign='left',
#             valign='middle'
#         ))
#         self.ip_input = ModernTextInput(text='127.0.0.1')
#         conn_card.add_widget(self.ip_input)
        
#         # Port
#         conn_card.add_widget(Label(
#             text='Port',
#             color=Colors.TEXT_SECONDARY,
#             size_hint_y=None,
#             height=dp(25),
#             halign='left',
#             valign='middle'
#         ))
#         self.port_input = ModernTextInput(text='7777', input_filter='int')
#         conn_card.add_widget(self.port_input)
        
#         # Auth Token
#         conn_card.add_widget(Label(
#             text='Authentication Token',
#             color=Colors.TEXT_SECONDARY,
#             size_hint_y=None,
#             height=dp(25),
#             halign='left',
#             valign='middle'
#         ))
#         self.token_input = ModernTextInput(text='your token', password=True)
#         conn_card.add_widget(self.token_input)
        
#         # Connect Button
#         self.connect_btn = RoundedButton(text='Connect', bg_color=Colors.PRIMARY)
#         self.connect_btn.bind(on_press=self.toggle_connection)
#         conn_card.add_widget(self.connect_btn)
        
#         main_layout.add_widget(conn_card)
        
#         # Status
#         self.status_label = Label(
#             text='● Disconnected',
#             color=Colors.DANGER,
#             size_hint_y=None,
#             height=dp(40),
#             font_size=dp(14)
#         )
#         main_layout.add_widget(self.status_label)
        
#         self.add_widget(main_layout)
    
#     def toggle_connection(self, instance):
#         app = App.get_running_app()
#         if not app.connected:
#             app.connect_to_server(
#                 self.ip_input.text,
#                 int(self.port_input.text),
#                 self.token_input.text
#             )
#         else:
#             app.disconnect_from_server()
    
#     def update_connection_status(self, connected):
#         if connected:
#             self.connect_btn.text = 'Disconnect'
#             self.connect_btn.bg_color = Colors.DANGER
#             self.status_label.text = '● Connected'
#             self.status_label.color = Colors.SUCCESS
#         else:
#             self.connect_btn.text = 'Connect'
#             self.connect_btn.bg_color = Colors.PRIMARY
#             self.status_label.text = '● Disconnected'
#             self.status_label.color = Colors.DANGER


# class CommandScreen(Screen):
#     """Command execution screen"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.name = 'command'
        
#         main_layout = BoxLayout(orientation='vertical', padding=dp(15), spacing=dp(15))
        
#         # Header with mode indicator
#         header = BoxLayout(size_hint_y=None, height=dp(60))
#         self.mode_label = Label(
#             text='[b]MODE: C2 SERVER[/b]',
#             markup=True,
#             color=Colors.TEXT_SECONDARY,
#             font_size=dp(14),
#             halign='left',
#             valign='middle'
#         )
#         header.add_widget(self.mode_label)
#         main_layout.add_widget(header)
        
#         # Log output
#         log_card = ModernCard()
#         log_card.add_widget(Label(
#             text='[b]System Logs[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(16),
#             size_hint_y=None,
#             height=dp(30),
#             halign='left',
#             valign='middle'
#         ))
        
#         scroll = ScrollView()
#         self.log_label = Label(
#             text='',
#             color=Colors.TEXT_SECONDARY,
#             font_size=dp(12),
#             size_hint_y=None,
#             halign='left',
#             valign='top',
#             markup=True
#         )
#         self.log_label.bind(texture_size=self.log_label.setter('size'))
#         scroll.add_widget(self.log_label)
#         log_card.add_widget(scroll)
#         main_layout.add_widget(log_card)
        
#         # Command input
#         cmd_layout = BoxLayout(size_hint_y=None, height=dp(60), spacing=dp(10))
#         self.cmd_input = ModernTextInput(hint_text='Enter command...')
#         self.cmd_input.bind(on_text_validate=self.send_command)
#         cmd_layout.add_widget(self.cmd_input)
        
#         send_btn = RoundedButton(text='Send', size_hint_x=None, width=dp(100))
#         send_btn.bind(on_press=self.send_command)
#         cmd_layout.add_widget(send_btn)
        
#         main_layout.add_widget(cmd_layout)
        
#         self.add_widget(main_layout)
    
#     def send_command(self, instance):
#         app = App.get_running_app()
#         cmd = self.cmd_input.text.strip()
#         if cmd and app.connected:
#             app.send_command(cmd)
#             self.cmd_input.text = ''
    
#     def add_log(self, text):
#         """Add text to log"""
#         timestamp = datetime.now().strftime("%H:%M:%S")
#         self.log_label.text += f"[{timestamp}] {text}\n"
    
#     def update_mode(self, mode_text, color):
#         """Update mode indicator"""
#         self.mode_label.text = f'[b]{mode_text}[/b]'
#         self.mode_label.color = color


# class FileExplorerScreen(Screen):
#     """File explorer for content box"""
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.name = 'files'
        
#         main_layout = BoxLayout(orientation='vertical', padding=dp(15), spacing=dp(15))
        
#         # Header
#         header = BoxLayout(size_hint_y=None, height=dp(60))
#         header.add_widget(Label(
#             text='[b]Content Box[/b]',
#             markup=True,
#             color=Colors.TEXT_PRIMARY,
#             font_size=dp(24),
#             halign='left',
#             valign='middle'
#         ))
#         main_layout.add_widget(header)
        
#         # Path bar
#         path_bar = BoxLayout(size_hint_y=None, height=dp(48), spacing=dp(10))
#         self.path_label = Label(
#             text='/',
#             color=Colors.TEXT_SECONDARY,
#             font_size=dp(12),
#             halign='left',
#             valign='middle'
#         )
#         path_bar.add_widget(self.path_label)
        
#         up_btn = RoundedButton(text='↑ Up', size_hint_x=None, width=dp(80))
#         up_btn.bind(on_press=self.go_up)
#         path_bar.add_widget(up_btn)
        
#         refresh_btn = RoundedButton(text='⟳', size_hint_x=None, width=dp(60))
#         refresh_btn.bind(on_press=self.refresh_files)
#         path_bar.add_widget(refresh_btn)
        
#         main_layout.add_widget(path_bar)
        
#         # Files list
#         scroll = ScrollView()
#         self.files_layout = GridLayout(cols=1, spacing=dp(10), size_hint_y=None)
#         self.files_layout.bind(minimum_height=self.files_layout.setter('height'))
#         scroll.add_widget(self.files_layout)
#         main_layout.add_widget(scroll)
        
#         self.add_widget(main_layout)
    
#     def refresh_files(self, instance=None):
#         """Refresh file list"""
#         app = App.get_running_app()
#         self.files_layout.clear_widgets()
#         self.path_label.text = app.current_path
        
#         try:
#             for item in os.listdir(app.current_path):
#                 path = os.path.join(app.current_path, item)
#                 is_dir = os.path.isdir(path)
                
#                 file_btn = RoundedButton(
#                     text=f"{'📁' if is_dir else '📄'} {item}",
#                     bg_color=Colors.CARD_DARK,
#                     halign='left'
#                 )
#                 file_btn.bind(on_press=lambda x, p=path, d=is_dir: self.on_file_click(p, d))
#                 self.files_layout.add_widget(file_btn)
#         except Exception as e:
#             pass
    
#     def on_file_click(self, path, is_dir):
#         """Handle file/folder click"""
#         if is_dir:
#             app = App.get_running_app()
#             app.current_path = path
#             self.refresh_files()
    
#     def go_up(self, instance):
#         """Go up one directory"""
#         app = App.get_running_app()
#         app.current_path = os.path.dirname(app.current_path)
#         self.refresh_files()


# # --- Main App ---
# class VenexC2App(App):
#     """Main Kivy Application"""
#     connected = BooleanProperty(False)
    
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.socket = None
#         self.targets = {}
#         self.target_lock = threading.Lock()
#         self.interacting_with_target = None
#         self.gui_queue = Queue()
        
#         # Setup content box directory inside app's private storage
#         self.content_box_path = os.path.join(os.path.dirname(__file__), "content_box")
#         os.makedirs(self.content_box_path, exist_ok=True)
#         self.current_path = self.content_box_path

#         # self.content_box_path = os.path.join(os.environ['ANDROID_PRIVATE'], 'venex_content_box')
#         # self.current_path = self.content_box_path

#         if not os.path.exists(self.content_box_path):
#             os.makedirs(self.content_box_path, exist_ok=True)
    
#     def build(self):
#         """Build the app UI"""
#         Window.clearcolor = Colors.BG_DARK
#         #Window.softinput_mode = "below_target"
        
#         # Screen Manager
#         self.sm = ScreenManager(transition=SlideTransition())
        
#         # Add screens
#         self.dashboard_screen = DashboardScreen()
#         self.connection_screen = ConnectionScreen()
#         self.command_screen = CommandScreen()
#         self.files_screen = FileExplorerScreen()
        
#         self.sm.add_widget(self.connection_screen)
#         self.sm.add_widget(self.dashboard_screen)
#         self.sm.add_widget(self.command_screen)
#         self.sm.add_widget(self.files_screen)
        
#         # Bottom navigation
#         root = BoxLayout(orientation='vertical')
#         root.add_widget(self.sm)
        
#         # Navigation bar
#         nav_bar = BoxLayout(size_hint_y=None, height=dp(60), spacing=dp(5), padding=dp(5))
#         nav_bar.canvas.before.clear()
#         with nav_bar.canvas.before:
#             Color(*Colors.CARD_DARKER)
#             nav_bar.bg_rect = RoundedRectangle(pos=nav_bar.pos, size=nav_bar.size)
        
#         nav_buttons = [
#             ('🔌', 'connection'),
#             ('📊', 'dashboard'),
#             ('⌨️', 'command'),
#             ('📁', 'files')
#         ]
        
#         for icon, screen_name in nav_buttons:
#             btn = RoundedButton(text=icon, bg_color=Colors.CARD_DARK)
#             btn.bind(on_press=lambda x, s=screen_name: self.switch_screen(s))
#             nav_bar.add_widget(btn)
        
#         root.add_widget(nav_bar)
        
#         # Start background processes
#         Clock.schedule_interval(self.process_gui_updates, 0.1)
#         threading.Thread(target=self.cleanup_old_targets, daemon=True).start()
        
#         return root
    
#     def switch_screen(self, screen_name):
#         """Switch to a different screen"""
#         self.sm.current = screen_name
#         if screen_name == 'files':
#             self.files_screen.refresh_files()
    
#     # --- Networking ---
#     def connect_to_server(self, host, port, token):
#         """Connect to C2 server"""
#         try:
#             ip = host if self.is_ip(host) else socket.gethostbyname(host)
#             self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.socket.connect((ip, port))
#             self.connected = True
            
#             # Send auth token
#             sha256_token = hashlib.sha256(token.encode('utf-8')).hexdigest()
#             self.socket.sendall(f"TOKEN:{sha256_token}".encode("utf-8"))
            
#             # Update UI
#             self.connection_screen.update_connection_status(True)
#             self.log_message(f"Connected to {ip}:{port}")
            
#             # Start receive thread
#             threading.Thread(target=self.receive_messages, daemon=True).start()
            
#         except Exception as e:
#             self.show_popup("Connection Error", str(e))
    
#     def disconnect_from_server(self):
#         """Disconnect from server"""
#         self.connected = False
#         if self.socket:
#             self.socket.close()
        
#         self.connection_screen.update_connection_status(False)
#         self.log_message("Disconnected from server")
        
#         with self.target_lock:
#             self.targets.clear()
#             self.gui_queue.put((self.update_targets_ui, ()))
    
#     def send_command(self, cmd):
#         """Send command to server"""
#         if not self.connected or not cmd:
#             return
        
#         try:
#             formatted_cmd = f"TARGET:{self.interacting_with_target}:{cmd}" if self.interacting_with_target else cmd
#             self.socket.sendall((formatted_cmd + "\n").encode())
#             self.log_message(f"Sent: {formatted_cmd}")
#         except Exception as e:
#             self.log_message(f"Error sending command: {e}")
    
#     def receive_messages(self):
#         """Receive messages from server"""
#         buffer = b""
#         while self.connected:
#             try:
#                 data = self.socket.recv(4096)
#                 if not data:
#                     break
                
#                 buffer += data
#                 while b"END_OF" in buffer:
#                     line, buffer = buffer.split(b"END_OF", 1)
#                     if line.strip():
#                         self.process_message(line.strip())
#             except:
#                 break
        
#         self.gui_queue.put((self.disconnect_from_server, ()))
    
#     def process_message(self, message):
#         """Process received message"""
#         if message.startswith(b"TARGET:"):
#             target_id = message[7:].strip().decode('utf-8')
#             self.add_target(target_id)
#         elif message.startswith(b"/DATA:"):
#             text = message[6:].decode('utf-8')
#             self.gui_queue.put((self.add_output, (f" $$-> {text}",)))
#         else:
#             text = message.decode(errors='ignore')
#             self.gui_queue.put((self.log_message, (f"← {text}",)))
    
#     # --- Target Management ---
#     def add_target(self, target_id):
#         """Add or update target"""
#         with self.target_lock:
#             if target_id not in self.targets:
#                 self.targets[target_id] = {
#                     "last": datetime.now(),
#                     "status": "Active"
#                 }
#             else:
#                 self.targets[target_id]["last"] = datetime.now()
            
#             self.gui_queue.put((self.update_targets_ui, ()))
    
#     def update_targets_ui(self):
#         """Update targets display"""
#         with self.target_lock:
#             targets_data = []
#             for tid, info in self.targets.items():
#                 targets_data.append({
#                     'target_id': tid,
#                     'last_seen': info['last'].strftime("%H:%M:%S"),
#                     'status': info['status']
#                 })
            
#             self.dashboard_screen.update_targets(targets_data)
    
#     def interact_with_target(self, target_id):
#         """Start interacting with a target"""
#         self.interacting_with_target = target_id
#         self.command_screen.update_mode(
#             f"MODE: INTERACTING WITH {target_id}",
#             Colors.PRIMARY
#         )
#         self.log_message(f"Now interacting with {target_id}")
#         self.switch_screen('command')
    
#     def cleanup_old_targets(self, dt=None):
#         """Remove inactive targets"""
#         while True:
#             time.sleep(30)
#             if not self.connected:
#                 continue
            
#             now = datetime.now()
#             with self.target_lock:
#                 to_remove = [
#                     tid for tid, info in self.targets.items()
#                     if now - info["last"] > timedelta(minutes=5)
#                 ]
                
#                 for tid in to_remove:
#                     del self.targets[tid]
                
#                 if to_remove:
#                     self.gui_queue.put((self.update_targets_ui, ()))
                    
#                     if self.interacting_with_target in to_remove:
#                         self.interacting_with_target = None
#                         self.gui_queue.put((
#                             self.command_screen.update_mode,
#                             ("MODE: C2 SERVER", Colors.TEXT_SECONDARY)
#                         ))
    
#     # --- UI Updates ---
#     def process_gui_updates(self, dt):
#         """Process queued GUI updates"""
#         while not self.gui_queue.empty():
#             func, args = self.gui_queue.get()
#             func(*args)
    
#     def log_message(self, text):
#         """Add message to log"""
#         self.command_screen.add_log(text)
    
#     def add_output(self, text):
#         """Add text to output"""
#         self.dashboard_screen.add_output(text)
    
#     def show_popup(self, title, message):
#         """Show popup dialog"""
#         content = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
#         content.add_widget(Label(text=message, color=Colors.TEXT_PRIMARY))
        
#         close_btn = RoundedButton(text='Close', size_hint_y=None, height=dp(48))
#         content.add_widget(close_btn)
        
#         popup = Popup(
#             title=title,
#             content=content,
#             size_hint=(0.8, 0.4),
#             background_color=Colors.CARD_DARK
#         )
#         close_btn.bind(on_press=popup.dismiss)
#         popup.open()
    
#     # --- Utilities ---
#     @staticmethod
#     def is_ip(s):
#         """Check if string is valid IP address"""
#         try:
#             ipaddress.ip_address(s)
#             return True
#         except:
#             return False


# if __name__ == '__main__':
#     VenexC2App().run()
## // long term



import base64
import hashlib
import socket
import threading
import time
import os
import re
import ipaddress
import platform
import subprocess
import shutil
from datetime import datetime, timedelta
from queue import Queue

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.scrollview import ScrollView
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.actionbar import ActionBar, ActionView, ActionPrevious, ActionButton
from kivy.uix.popup import Popup
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.graphics import Color, RoundedRectangle

from android.storage import app_storage_path

# --- Mobile Styling Constants ---
ACCENT_BLUE = [0, 0.47, 0.83, 1]  # #0078d4
BG_DARK = [0.125, 0.125, 0.125, 1]  # #202020
CARD_DARK = [0.17, 0.17, 0.17, 1]  # #2b2b2b
TEXT_PRIMARY = [1, 1, 1, 1]
TEXT_SECONDARY = [0.63, 0.63, 0.63, 1]
SUCCESS_GREEN = [0.13, 0.87, 0.13, 1]
DANGER_RED = [0.82, 0.2, 0.22, 1]

class StyledButton(Button):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_normal = ''
        self.background_color = ACCENT_BLUE
        self.font_size = '16sp'
        self.bold = True
        self.size_hint_y = None
        self.height = dp(45)

class DashboardScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        
        # Connection Card
        conn_card = BoxLayout(orientation='vertical', size_hint_y=None, height=dp(160), padding=dp(10), spacing=dp(5))
        with conn_card.canvas.before:
            Color(*CARD_DARK)
            self.rect = RoundedRectangle(pos=conn_card.pos, size=conn_card.size, radius=[dp(10)])
        conn_card.bind(pos=self.update_rect, size=self.update_rect)
        
        ip_layout = BoxLayout(spacing=dp(5), size_hint_y=None, height=dp(40))
        ip_layout.add_widget(Label(text="Server:", size_hint_x=0.25, color=TEXT_PRIMARY))
        self.ip_input = TextInput(text="127.0.0.1", multiline=False, background_color=[0.2, 0.2, 0.2, 1], foreground_color=TEXT_PRIMARY)
        ip_layout.add_widget(self.ip_input)
        
        port_layout = BoxLayout(spacing=dp(5), size_hint_y=None, height=dp(40))
        port_layout.add_widget(Label(text="Port:", size_hint_x=0.25, color=TEXT_PRIMARY))
        self.port_input = TextInput(text="7777", multiline=False, background_color=[0.2, 0.2, 0.2, 1], foreground_color=TEXT_PRIMARY)
        port_layout.add_widget(self.port_input)
        
        self.connect_btn = StyledButton(text="Connect")
        
        conn_card.add_widget(ip_layout)
        conn_card.add_widget(port_layout)
        conn_card.add_widget(self.connect_btn)
        self.layout.add_widget(conn_card)
        
        # Targets List
        self.layout.add_widget(Label(text="Active Targets", size_hint_y=None, height=dp(30), bold=True, halign='left'))
        self.target_scroll = ScrollView(size_hint_y=0.3)
        self.target_list = GridLayout(cols=1, spacing=dp(2), size_hint_y=None)
        self.target_list.bind(minimum_height=self.target_list.setter('height'))
        self.target_scroll.add_widget(self.target_list)
        self.layout.add_widget(self.target_scroll)
        
        # Terminal Output
        self.layout.add_widget(Label(
            text="Terminal Output",
            size_hint_y=None,
            height=dp(20),
            bold=True,
            halign='left'
        ))

        self.output_scroll = ScrollView(size_hint=(1, None), height=dp(200))

        # Create container that supports padding
        output_container = BoxLayout(
            size_hint_y=None,
            padding=dp(10)  # <-- padding added here
        )
        output_container.bind(minimum_height=output_container.setter('height'))

        self.output_text = Label(
            text="",
            size_hint_y=None,
            color=SUCCESS_GREEN,
            font_name='Roboto',
            font_size='13sp',
            halign='left',
            valign='top',
            markup=True,
            text_size=(1, None)  # will be updated by width bind
        )

        # grow only by real text height
        self.output_text.bind(
            texture_size=lambda instance, value: setattr(instance, 'height', value[1])
        )


        # Update text_size when ScrollView width changes
        self.output_scroll.bind(
            width=lambda instance, value: setattr(self.output_text, 'text_size', (value, None))
        )

        output_container.add_widget(self.output_text)
        self.output_scroll.add_widget(output_container)

        # Background canvas (kept the same)
        with self.output_scroll.canvas.before:
            Color(0.1, 0.1, 0.1, 1)
            self.out_rect = RoundedRectangle(
                pos=self.output_scroll.pos,
                size=self.output_scroll.size,
                radius=[dp(10)]
            )

        self.output_scroll.bind(pos=self.update_out_rect, size=self.update_out_rect)
        self.layout.add_widget(self.output_scroll)
        
        # Command Bar
        self.mode_label = Label(text="MODE: C2 SERVER", size_hint_y=None, height=dp(20), font_size='11sp', color=TEXT_SECONDARY)
        self.layout.add_widget(self.mode_label)
        
        cmd_layout = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(5))
        # FIXED: Changed placeholder_text to hint_text for Kivy compatibility
        self.cmd_input = TextInput(hint_text="Type command...", multiline=False, background_color=[0.15, 0.15, 0.15, 1], foreground_color=TEXT_PRIMARY)
        self.send_btn = StyledButton(text="Exec", size_hint_x=0.2)
        cmd_layout.add_widget(self.cmd_input)
        cmd_layout.add_widget(self.send_btn)
        self.layout.add_widget(cmd_layout)
        
        self.add_widget(self.layout)

    def update_rect(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size

    def update_out_rect(self, instance, value):
        self.out_rect.pos = instance.pos
        self.out_rect.size = instance.size
        self.output_text.height = max(self.output_scroll.height, self.output_text.texture_size[1])

class ContentScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.layout = BoxLayout(orientation='vertical', padding=dp(10), spacing=dp(10))
        
        header = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
        header.add_widget(Label(text="Content Box", font_size='20sp', bold=True))
        self.refresh_btn = StyledButton(text="Refresh", size_hint_x=0.3)
        header.add_widget(self.refresh_btn)
        self.layout.add_widget(header)
        
        self.path_label = Label(text="", size_hint_y=None, height=dp(30), color=TEXT_SECONDARY, halign='left')
        self.layout.add_widget(self.path_label)
        
        self.file_scroll = ScrollView()
        self.file_list = GridLayout(cols=1, spacing=dp(5), size_hint_y=None)
        self.file_list.bind(minimum_height=self.file_list.setter('height'))
        self.file_scroll.add_widget(self.file_list)
        self.layout.add_widget(self.file_scroll)
        
        self.add_widget(self.layout)

class SettingsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))
        layout.add_widget(Label(text="Settings", font_size='24sp', bold=True, size_hint_y=None, height=dp(60)))
        
        layout.add_widget(Label(text="Auth Token:", size_hint_y=None, height=dp(30), halign='left'))
        self.token_input = TextInput(text="your token", multiline=False, size_hint_y=None, height=dp(45))
        layout.add_widget(self.token_input)
        
        layout.add_widget(Label(text="System Logs", font_size='18sp', bold=True, size_hint_y=None, height=dp(40)))
        self.log_scroll = ScrollView()
        self.log_text = Label(text="", size_hint_y=None, color=TEXT_SECONDARY, font_size='12sp', halign='left', valign='top')
        self.log_text.bind(size=self.log_text.setter('text_size'))
        self.log_scroll.add_widget(self.log_text)
        layout.add_widget(self.log_scroll)
        
        self.add_widget(layout)

class VenexC2Mobile(App):
    def build(self):
        Window.clearcolor = BG_DARK
        self.sm = ScreenManager()
        
        # Logic Variables
        self.connected = False
        self.socket = None
        self.targets = {}
        self.target_lock = threading.Lock()
        self.interacting_with_target = None
        self.gui_queue = Queue()
        
        self.content_box_path = os.path.join(app_storage_path(), "content_box")
        self.current_path = self.content_box_path

        if not os.path.exists(self.content_box_path):
            os.makedirs(self.content_box_path)
        
        self.global_commands = ["AUTH:STOP_HTTP", "AUTH:START_HTTP", "help", "targets", "clear", "exit"]
        self.target_commands = ["tm powershell -command \"\"", "$sysinfo", "rmf", "back", "screenshot", "shell", "pwd", "ls"]
        self.current_commands = self.global_commands
        
        # Screens
        self.dash = DashboardScreen(name='dashboard')
        self.content = ContentScreen(name='content')
        self.settings = SettingsScreen(name='settings')
        
        self.sm.add_widget(self.dash)
        self.sm.add_widget(self.content)
        self.sm.add_widget(self.settings)
        
        # Main Layout
        root = BoxLayout(orientation='vertical')
        
        # Action Bar
        ab = ActionBar(pos_hint={'top': 1})
        av = ActionView()
        ap = ActionPrevious(title='Venex C2', with_previous=False)
        av.add_widget(ap)
        av.add_widget(ActionButton(text='Dash', on_release=lambda x: self.switch_screen('dashboard')))
        av.add_widget(ActionButton(text='Files', on_release=lambda x: self.switch_screen('content')))
        av.add_widget(ActionButton(text='Settings', on_release=lambda x: self.switch_screen('settings')))
        ab.add_widget(av)
        
        root.add_widget(ab)
        root.add_widget(self.sm)
        
        # Bindings
        self.dash.connect_btn.bind(on_release=self.toggle_connection)
        self.dash.send_btn.bind(on_release=self.send_command)
        self.content.refresh_btn.bind(on_release=lambda x: self.refresh_file_explorer())
        
        # Start GUI update loop
        Clock.schedule_interval(self.process_gui_updates, 0.1)
        self.refresh_file_explorer()
        
        return root

    def switch_screen(self, name):
        self.sm.current = name

    def toggle_connection(self, instance):
        if not self.connected: self.connect_to_server()
        else: self.disconnect_from_server()

    def connect_to_server(self):
        host = self.dash.ip_input.text
        try:
            port = int(self.dash.port_input.text)
            ip = host if self.is_ip(host) else socket.gethostbyname(host)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ip, port))
            self.connected = True
            
            sha256_token = hashlib.sha256(self.settings.token_input.text.encode('utf-8')).hexdigest()
            self.socket.sendall(f"TOKEN:{sha256_token}".encode("utf-8"))
            
            self.dash.connect_btn.text = "Disconnect"
            self.dash.connect_btn.background_color = DANGER_RED
            
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.log_message(f"Connected to {ip}")
        except Exception as e:
            self.show_popup("Error", f"Connection failed: {e}")

    def disconnect_from_server(self):
        self.connected = False
        if self.socket: self.socket.close()
        self.dash.connect_btn.text = "Connect"
        self.dash.connect_btn.background_color = ACCENT_BLUE
        self.log_message("Disconnected")
        self.switch_to_normal_mode()
        with self.target_lock:
            self.targets.clear()
            self.gui_queue.put((self.clear_target_list, ()))

    def send_command(self, instance=None):
        cmd = self.dash.cmd_input.text.strip()
        if not cmd or not self.connected: return
        try:
            f_cmd = f"TARGET:{self.interacting_with_target}:{cmd}" if self.interacting_with_target else cmd
            self.socket.sendall((f_cmd + "\n").encode())
            self.dash.cmd_input.text = ""
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
            self.gui_queue.put((self.output_data, (f" $$-> {text}",)))
        else:
            self.gui_queue.put((self.output_server_log, (f" > {message.decode(errors='ignore')}",)))

    def add_target(self, tid):
        with self.target_lock:
            if tid not in self.targets:
                self.targets[tid] = {"last": datetime.now(), "status": "Active"}
                self.gui_queue.put((self.update_target_ui, ()))
            else:
                self.targets[tid]["last"] = datetime.now()

    def update_target_ui(self):
        self.dash.target_list.clear_widgets()
        for tid in self.targets:
            btn = Button(text=f"Target: {tid}", size_hint_y=None, height=dp(40), background_color=[0.2, 0.2, 0.2, 1])
            btn.bind(on_release=lambda x, t=tid: self.interact_with_target(t))
            self.dash.target_list.add_widget(btn)

    def interact_with_target(self, tid):
        self.interacting_with_target = tid
        self.dash.mode_label.text = f"MODE: INTERACTING WITH {tid}"
        self.dash.mode_label.color = ACCENT_BLUE
        self.log_message(f"Interacting with {tid}")
        self.current_commands = self.target_commands
        self.switch_screen('dashboard')

    def switch_to_normal_mode(self):
        self.interacting_with_target = None
        self.dash.mode_label.text = "MODE: C2 SERVER"
        self.dash.mode_label.color = TEXT_SECONDARY
        self.current_commands = self.global_commands

    def log_message(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.settings.log_text.text += f"[{ts}] {msg}\n"

        self.settings.log_text.texture_update()

        self.settings.log_text.height = max(self.settings.log_scroll.height, self.settings.log_text.texture_size[1])
    
    def output_data(self, msg):
        self.dash.output_text.text += f"[color=#5cb85c{msg}[/color]\n"
        self.dash.output_text.texture_update()
        self.dash.output_scroll.scroll_y = 0  # bottom scroll

    def output_server_log(self, msg):
        self.dash.output_text.text += f"[color=#F54927]{msg}[/color]\n"
        self.dash.output_text.texture_update()
        self.dash.output_scroll.scroll_y = 0
    
    def clear_target_list(self):
        self.dash.target_list.clear_widgets()


    def refresh_file_explorer(self):
        self.content.file_list.clear_widgets()
        self.content.path_label.text = self.current_path
        try:
            # Add "Up" button
            up_btn = Button(text=".. [Go Up]", size_hint_y=None, height=dp(45), background_color=[0.3, 0.3, 0.3, 1])
            up_btn.bind(on_release=lambda x: self.go_up_directory())
            self.content.file_list.add_widget(up_btn)
            
            for item in os.listdir(self.current_path):
                p = os.path.join(self.current_path, item)
                is_dir = os.path.isdir(p)
                prefix = "📁 " if is_dir else "📄 "
                btn = Button(text=f"{prefix}{item}", size_hint_y=None, height=dp(45), background_color=[0.2, 0.2, 0.2, 1])
                if is_dir:
                    btn.bind(on_release=lambda x, path=p: self.change_dir(path))
                self.content.file_list.add_widget(btn)
        except: pass

    def change_dir(self, path):
        self.current_path = path
        self.refresh_file_explorer()

    def go_up_directory(self):
        self.current_path = os.path.dirname(self.current_path)
        self.refresh_file_explorer()

    def is_ip(self, s):
        try:
            ipaddress.ip_address(s)
            return True
        except: return False

    def process_gui_updates(self, dt):
        while not self.gui_queue.empty():
            func, args = self.gui_queue.get()
            func(*args)

    def show_popup(self, title, text):
        content = BoxLayout(orientation='vertical', padding=dp(10))
        content.add_widget(Label(text=text))
        btn = Button(text="Close", size_hint_y=None, height=dp(40))
        content.add_widget(btn)
        popup = Popup(title=title, content=content, size_hint=(0.8, 0.4))
        btn.bind(on_release=popup.dismiss)
        popup.open()

if __name__ == '__main__':
    VenexC2Mobile().run()
# lon g term



# import base64
# import hashlib
# import socket
# import threading
# import time
# import os
# import re
# import ipaddress
# from datetime import datetime
# from queue import Queue

# from kivy.app import App
# from kivy.uix.boxlayout import BoxLayout
# from kivy.uix.gridlayout import GridLayout
# from kivy.uix.label import Label
# from kivy.uix.button import Button
# from kivy.uix.textinput import TextInput
# from kivy.uix.scrollview import ScrollView
# from kivy.uix.screenmanager import ScreenManager, Screen
# from kivy.uix.actionbar import ActionBar, ActionView, ActionPrevious, ActionButton
# from kivy.uix.popup import Popup
# from kivy.core.window import Window
# from kivy.clock import Clock
# from kivy.metrics import dp
# from kivy.graphics import Color, RoundedRectangle

# # --- Professional Styling ---
# ACCENT_BLUE = [0, 0.47, 0.83, 1]
# BG_DARK = [0.1, 0.1, 0.1, 1]
# CARD_DARK = [0.15, 0.15, 0.15, 1]
# TEXT_PRIMARY = [1, 1, 1, 1]
# TEXT_SECONDARY = [0.6, 0.6, 0.6, 1]
# SUCCESS_GREEN = [0.13, 0.87, 0.13, 1]
# DANGER_RED = [0.82, 0.2, 0.22, 1]
# WARNING_ORANGE = [1, 0.6, 0, 1]

# class StyledButton(Button):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.background_normal = ''
#         self.background_down = ''
#         self.background_color = [0, 0, 0, 0]
#         self.color = TEXT_PRIMARY
#         self.bold = True
#         self.font_size = '15sp'
#         self.size_hint_y = None
#         self.height = dp(48)
#         with self.canvas.before:
#             self.bg_color = Color(*ACCENT_BLUE)
#             self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(8)])
#         self.bind(pos=self.update_rect, size=self.update_rect)

#     def update_rect(self, instance, value):
#         self.rect.pos = instance.pos
#         self.rect.size = instance.size

# class DashboardScreen(Screen):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.layout = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(12))
        
#         # Connection Card
#         conn_card = BoxLayout(orientation='vertical', size_hint_y=None, height=dp(170), padding=dp(15), spacing=dp(8))
#         with conn_card.canvas.before:
#             Color(*CARD_DARK)
#             self.rect = RoundedRectangle(pos=conn_card.pos, size=conn_card.size, radius=[dp(12)])
#         conn_card.bind(pos=self.update_rect, size=self.update_rect)
        
#         ip_layout = BoxLayout(spacing=dp(8), size_hint_y=None, height=dp(42))
#         ip_layout.add_widget(Label(text="Server:", size_hint_x=0.25, color=TEXT_PRIMARY, bold=True))
#         self.ip_input = TextInput(text="127.0.0.1", multiline=False, background_color=[0.2, 0.2, 0.2, 1], foreground_color=TEXT_PRIMARY, padding=[dp(10), dp(10)])
#         ip_layout.add_widget(self.ip_input)
        
#         port_layout = BoxLayout(spacing=dp(8), size_hint_y=None, height=dp(42))
#         port_layout.add_widget(Label(text="Port:", size_hint_x=0.25, color=TEXT_PRIMARY, bold=True))
#         self.port_input = TextInput(text="7777", multiline=False, background_color=[0.2, 0.2, 0.2, 1], foreground_color=TEXT_PRIMARY, padding=[dp(10), dp(10)])
#         port_layout.add_widget(self.port_input)
        
#         self.connect_btn = StyledButton(text="CONNECT SERVER")
        
#         conn_card.add_widget(ip_layout)
#         conn_card.add_widget(port_layout)
#         conn_card.add_widget(self.connect_btn)
#         self.layout.add_widget(conn_card)
        
#         # Targets List
#         self.layout.add_widget(Label(text="ACTIVE TARGETS", size_hint_y=None, height=dp(25), bold=True, halign='left', color=TEXT_SECONDARY, font_size='12sp'))
#         self.target_scroll = ScrollView(size_hint_y=0.3)
#         self.target_list = GridLayout(cols=1, spacing=dp(5), size_hint_y=None)
#         self.target_list.bind(minimum_height=self.target_list.setter('height'))
#         self.target_scroll.add_widget(self.target_list)
#         self.layout.add_widget(self.target_scroll)
        
#         # Terminal Output
#         self.layout.add_widget(Label(text="TERMINAL OUTPUT", size_hint_y=None, height=dp(25), bold=True, halign='left', color=TEXT_SECONDARY, font_size='12sp'))
#         self.output_scroll = ScrollView()
#         self.output_text = Label(text="", size_hint_y=None, color=SUCCESS_GREEN, font_name='Roboto', font_size='13sp', halign='left', valign='top')
#         self.output_text.bind(size=self.output_text.setter('text_size'))
#         self.output_scroll.add_widget(self.output_text)
        
#         with self.output_scroll.canvas.before:
#             Color(0.05, 0.05, 0.05, 1)
#             self.out_rect = RoundedRectangle(pos=self.output_scroll.pos, size=self.output_scroll.size, radius=[dp(10)])
#         self.output_scroll.bind(pos=self.update_out_rect, size=self.update_out_rect)
#         self.layout.add_widget(self.output_scroll)
        
#         # Command Bar
#         self.mode_label = Label(text="MODE: C2 SERVER", size_hint_y=None, height=dp(20), font_size='11sp', color=TEXT_SECONDARY)
#         self.layout.add_widget(self.mode_label)
        
#         cmd_layout = BoxLayout(size_hint_y=None, height=dp(55), spacing=dp(8))
#         self.cmd_input = TextInput(hint_text="Type command...", multiline=False, background_color=[0.18, 0.18, 0.18, 1], foreground_color=TEXT_PRIMARY, padding=[dp(12), dp(12)])
#         self.send_btn = StyledButton(text="EXEC", size_hint_x=0.25)
#         cmd_layout.add_widget(self.cmd_input)
#         cmd_layout.add_widget(self.send_btn)
#         self.layout.add_widget(cmd_layout)
        
#         self.add_widget(self.layout)

#     def update_rect(self, instance, value):
#         self.rect.pos = instance.pos
#         self.rect.size = instance.size

#     def update_out_rect(self, instance, value):
#         self.out_rect.pos = instance.pos
#         self.out_rect.size = instance.size
#         self.output_text.height = max(self.output_scroll.height, self.output_text.texture_size[1])

# class ContentScreen(Screen):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         self.layout = BoxLayout(orientation='vertical', padding=dp(12), spacing=dp(12))
        
#         header = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10))
#         header.add_widget(Label(text="Content Box", font_size='22sp', bold=True, color=ACCENT_BLUE))
#         self.refresh_btn = StyledButton(text="Refresh", size_hint_x=0.3)
#         header.add_widget(self.refresh_btn)
#         self.layout.add_widget(header)
        
#         self.path_label = Label(text="", size_hint_y=None, height=dp(30), color=TEXT_SECONDARY, halign='left', font_size='12sp')
#         self.layout.add_widget(self.path_label)
        
#         self.file_scroll = ScrollView()
#         self.file_list = GridLayout(cols=1, spacing=dp(5), size_hint_y=None)
#         self.file_list.bind(minimum_height=self.file_list.setter('height'))
#         self.file_scroll.add_widget(self.file_list)
#         self.layout.add_widget(self.file_scroll)
        
#         self.add_widget(self.layout)

# class SettingsScreen(Screen):
#     def __init__(self, **kwargs):
#         super().__init__(**kwargs)
#         layout = BoxLayout(orientation='vertical', padding=dp(20), spacing=dp(15))
#         layout.add_widget(Label(text="Settings", font_size='24sp', bold=True, size_hint_y=None, height=dp(60), color=ACCENT_BLUE))
        
#         layout.add_widget(Label(text="Auth Token:", size_hint_y=None, height=dp(30), halign='left', bold=True))
#         self.token_input = TextInput(text="your token", multiline=False, size_hint_y=None, height=dp(48), background_color=[0.18, 0.18, 0.18, 1], foreground_color=TEXT_PRIMARY, padding=[dp(12), dp(12)], password=True)
#         layout.add_widget(self.token_input)
        
#         layout.add_widget(Label(text="System Logs", font_size='18sp', bold=True, size_hint_y=None, height=dp(40), color=TEXT_SECONDARY))
#         self.log_scroll = ScrollView()
#         self.log_text = Label(text="", size_hint_y=None, color=TEXT_SECONDARY, font_size='12sp', halign='left', valign='top')
#         self.log_text.bind(size=self.log_text.setter('text_size'))
#         self.log_scroll.add_widget(self.log_text)
#         layout.add_widget(self.log_scroll)
        
#         self.add_widget(layout)

# class VenexC2Mobile(App):
#     def build(self):
#         Window.clearcolor = BG_DARK
#         self.sm = ScreenManager()
        
#         # Logic Variables
#         self.connected = False
#         self.socket = None
#         self.targets = {}
#         self.target_lock = threading.Lock()
#         self.interacting_with_target = None
#         self.gui_queue = Queue()
#         self.content_box_path = os.path.join(os.getcwd(), "content_box")
#         self.current_path = self.content_box_path
#         if not os.path.exists(self.content_box_path): os.makedirs(self.content_box_path)
        
#         self.global_commands = ["AUTH:STOP_HTTP", "AUTH:START_HTTP", "help", "targets", "clear", "exit"]
#         self.target_commands = ["tm powershell -command \"\"", "$sysinfo", "rmf", "back", "screenshot", "shell", "pwd", "ls"]
#         self.current_commands = self.global_commands
        
#         # Screens
#         self.dash = DashboardScreen(name='dashboard')
#         self.content = ContentScreen(name='content')
#         self.settings = SettingsScreen(name='settings')
        
#         self.sm.add_widget(self.dash)
#         self.sm.add_widget(self.content)
#         self.sm.add_widget(self.settings)
        
#         # Main Layout
#         root = BoxLayout(orientation='vertical')
        
#         # Action Bar
#         ab = ActionBar(pos_hint={'top': 1})
#         av = ActionView()
#         ap = ActionPrevious(title='Venex C2', with_previous=False, color=ACCENT_BLUE)
#         av.add_widget(ap)
#         av.add_widget(ActionButton(text='Dash', on_release=lambda x: self.switch_screen('dashboard')))
#         av.add_widget(ActionButton(text='Files', on_release=lambda x: self.switch_screen('content')))
#         av.add_widget(ActionButton(text='Settings', on_release=lambda x: self.switch_screen('settings')))
#         ab.add_widget(av)
        
#         root.add_widget(ab)
#         root.add_widget(self.sm)
        
#         # Bindings
#         self.dash.connect_btn.bind(on_release=self.toggle_connection)
#         self.dash.send_btn.bind(on_release=self.send_command)
#         self.content.refresh_btn.bind(on_release=lambda x: self.refresh_file_explorer())
        
#         # Start GUI update loop
#         Clock.schedule_interval(self.process_gui_updates, 0.1)
#         self.refresh_file_explorer()
        
#         return root

#     def switch_screen(self, name):
#         self.sm.current = name

#     def toggle_connection(self, instance):
#         if not self.connected: self.connect_to_server()
#         else: self.disconnect_from_server()

#     def connect_to_server(self):
#         host = self.dash.ip_input.text
#         try:
#             port = int(self.dash.port_input.text)
#             ip = host if self.is_ip(host) else socket.gethostbyname(host)
#             self.log_message(f"Connecting to {ip}...")
#             self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#             self.socket.settimeout(5)
#             self.socket.connect((ip, port))
#             self.connected = True
            
#             sha256_token = hashlib.sha256(self.settings.token_input.text.encode('utf-8')).hexdigest()
#             self.socket.sendall(f"TOKEN:{sha256_token}".encode("utf-8"))
            
#             self.dash.connect_btn.text = "DISCONNECT"
#             self.dash.connect_btn.bg_color.rgba = DANGER_RED
            
#             threading.Thread(target=self.receive_messages, daemon=True).start()
#             self.log_message(f"Authenticated successfully")
#         except Exception as e:
#             self.show_popup("Error", f"Connection failed: {e}")

#     def disconnect_from_server(self):
#         self.connected = False
#         if self.socket: self.socket.close()
#         self.dash.connect_btn.text = "CONNECT SERVER"
#         self.dash.connect_btn.bg_color.rgba = ACCENT_BLUE
#         self.log_message("Disconnected")
#         self.switch_to_normal_mode()
#         with self.target_lock:
#             self.targets.clear()
#             self.gui_queue.put((self.clear_target_list, ()))

#     def send_command(self, instance=None):
#         cmd = self.dash.cmd_input.text.strip()
#         if not cmd or not self.connected: return
#         try:
#             f_cmd = f"TARGET:{self.interacting_with_target}:{cmd}" if self.interacting_with_target else cmd
#             self.socket.sendall((f_cmd + "\n").encode())
#             self.dash.cmd_input.text = ""
#             self.output_data(f"> {cmd}")
#         except Exception as e: self.log_message(f"Send error: {e}")

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
#         msg = message.decode(errors='ignore')
#         if msg.startswith("TARGET:"):
#             self.add_target(msg[7:].strip())
#         elif msg.startswith("/DATA:"):
#             self.gui_queue.put((self.output_data, (f"← {msg[6:]}",)))
#         else:
#             self.gui_queue.put((self.output_data, (f"-> {msg}",)))

#     def add_target(self, tid):
#         with self.target_lock:
#             if tid not in self.targets:
#                 self.targets[tid] = {"last": datetime.now(), "status": "Active"}
#                 self.gui_queue.put((self.update_target_ui, ()))
#             else:
#                 self.targets[tid]["last"] = datetime.now()

#     def update_target_ui(self):
#         self.dash.target_list.clear_widgets()
#         for tid in self.targets:
#             btn = Button(text=f"INTERACT: {tid}", size_hint_y=None, height=dp(45), background_color=[0.2, 0.2, 0.2, 1])
#             btn.bind(on_release=lambda x, t=tid: self.interact_with_target(t))
#             self.dash.target_list.add_widget(btn)

#     def interact_with_target(self, tid):
#         self.interacting_with_target = tid
#         self.dash.mode_label.text = f"MODE: INTERACTING WITH {tid}"
#         self.dash.mode_label.color = ACCENT_BLUE
#         self.log_message(f"Interacting with {tid}")
#         self.current_commands = self.target_commands
#         self.switch_screen('dashboard')

#     def switch_to_normal_mode(self):
#         self.interacting_with_target = None
#         self.dash.mode_label.text = "MODE: C2 SERVER"
#         self.dash.mode_label.color = TEXT_SECONDARY

#     def log_message(self, msg):
#         ts = datetime.now().strftime("%H:%M:%S")
#         self.settings.log_text.text += f"[{ts}] {msg}\n"
#         self.settings.log_text.height = max(self.settings.log_scroll.height, self.settings.log_text.texture_size[1])

#     def output_data(self, msg):
#         self.dash.output_text.text += f"{msg}\n"
#         self.dash.output_text.height = max(self.dash.output_scroll.height, self.dash.output_text.texture_size[1])
#         self.dash.output_scroll.scroll_y = 0

#     def clear_target_list(self):
#         self.dash.target_list.clear_widgets()

#     def refresh_file_explorer(self):
#         self.content.file_list.clear_widgets()
#         self.content.path_label.text = self.current_path
#         try:
#             for item in os.listdir(self.current_path):
#                 prefix = "📁 " if os.path.isdir(os.path.join(self.current_path, item)) else "📄 "
#                 btn = Button(text=f"{prefix}{item}", size_hint_y=None, height=dp(45), background_color=[0.15, 0.15, 0.15, 1])
#                 self.content.file_list.add_widget(btn)
#         except: pass

#     def is_ip(self, s):
#         try:
#             ipaddress.ip_address(s)
#             return True
#         except: return False

#     def process_gui_updates(self, dt):
#         while not self.gui_queue.empty():
#             func, args = self.gui_queue.get()
#             func(*args)

#     def show_popup(self, title, text):
#         content = BoxLayout(orientation='vertical', padding=dp(10))
#         content.add_widget(Label(text=text))
#         btn = Button(text="Close", size_hint_y=None, height=dp(40))
#         content.add_widget(btn)
#         popup = Popup(title=title, content=content, size_hint=(0.8, 0.4))
#         btn.bind(on_release=popup.dismiss)
#         popup.open()

# if __name__ == '__main__':
#     VenexC2Mobile().run()
