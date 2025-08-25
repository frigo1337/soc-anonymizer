#!/usr/bin/env python3

import re
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
from tkinter import simpledialog

class Anonymizer:
    def __init__(self):
        self.value_to_tag = {
            'ip': {}, 'email': {}, 'user': {},
            'host': {}, 'company': {}, 'custom': {}
        }
        self.tag_to_value = {}
        self.counters = {'ip': 0, 'email': 0, 'user': 0, 'host': 0}
        self.company_literal = None
        self.host_prefix_regex = r"(?:win|srv)"

        # Extract just the username from common home-like paths
        self.path_patterns = [
            # C:\Users\Alice  -> capture "Alice"
            re.compile(r'(?i)\b([A-Za-z]:\\Users\\)([^\\\r\n]+)'),
            # C:\Documents and Settings\Alice -> capture "Alice"
            re.compile(r'(?i)\b([A-Za-z]:\\Documents and Settings\\)([^\\\r\n]+)'),
            # \\server\share\Users\Alice -> capture "Alice"
            re.compile(r'(?i)(\\\\[^\\\r\n]+\\[^\\\r\n]+\\Users\\)([^\\\r\n]+)'),
            # /Users/alice or /home/alice -> capture "alice"
            re.compile(r'(?i)((?:/Users/|/home/))([^/\r\n]+)'),
        ]

        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            'ip': re.compile(
                r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}'
                r'(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
            ),
            'ipv6': re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'),
            'host': None,
            'company': None,
        }
        self._compile_host_pattern()

    def _compile_host_pattern(self):
        if self.host_prefix_regex:
            literal_prefix = re.escape(self.host_prefix_regex.strip())
            # Treat input as a literal prefix, not a regex.
            self.patterns['host'] = re.compile(
                rf'\b{literal_prefix}[A-Za-z0-9-]+\b', re.IGNORECASE
            )
        else:
            self.patterns['host'] = None

    def set_company(self, company_str: str):
        self.company_literal = (company_str or '').strip() or None
        self.patterns['company'] = (
            re.compile(re.escape(self.company_literal), re.IGNORECASE)
            if self.company_literal else None
        )

    def set_host_prefix_literal(self, prefix_literal: str):
        prefix_literal = (prefix_literal or '').strip()
        if not prefix_literal:
            raise ValueError("Host prefix cannot be empty.")
        self.host_prefix_regex = prefix_literal
        self._compile_host_pattern()

    def reset(self):
        self.value_to_tag = {
            'ip': {}, 'email': {}, 'user': {},
            'host': {}, 'company': {}, 'custom': {}
        }
        self.tag_to_value = {}
        self.counters = {'ip': 0, 'email': 0, 'user': 0, 'host': 0}

    def _next_tag(self, etype: str) -> str:
        if etype == 'company':
            return "{company}"
        self.counters[etype] += 1
        return f"{{{etype}{self.counters[etype]}}}"

    def _canonical_key(self, etype: str, original: str) -> str:
        if etype in ('email', 'host') or (etype == 'user' and '@' in original):
            return original.lower()
        return original

    def _assign_tag(self, etype: str, original: str) -> str:
        canon = self._canonical_key(etype, original)
        if canon in self.value_to_tag[etype]:
            return self.value_to_tag[etype][canon]
        tag = self._next_tag('company' if etype == 'company' else etype)
        self.value_to_tag[etype][canon] = tag
        if tag not in self.tag_to_value:
            self.tag_to_value[tag] = original
        return tag

    def _find_all(self, text: str, needle: str):
        # Case-sensitive literal search; yields (start, end) for all non-overlapping matches
        start = 0
        nlen = len(needle)
        while True:
            i = text.find(needle, start)
            if i == -1:
                break
            yield i, i + nlen
            start = i + nlen

    def anonymize(self, text: str) -> str:
        replacements = []

        # 1) Custom literals (persist across runs)
        # If user saved: literal -> {tag}, apply everywhere in source
        for literal, tag in self.value_to_tag['custom'].items():
            for s, e in self._find_all(text, literal):
                replacements.append((s, e, tag))

        # 2) Paths (only replace the username portion)
        for pat in self.path_patterns:
            for m in pat.finditer(text):
                user_part = m.group(2)
                tag = self._assign_tag('user', user_part)
                replacements.append((m.start(2), m.end(2), tag))

        # 3) Emails, IPs, IPv6
        for m in self.patterns['email'].finditer(text):
            tag = self._assign_tag('email', m.group(0))
            replacements.append((m.start(), m.end(), tag))
        for m in self.patterns['ip'].finditer(text):
            tag = self._assign_tag('ip', m.group(0))
            replacements.append((m.start(), m.end(), tag))
        for m in self.patterns['ipv6'].finditer(text):
            tag = self._assign_tag('ip', m.group(0))
            replacements.append((m.start(), m.end(), tag))

        # 4) Hosts
        if self.patterns['host']:
            for m in self.patterns['host'].finditer(text):
                tag = self._assign_tag('host', m.group(0))
                replacements.append((m.start(), m.end(), tag))

        # 5) Company literal
        if self.patterns['company']:
            for m in self.patterns['company'].finditer(text):
                tag = self._assign_tag('company', m.group(0))
                replacements.append((m.start(), m.end(), tag))

        # Resolve overlaps by working right-to-left
        replacements.sort(key=lambda t: t[0], reverse=True)
        result_parts, last_index = [], len(text)
        for start, end, rep in replacements:
            if end > last_index:
                continue
            result_parts.append(text[end:last_index])
            result_parts.append(rep)
            last_index = start
        result_parts.append(text[:last_index])
        return ''.join(reversed(result_parts))

    def deanonymize(self, text: str) -> str:
        tag_pat = re.compile(r'\{[A-Za-z][A-Za-z0-9_-]*[0-9]*\}')
        return tag_pat.sub(lambda m: self.tag_to_value.get(m.group(0), m.group(0)), text)

    def _sanitize_tag_name(self, tag_name: str) -> str:
        # Strip braces/spaces and enforce safe charset
        t = (tag_name or '').strip()
        if t.startswith('{') and t.endswith('}'):
            t = t[1:-1].strip()
        if not t:
            raise ValueError("Tag name cannot be empty.")
        if not re.match(r'^[A-Za-z][A-Za-z0-9_-]*$', t):
            raise ValueError("Tag name must start with a letter and contain only letters, digits, '_' or '-'.")
        # Avoid collisions with built-in auto tags like email1/ip1/host1
        if re.match(r'^(email|ip|host|user)\d+$', t, re.IGNORECASE) or t.lower() == 'company':
            raise ValueError("Tag name collides with built-in tags. Choose a different name.")
        return t

    def custom_anonymize(self, text: str, find_str: str, tag_name: str) -> str:
        literal = (find_str or '')
        if not literal:
            raise ValueError("Literal text to find cannot be empty.")

        clean = self._sanitize_tag_name(tag_name)
        tag = f'{{{clean}}}'

        # If this literal already has a tag, reuse it; otherwise set mapping
        existing = self.value_to_tag['custom'].get(literal)
        if existing and existing != tag:
            # Same literal, different requested tag — honor the newest, update both maps
            old_tag = existing
            if old_tag in self.tag_to_value:
                del self.tag_to_value[old_tag]
        self.value_to_tag['custom'][literal] = tag
        self.tag_to_value[tag] = literal

        # If the literal isn't present, still run the pipeline but don't inject tag anywhere
        if text.find(literal) == -1:
            return self.anonymize(text)

        # Re-run full pipeline on source; custom mapping will be applied within anonymize()
        return self.anonymize(text)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SOC Incident Anonymizer")
        self.geometry("1100x650")
        self.an = Anonymizer()
        
        # Theme state
        self.dark_mode = False
        self.matrix_mode = False
        
        # Super omega secret key sequence for 1337 mode
        self.key_sequence = []
        self.secret_combo = ['Control_L', 'Shift_L', '1', '3', '3', '7']
        
        # Matrix animation variables
        self.matrix_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+-=[]{}|;':\",./<>?"
        self.matrix_animation_id = None
        
        # Color schemes
        self.light_colors = {
            'bg': '#ffffff',
            'fg': '#000000',
            'text_bg': '#ffffff',
            'text_fg': '#000000',
            'button_bg': '#f0f0f0',
            'button_fg': '#000000',
            'select_bg': '#0078d4',
            'select_fg': '#ffffff'
        }
        
        self.dark_colors = {
            'bg': '#2d2d2d',
            'fg': '#ffffff',
            'text_bg': '#1e1e1e',
            'text_fg': '#ffffff',
            'button_bg': '#404040',
            'button_fg': '#ffffff',
            'select_bg': '#0078d4',
            'select_fg': '#ffffff'
        }
        
        self.matrix_colors = {
            'bg': '#000000',
            'fg': '#00ff00',
            'text_bg': '#001100',  # Very dark green instead of pure black
            'text_fg': '#00ff00',
            'button_bg': '#001100',
            'button_fg': '#00ff00',
            'select_bg': '#003300',
            'select_fg': '#00ff00'
        }
        
        self._build_ui()
        self.apply_theme()
        
        # Bind key events for secret combo
        self.bind_all('<KeyPress>', self.on_key_press)
        self.focus_set()  # Make sure window can receive key events

    def _build_ui(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        btn_new = ttk.Button(toolbar, text="NEW Session", command=self.on_new)
        btn_new.pack(side=tk.LEFT, padx=4)
        btn_set_company = ttk.Button(toolbar, text="Set Company", command=self.on_set_company)
        btn_set_company.pack(side=tk.LEFT, padx=4)
        btn_set_host = ttk.Button(toolbar, text="Host Prefix", command=self.on_set_host_prefix)
        btn_set_host.pack(side=tk.LEFT, padx=4)
        btn_custom = ttk.Button(toolbar, text="Custom Anonymize", command=self.on_custom)
        btn_custom.pack(side=tk.LEFT, padx=4)
        
        # Dark mode toggle button
        if self.matrix_mode:
            self.btn_dark_mode = ttk.Button(toolbar, text="🔋 1337 MODE", command=self.toggle_dark_mode)
        else:
            self.btn_dark_mode = ttk.Button(toolbar, text="🌙 Dark Mode", command=self.toggle_dark_mode)
        self.btn_dark_mode.pack(side=tk.RIGHT, padx=4)

        panes = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        left = ttk.Frame(panes)
        right = ttk.Frame(panes)
        panes.add(left, weight=1)
        panes.add(right, weight=1)

        self.input_text = ScrolledText(left, wrap=tk.WORD, font=("Consolas", 11))
        self.input_text.pack(fill=tk.BOTH, expand=True)
        self.output_text = ScrolledText(right, wrap=tk.WORD, font=("Consolas", 11), state=tk.NORMAL)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # Matrix background canvas (initially hidden)
        self.matrix_canvas = tk.Canvas(self, bg='#000000', highlightthickness=0)
        self.matrix_drops = []
        
        # Store references to text widgets for matrix effects
        self.text_widgets = [self.input_text, self.output_text]
        
        # Ensure Ctrl+A works on all platforms
        self.input_text.bind('<Control-a>', self._select_all)
        self.output_text.bind('<Control-a>', self._select_all)

        actions = ttk.Frame(self)
        actions.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=6)
        btn_anonymize = ttk.Button(actions, text="Anonymize →", command=self.on_anonymize)
        btn_anonymize.pack(side=tk.LEFT, padx=4)
        btn_deanonymize = ttk.Button(actions, text="← De-anonymize", command=self.on_deanonymize)
        btn_deanonymize.pack(side=tk.LEFT, padx=4)

    # def toggle_dark_mode(self):
    #     self.dark_mode = not self.dark_mode
    #     self.apply_theme()

    def on_key_press(self, event):
        """Handle key presses for secret combo detection"""
        key = event.keysym
        
        # Add key to sequence
        self.key_sequence.append(key)
        
        # Keep only last 6 keys (length of our secret combo)
        if len(self.key_sequence) > 6:
            self.key_sequence.pop(0)
        
        # Check if we have the secret combo
        if self.key_sequence == self.secret_combo:
            self.activate_matrix_mode()
            self.key_sequence = []  # Reset sequence
    
    def activate_matrix_mode(self):
        """Activate the secret 1337 Matrix mode"""
        self.matrix_mode = True
        self.dark_mode = False  # Override dark mode
        self.title("SOC Incident Anonymizer - 1337 M4TR1X M0D3")
        self.apply_theme()
        self.start_matrix_animation()
        
        # Show a brief message
        messagebox.showinfo("1337 MODE ACTIVATED", "ALL YOUR BASE ARE BELONG TO US")

    def toggle_dark_mode(self):
        if self.matrix_mode:
            # Exit matrix mode
            self.matrix_mode = False
            self.stop_matrix_animation()
            self.title("SOC Incident Anonymizer")
        else:
            # Normal dark/light toggle
            self.dark_mode = not self.dark_mode
        self.apply_theme()

    def start_matrix_animation(self):
        """Start the matrix rain animation"""
        if self.matrix_animation_id:
            self.after_cancel(self.matrix_animation_id)
        
        # Don't use background canvas - just add subtle effects to text widgets
        self.add_matrix_text_effects()

    def add_matrix_text_effects(self):
        """Add Matrix-style visual effects to text widgets"""
        # Add some Matrix-style placeholder text with blinking effect
        if not hasattr(self, 'matrix_blink_state'):
            self.matrix_blink_state = True
        
        # Add Matrix-style border effect by configuring relief
        for widget in self.text_widgets:
            widget.configure(
                relief='ridge',
                borderwidth=2,
                highlightbackground='#00ff00',
                highlightcolor='#00ff00',
                highlightthickness=1
            )
        
        # Start subtle blinking animation for cursor
        self.animate_matrix_cursor()
    
    def animate_matrix_cursor(self):
        """Animate Matrix-style cursor effects"""
        if not self.matrix_mode:
            return
            
        # Toggle cursor visibility for blinking effect
        self.matrix_blink_state = not self.matrix_blink_state
        cursor_color = '#00ff00' if self.matrix_blink_state else '#003300'
        
        for widget in self.text_widgets:
            widget.configure(insertbackground=cursor_color)
        
        # Schedule next blink
        self.matrix_animation_id = self.after(500, self.animate_matrix_cursor)

    def animate_matrix(self):
        """Simplified matrix animation - removed complex canvas animation"""
        # This method is now simplified - the complex canvas animation was causing issues
        pass

    def stop_matrix_animation(self):
        """Stop the matrix animation"""
        if self.matrix_animation_id:
            self.after_cancel(self.matrix_animation_id)
            self.matrix_animation_id = None
        
        # Reset text widget styling
        for widget in self.text_widgets:
            widget.configure(
                relief='sunken',
                borderwidth=1,
                highlightbackground='SystemButtonFace',
                highlightcolor='SystemButtonFace',
                highlightthickness=1
            )

    def apply_theme(self):
        if self.matrix_mode:
            colors = self.matrix_colors
        else:
            colors = self.dark_colors if self.dark_mode else self.light_colors
        
        # Update main window
        self.configure(bg=colors['bg'])
        
        # Update text widgets
        for widget in self.text_widgets:
            widget.configure(
                bg=colors['text_bg'],
                fg=colors['text_fg'],
                insertbackground=colors['text_fg'],
                selectbackground=colors['select_bg'],
                selectforeground=colors['select_fg']
            )
            
            # Matrix mode special effects
            if self.matrix_mode:
                widget.configure(
                    font=("Courier", 11, "bold"),
                    cursor="dotbox"  # Matrix-style cursor
                )
            else:
                widget.configure(
                    font=("Consolas", 11),
                    cursor="xterm"  # Normal cursor
                )
        
        # Update button text and icon
        if self.matrix_mode:
            self.btn_dark_mode.configure(text="🔌 EXIT M4TR1X")
        elif self.dark_mode:
            self.btn_dark_mode.configure(text="☀️ Light Mode")
        else:
            self.btn_dark_mode.configure(text="🌙 Dark Mode")
        
        # Configure ttk style for buttons and frames
        style = ttk.Style()
        
        if self.matrix_mode:
            # Matrix theme configuration
            style.theme_use('clam')
            
            style.configure('TFrame', background=colors['bg'])
            style.configure('TPanedwindow', background=colors['bg'])
            
            style.configure('TButton',
                          background=colors['button_bg'],
                          foreground=colors['button_fg'],
                          bordercolor='#00ff00',
                          lightcolor=colors['button_bg'],
                          darkcolor=colors['button_bg'],
                          relief='ridge')
            
            style.map('TButton',
                     background=[('active', '#003300'),
                               ('pressed', '#005500')],
                     foreground=[('active', '#00ff00')])
                     
        elif self.dark_mode:
            # Dark theme configuration
            style.theme_use('clam')  # Use clam theme as base for better customization
            
            # Configure frame colors
            style.configure('TFrame', background=colors['bg'])
            style.configure('TPanedwindow', background=colors['bg'])
            
            # Configure button colors
            style.configure('TButton',
                          background=colors['button_bg'],
                          foreground=colors['button_fg'],
                          bordercolor=colors['button_bg'],
                          lightcolor=colors['button_bg'],
                          darkcolor=colors['button_bg'])
            
            style.map('TButton',
                     background=[('active', '#505050'),
                               ('pressed', '#606060')])
        else:
            # Light theme - use default
            try:
                style.theme_use('winnative')  # Windows native theme
            except:
                style.theme_use('default')    # Fallback to default

    def on_new(self):
        if messagebox.askyesno("Confirm", "Start new session and clear mapping and text?"):
            self.an.reset()
            self.input_text.delete("1.0", tk.END)
            self.output_text.delete("1.0", tk.END)

    def on_set_company(self):
        value = simpledialog.askstring("Company", "Enter company name to anonymize (blank to clear):", parent=self)
        if value is None:
            return
        self.an.set_company(value)
        src = self.input_text.get("1.0", tk.END)
        out = self.an.anonymize(src)
        self._set_output(out)

    def on_set_host_prefix(self):
        value = simpledialog.askstring("Host Prefix", "Enter host prefix (e.g., DESKTOP-):", parent=self)
        if value is None:
            return
        try:
            self.an.set_host_prefix_literal(value)
            src = self.input_text.get("1.0", tk.END)
            out = self.an.anonymize(src)
            self._set_output(out)
        except re.error as e:
            messagebox.showerror("Regex Error", f"Invalid prefix: {e}")
        except ValueError as e:
            messagebox.showerror("Host Prefix Error", str(e))

    def on_custom(self):
        find_str = simpledialog.askstring("Custom Anonymize", "Literal text to find:", parent=self)
        if find_str is None or find_str == "":
            return
        tag_name = simpledialog.askstring("Custom Anonymize", "Tag name (e.g., vlan1):", parent=self)
        if tag_name is None or tag_name == "":
            return
        try:
            src = self.input_text.get("1.0", tk.END)
            out = self.an.custom_anonymize(src, find_str, tag_name)
            self._set_output(out)
        except Exception as e:
            messagebox.showerror("Custom Anonymize Error", str(e))

    def on_anonymize(self):
        src = self.input_text.get("1.0", tk.END)
        out = self.an.anonymize(src)
        self._set_output(out)

    def on_deanonymize(self):
        src = self.input_text.get("1.0", tk.END)
        out = self.an.deanonymize(src)
        self._set_output(out)

    def _set_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state=tk.NORMAL)
    
    def _select_all(self, event):
        """Handle Ctrl+A to select all text in text widgets"""
        event.widget.tag_add(tk.SEL, "1.0", tk.END)
        event.widget.mark_set(tk.INSERT, "1.0")
        event.widget.see(tk.INSERT)
        return 'break'  # Prevent default handling


if __name__ == "__main__":
    app = App()
    app.mainloop()