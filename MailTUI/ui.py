# ui.py

import urwid
import html2text
import os
import json
import glob
from mail_api import search_messages, get_message_headers, get_message_preview, save_eml, unescape_preview, get_html_body
from theme_loader import get_available_themes, DEFAULT_THEME, load_theme_palette
from secure_store import decrypt_to_memory

def safe_str(text):
    return ''.join(
        c if c in '\n\t' or 0x20 <= ord(c) < 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD
        else '?' for c in text
    )

THEME_TAGS = ["header", "reversed", "focus", "preview", "success", "error"]

AVAILABLE_COLORS = [
    "default", "black", "dark red", "dark green", "brown", "dark blue",
    "dark magenta", "dark cyan", "light gray", "dark gray", "light red",
    "light green", "yellow", "light blue", "light magenta", "light cyan", "white"
]

from email_clients import EmailClient

class SelectableText(urwid.Text):
    def selectable(self):
        return True

    def keypress(self, size, key):
        return key

class EmailApp:

    preview_source = 'gmail'  # or 'local'

    def _write_and_apply_theme(self, theme_name, path):
        try:
            with open(path, "w") as f:
                json.dump(self.new_theme, f, indent=2)
            self.preview_lines.clear()

            new_palette = load_theme_palette(theme_name)
            print("[DEBUG] Registered palette:")
            for tag, fg, bg in new_palette:
                print(f"  {tag:<10} → fg: {fg:<12} bg: {bg}")
            self.loop.screen.register_palette(new_palette)
            self.loop.draw_screen()
            self.prompt.set_text(f"✅ Theme '{theme_name}.json' saved and applied!")
        except Exception as e:
            self.prompt.set_text(f"❌ Failed to save/apply theme: {e}")

        self.loop.widget = self.main_layout

    def save_custom_theme(self):
        theme_name = self.theme_name_edit.edit_text.strip()
        if not theme_name:
            self.prompt.set_text("⚠ Theme name cannot be empty.")
            return

        path = os.path.join("themes", f"{theme_name}.json")

        # If the theme file already exists, confirm overwrite
        if os.path.exists(path):
            def on_keypress(key):
                if key.lower() == 'y':
                    self.loop.widget = self.main_layout
                    self._write_and_apply_theme(theme_name, path)
                elif key.lower() == 'n':
                    self.prompt.set_text("ℹ Theme not saved.")
                    self.loop.widget = self.main_layout

            confirm_prompt = urwid.Text(f"⚠ Theme '{theme_name}' already exists. Overwrite? (y/n)")
            self.loop.widget = urwid.Overlay(
                urwid.Filler(confirm_prompt),
                self.main_layout,
                align='center', width=('relative', 60),
                valign='middle', height=('relative', 20)
            )
            self.loop.screen.clear()
            self.loop.unhandled_input = on_keypress
            return

        # No file exists, safe to save
        self._write_and_apply_theme(theme_name, path)

    def build_theme_overlay(self):
        self.new_theme = {}
        self.theme_edit_index = 0
        self.theme_name_edit = urwid.Edit("Theme name: ")

        def on_color_select(color, is_fg):
            if is_fg:
                self.selected_fg = color
            else:
                self.selected_bg = color

        def next_step(button=None):
            tag = THEME_TAGS[self.theme_edit_index]
            if not hasattr(self, 'selected_fg') or not hasattr(self, 'selected_bg'):
                self.prompt.set_text("⚠ Select both foreground and background.")
                return

            self.new_theme[tag] = [self.selected_fg, self.selected_bg]
            self.theme_edit_index += 1
            self.selected_fg = None
            self.selected_bg = None

            if self.theme_edit_index >= len(THEME_TAGS):
                self.save_custom_theme()
                return

            self.show_theme_step()

        self.prompt = urwid.Text("")
        self.next_button = urwid.Button("Next", on_press=next_step)
        self.cancel_button = urwid.Button("Cancel", on_press=lambda btn: self.close_overlay())
        self.theme_body = urwid.Pile([])
        self.show_theme_step()

    def show_theme_step(self):
        tag = THEME_TAGS[self.theme_edit_index]
        self.prompt.set_text(f"🎨 Editing tag: '{tag}'")

        fg_widgets = [urwid.Text("Select foreground color:")]
        bg_widgets = [urwid.Text("Select background color:")]

        def on_color_select(color, is_fg):
            if is_fg:
                self.selected_fg = color
                self.prompt.set_text(f"🎨 Selected foreground: {color}")
            else:
                self.selected_bg = color
                self.prompt.set_text(f"🎨 Selected background: {color}")

        for color in AVAILABLE_COLORS:
            fg_button = urwid.AttrMap(urwid.Button(color), 'preview', focus_map='focus')
            bg_button = urwid.AttrMap(urwid.Button(color), 'preview', focus_map='focus')

            urwid.connect_signal(fg_button.base_widget, 'click', lambda btn, c=color: on_color_select(c, True))
            urwid.connect_signal(bg_button.base_widget, 'click', lambda btn, c=color: on_color_select(c, False))

            fg_widgets.append(fg_button)
            bg_widgets.append(bg_button)

        fg_box = urwid.LineBox(urwid.ListBox(urwid.SimpleFocusListWalker(fg_widgets)))
        bg_box = urwid.LineBox(urwid.ListBox(urwid.SimpleFocusListWalker(bg_widgets)))

        prompt_line = urwid.AttrMap(
            urwid.LineBox(urwid.BoxAdapter(urwid.Filler(self.prompt), height=1)),
            'header'
        )

        columns = urwid.Columns([fg_box, bg_box])
        self.theme_body.contents = [
            (prompt_line, self.theme_body.options()),
            (columns, self.theme_body.options()),
            (urwid.LineBox(urwid.BoxAdapter(urwid.Filler(self.theme_name_edit), height=1)), self.theme_body.options()),
            (urwid.LineBox(urwid.BoxAdapter(urwid.Filler(self.next_button), height=1)), self.theme_body.options()),
            (urwid.LineBox(urwid.BoxAdapter(urwid.Filler(self.cancel_button), height=1)), self.theme_body.options()),        ]

        self.theme_overlay = urwid.Overlay(
            urwid.LineBox(self.theme_body),
            self.main_layout,
            align='center', width=('relative', 80),
            valign='middle', height=('relative', 80)
        )
        self.loop.widget = self.theme_overlay



    def choose_theme(self):
        def on_select(button, theme_name):
            raise urwid.ExitMainLoop(theme_name)

        themes = get_available_themes()
        theme_widgets = [urwid.AttrMap(urwid.Button(theme), None, focus_map='reversed') for theme in themes]
        walker = urwid.SimpleFocusListWalker(theme_widgets)
        theme_listbox = urwid.ListBox(walker)

        for i, theme in enumerate(themes):
            urwid.connect_signal(theme_widgets[i].base_widget, 'click', on_select, theme)

        overlay = urwid.Overlay(
            urwid.LineBox(theme_listbox),
            urwid.SolidFill(),  # background filler
            align='center', width=('relative', 50),
            valign='middle', height=('relative', 50)
        )

        loop = urwid.MainLoop(overlay, palette=[('reversed', 'standout', '')])
        try:
            loop.run()
        except urwid.ExitMainLoop as e:
            selected_theme = e.args[0] if e.args else DEFAULT_THEME
            return selected_theme


    def show_filter_overlay(self):
        self.overlay = urwid.Overlay(
            self.filter_box,
            self.main_layout,
            align='center', width=('relative', 30),
            valign='middle', height=('relative', 50)
        )
        self.loop.widget = self.overlay
        self.active_overlay = 'filter'

    def __init__(self, gmail_service):
        self.load_theme_palette = load_theme_palette
        self.service = gmail_service
        theme_name = self.choose_theme() or DEFAULT_THEME  # ask user once on startup
        palette = self.load_theme_palette(theme_name)
        print("[DEBUG] Registered palette:")
        for tag, fg, bg in palette:
            print(f"  {tag:<10} → fg: {fg:<12} bg: {bg}")
        self.query_edit = urwid.Edit("Search: ")
        self.email_list = urwid.SimpleFocusListWalker([])
        self.result_box = urwid.ListBox(self.email_list)
        self.preview_lines = urwid.SimpleFocusListWalker(
            [urwid.Text("Search to begin...")]
        )
        self.preview_listbox = urwid.ListBox(self.preview_lines)
        self.preview_box = urwid.Padding(self.preview_listbox, left=1, right=1)

        # Layout
        self.columns = urwid.Columns([
            ('weight', 1, self.result_box),
            ('weight', 2, urwid.LineBox(self.preview_box))  # wrap in LineBox for debugging
        ], dividechars=1)

        self.main_layout = urwid.Frame(
            header=urwid.AttrWrap(self.query_edit, 'header'),
            body=self.columns
        )



        self.page = 1
        self.next_page_token = None
        self.query = ""
        self.filters = ['from:', 'to:', 'cc:', 'bcc:', 'subject:', 'after:', 'before:', 'older:', 'newer:','older_than:', 'newer_than:', 'OR ', '{ }', 'AND', '-', 'AROUND', 'label:', 'category:', 'has:', 'list:', 'filename:', '" "', '( )', 'in:', 'is:', 'has:yellow-star', 'has:orange-star', 'has:red-star', 'has:purple-star', 'has:blue-star', 'has:green-star', 'has:red-bang', 'has:orange-guillemet', 'has:yellow-bang', 'has:green-check', 'has:blue-info', 'has:purple-question', 'deliveredto:', 'size:', 'larger:', 'smaller:', '+', 'rfc822msgid', 'has:userlabels', 'has:nouserlabels']

        filter_items = [urwid.Text("Select filter and press →")] + [
            urwid.AttrMap(SelectableText(f), None, focus_map='reversed') for f in self.filters
        ]
        self.filter_list = urwid.SimpleFocusListWalker(filter_items)
        self.filter_list.set_focus(1)
        self.filter_listbox = urwid.ListBox(self.filter_list)
        self.filter_box = urwid.LineBox(self.filter_listbox)
        self.overlay = None

        self.filter_help_lines = urwid.SimpleFocusListWalker([
            urwid.Text("📖 Help Menu - Gmail Filters (press the escape or q keys to return)", align='center'),
            urwid.Divider(),

            urwid.Text("🧑‍💻 People Filters"),
            urwid.Text("  from:me              → Emails sent by you"),
            urwid.Text("  from:amy@example.com → Emails from a specific sender"),
            urwid.Text("  to:john@example.com  → Emails sent to a specific recipient"),
            urwid.Text("  cc: / bcc:           → Emails where person was Cc’d/Bcc’d"),
            urwid.Text("  deliveredto:me@example.com → Delivered to a specific address"),
            urwid.Divider(),

            urwid.Text("📅 Date Filters"),
            urwid.Text("  after:YYYY/MM/DD     → Sent after a date"),
            urwid.Text("  before:YYYY/MM/DD    → Sent before a date"),
            urwid.Text("  older_than:1y        → Older than 1 year (d/m/y)"),
            urwid.Text("  newer_than:5d        → Newer than 5 days (d/m/y)"),
            urwid.Divider(),

            urwid.Text("📎 Attachment Filters"),
            urwid.Text("  has:attachment       → Has any attachment"),
            urwid.Text("  filename:pdf         → Attachment with specific name/type"),
            urwid.Text("  has:drive            → Includes Google Drive file"),
            urwid.Text("  has:document         → Includes Google Docs"),
            urwid.Text("  has:spreadsheet      → Includes Google Sheets"),
            urwid.Text("  has:presentation     → Includes Google Slides"),
            urwid.Text("  has:youtube          → Has a YouTube link"),
            urwid.Divider(),

            urwid.Text("🏷️ Label/Category Filters"),
            urwid.Text("  label:important      → Gmail label applied (also nested labels)"),
            urwid.Text("  category:promotions  → Inbox category (social/forums/etc)"),
            urwid.Text("  has:userlabels       → Has user-created label"),
            urwid.Text("  has:nouserlabels     → No user-created label"),
            urwid.Text("  list:list@domain.com → From mailing list"),
            urwid.Divider(),

            urwid.Text("⚙ Status & Location Filters"),
            urwid.Text("  is:read / is:unread  → Read/unread status"),
            urwid.Text("  is:important / is:starred → Important or starred"),
            urwid.Text("  is:muted             → Muted conversation"),
            urwid.Text("  in:anywhere          → Includes Trash/Spam"),
            urwid.Text("  in:inbox / in:sent   → Specific Gmail folder"),
            urwid.Text("  in:snoozed           → Snoozed messages"),
            urwid.Divider(),

            urwid.Text("🧠 Advanced Filters"),
            urwid.Text("  subject:meeting      → Word in subject line"),
            urwid.Text("  -unsubscribe         → Exclude a word"),
            urwid.Text("  +urgent              → Match exact word"),
            urwid.Text("  \"project alpha\"       → Match exact phrase"),
            urwid.Text("  AROUND 5             → Words near each other"),
            urwid.Text("  (from:amy subject:dinner) → Grouped terms"),
            urwid.Text("  from:amy OR from:bob → Match either condition"),
            urwid.Text("  from:amy AND to:bob  → Must match both"),
            urwid.Text("  rfc822msgid:<id>     → Find message by Message-ID"),
            urwid.Divider(),

            urwid.Text("📏 Size Filters"),
            urwid.Text("  size:1000000         → Bytes (over ~1MB)"),
            urwid.Text("  larger:10M           → More than 10 megabytes"),
            urwid.Text("  smaller:1M           → Less than 1 megabyte"),
            urwid.Divider(),

            urwid.Text("⭐ Star Filters"),
            urwid.Text("  has:yellow-star      → Specific star icon"),
            urwid.Text("  has:blue-info        → Custom markers supported"),
            urwid.Text("  has:red-bang OR has:green-check → Combine star types"),
        ])


        self.filter_help_box = urwid.LineBox(urwid.ListBox(self.filter_help_lines))

        self.showing_html = False

        self.help_lines = urwid.SimpleFocusListWalker([
            urwid.Text("📖 Help Menu - Key Bindings\n", align='center'),
            urwid.Text("🔍  enter        → Search with query"),
            urwid.Text("📩  1-9          → Open preview of result"),
            urwid.Text("📨  n / p        → Next / Previous search page"),
            urwid.Text("📁  d            → Download selected email as .eml"),
            urwid.Text("🧹  b            → Clear preview"),
            urwid.Text("🔧  f            → Show filter overlay"),
            urwid.Text("🌐  h            → Toggle raw/plaintext ↔ HTML"),
            urwid.Text("❓  Shift+H      → Show this help menu"),
            urwid.Text("🚪  esc / q      → Quit or close overlay"),
            urwid.Divider(),
            urwid.Text("Press the escape or q keys to close this help.")
        ])
        self.help_box = urwid.LineBox(urwid.ListBox(self.help_lines))
        self.current_msg_id = None
        self.active_overlay = None  # 'filter', 'help', etc.

        self.loop = urwid.MainLoop(self.main_layout, palette=palette, unhandled_input=self.handle_input)


    def render_html(self, html_content):
        h = html2text.HTML2Text()
        h.ignore_links = False
        h.ignore_images = False
        return h.handle(html_content)

    def run(self):
        self.loop.run()

    def prompt_encrypt_eml(self, callback):
        prompt = urwid.Text("Encrypt this email before saving? (y/n)")
        self.encrypt_prompt_overlay = urwid.Overlay(
            urwid.Filler(prompt),
            self.main_layout,
            align='center', width=('relative', 50),
            valign='middle', height=('relative', 20)
        )

        def handle_yes_no(key):
            if key.lower() == 'y':
                self.loop.widget = self.main_layout
                self.loop.unhandled_input = self.handle_input
                callback(True)
            elif key.lower() == 'n':
                self.loop.widget = self.main_layout
                self.loop.unhandled_input = self.handle_input
                callback(False)

        self.loop.widget = self.encrypt_prompt_overlay
        self.loop.unhandled_input = handle_yes_no


    def handle_input(self, key):
        if key == 'enter':
            query = self.query_edit.edit_text.strip()
            self.perform_search(query)
        elif key in ('esc', 'q') and not self.overlay:
            raise urwid.ExitMainLoop()
        elif key == 'b':
            self.columns.contents[1] = (urwid.LineBox(self.preview_box), self.columns.options('weight', 2))
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text("Select an email or search again."))
        elif key == 's':
            self.query_edit.set_edit_text("")
            self.main_layout.set_focus('header')

        elif key == 'd':
            from datetime import datetime
            now_str = datetime.now().strftime('%Y%m%d_%H%M%S')

            # Case 1: Saving a preview loaded from decrypted file
            if self.preview_source == 'file':
                try:
                    filename = f"email_decrypted_{now_str}.eml"
                    with open(filename, 'w', encoding='utf-8') as f:
                        for w in self.preview_lines:
                            if isinstance(w, urwid.Text):
                                f.write(w.text + '\n')
                    self.preview_lines.clear()
                    self.preview_lines.append(urwid.Text(f"✅ Decrypted email saved as: {filename}"))
                except Exception as e:
                    self.preview_lines.clear()
                    self.preview_lines.append(urwid.Text(f"❌ Failed to save: {e}"))
                return

            # Case 2: Invalid preview — can't save
            if self.preview_source != 'gmail' or not self.current_msg_id:
                self.preview_lines.clear()
                self.preview_lines.append(urwid.Text("⚠ Download only works for Gmail messages."))
                return

            # Case 3: Gmail email — prompt for encryption
            filename = f"email_{self.current_msg_id}.eml"

            def do_save(encrypt_eml):
                try:
                    save_eml(self.service.service, self.current_msg_id, filename, encrypt=encrypt_eml)
                    self.preview_lines.clear()
                    self.preview_lines.append(
                        urwid.Text(f"✅ Saved as: {filename}{'.enc' if encrypt_eml else ''}")
                    )
                except Exception as e:
                    self.preview_lines.clear()
                    self.preview_lines.append(urwid.Text(f"❌ Failed to save: {e}"))

            self.prompt_encrypt_eml(callback=do_save)


        elif key in map(str, range(1, 10)):  # Number keys 1-9
            index = int(key) - 1
            if 0 <= index < len(self.messages):
                msg_id = self.messages[index]['id']
                self.show_preview(None, msg_id)
        elif key == 'n' and self.next_page_token:
            self.page += 1
            self.perform_search(page_token=self.next_page_token)
        elif key == 'p' and self.page > 1:
            self.page -= 1
            self.perform_search()  # Gmail API doesn't support prev tokens, so requery from scratch
        elif key == 'f':
            self.show_filter_overlay()
        elif key == 'right' and self.overlay:
            focus_widget, _ = self.filter_listbox.get_focus()
            if isinstance(focus_widget, urwid.AttrMap):
                text_widget = focus_widget.original_widget
            elif isinstance(focus_widget, urwid.Text):
                text_widget = focus_widget
            else:
                return  # not valid

            filter_term = text_widget.text.strip()
            if filter_term and ':' in filter_term:
                self.query_edit.edit_text += f" {filter_term}"
            if filter_term.startswith("Select filter"):
                return
            self.loop.widget = self.main_layout
            self.overlay = None
        elif self.overlay and key in ('esc', 'left', 'q', 'enter'):
            self.loop.widget = self.main_layout
            self.overlay = None
            self.active_overlay = None
        elif key == 'h' and self.current_msg_id is not None:
            focus_index = self.preview_listbox.get_focus()[1]

            if self.showing_html:
                preview = get_message_preview(self.service.service, self.current_msg_id)
                self.preview_lines.clear()
                for line in preview.splitlines():
                    self.preview_lines.append(urwid.Text(line))
                self.showing_html = False
            else:
                html = get_html_body(self.service.service, self.current_msg_id)
                if not html:
                    self.preview_lines.clear()
                    self.preview_lines.append(urwid.Text("[No HTML content found]"))
                else:
                    rendered = self.render_html(html)
                    self.preview_lines.clear()
                    for line in rendered.splitlines():
                        self.preview_lines.append(urwid.Text(line))
                    self.showing_html = True

            # Re-apply scroll position
            if focus_index < len(self.preview_lines):
                self.preview_listbox.set_focus(focus_index)
        elif key == 'H':
            self.overlay = urwid.Overlay(
                self.help_box,
                self.main_layout,
                align='center', width=('relative', 60),
                valign='middle', height=('relative', 70)
            )
            self.loop.widget = self.overlay
        elif key == '?' and self.active_overlay == 'filter':
            self.overlay = urwid.Overlay(
                self.filter_help_box,
                self.main_layout,
                align='center', width=('relative', 80),
                valign='middle', height=('relative', 70)
            )
            self.loop.widget = self.overlay
            self.active_overlay = 'filter-help'
        elif key == 'T':
            self.build_theme_overlay()
        elif key == 'o':  # Open encrypted .eml.enc
            self.show_encrypted_file_picker()

    def perform_search(self, query=None, page_token=None):
        self.email_list.clear()
        self.preview_lines.clear()
        self.preview_lines.append(urwid.Text("Searching..."))


        if query is not None:
            self.query = query
            self.page = 1

        self.messages, self.next_page_token, _ = self.service.search(self.query, page_token=page_token)
        if not self.messages:
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text("No results found."))
            return

        for i, msg in enumerate(self.messages):
            headers = get_message_headers(self.service.service, msg['id'])
            subject = headers.get("Subject", "[No Subject]")
            sender = headers.get("From", "[No From]")
            date = headers.get("Date", "[No Date]")
            display = f"{i+1}. {subject} | {sender} | {date}"
            display = safe_str(display)
            button = urwid.Button(display)
            urwid.connect_signal(button, 'click', self.show_preview, msg['id'])
            self.email_list.append(urwid.AttrMap(button, 'preview', focus_map='focus'))
        self.preview_lines.clear()
        self.preview_lines.append(urwid.Text(f"Page {self.page}. Use 'n'/'p' to navigate."))
        


    def show_preview(self, button, msg_id):
        try:
            self.current_msg_id = msg_id
            self.preview_source = 'gmail'
            preview = get_message_preview(self.service.service, msg_id)
            if not preview:
                preview = "[No preview available]"
            preview = unescape_preview(preview)
            preview = safe_str(preview)
            lines = preview.splitlines() or ["[No content]"]
            self.showing_html = False
            self.preview_lines.clear()
            for line in lines:
                self.preview_lines.append(urwid.Text(line))
            self.preview_listbox.base_widget.set_focus(0)
        except Exception as e:
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text(f"Error loading preview: {e}"))

    def show_encrypted_file_picker(self):
        files = [f for f in os.listdir('.') if f.endswith('.eml.enc')]

        if not files:
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text("⚠ No .eml.enc files found in current directory."))
            return

        def on_file_select(button, filename):
            try:
                self.preview_source = 'file'
                decrypted = decrypt_to_memory(filename).decode('utf-8', errors='replace')
                self.preview_lines.clear()
                self.preview_lines.append(urwid.Text(f"📄 Previewing decrypted: {filename}"))
                for line in decrypted.splitlines():
                    self.preview_lines.append(urwid.Text(line))
                self.preview_listbox.base_widget.set_focus(0)
                self.loop.widget = self.main_layout
                self.overlay = None
                self.active_overlay = None
            except Exception as e:
                self.preview_lines.clear()
                self.preview_lines.append(urwid.Text(f"❌ Failed to decrypt {filename}: {e}"))
                self.loop.widget = self.main_layout
                self.overlay = None
                self.active_overlay = None

        buttons = [urwid.AttrMap(urwid.Button(f, on_press=on_file_select, user_data=f), None, focus_map='reversed') for f in files]
        file_listbox = urwid.ListBox(urwid.SimpleFocusListWalker(buttons))
        file_overlay = urwid.Overlay(
            urwid.LineBox(file_listbox, title="🔐 Select Encrypted Email to Open"),
            self.main_layout,
            align='center', width=('relative', 60),
            valign='middle', height=('relative', 60)
        )

        self.loop.widget = file_overlay
        self.overlay = file_overlay
        self.active_overlay = 'encrypted-picker'


    def prompt_open_encrypted_eml(self):
        enc_files = glob.glob("*.eml.enc")
        if not enc_files:
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text("📭 No encrypted .eml.enc files found in current directory."))
            return

        widgets = [urwid.Text("🔐 Select an encrypted email file:")]
        file_buttons = []

        for fname in enc_files:
            btn = urwid.Button(fname)
            urwid.connect_signal(btn, 'click', lambda btn, f=fname: self.open_encrypted_eml(f))
            file_buttons.append(urwid.AttrMap(btn, None, focus_map='reversed'))

        widgets += file_buttons
        pile = urwid.Pile(widgets)
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.ListBox(urwid.SimpleFocusListWalker(widgets))),
            self.main_layout,
            align='center', width=('relative', 60),
            valign='middle', height=('relative', 60)
        )

        self.loop.widget = overlay
        self.active_overlay = 'decrypt'

    def open_encrypted_eml(self):
        from tkinter import filedialog, Tk
        from secure_store import decrypt_to_memory

        try:
            # Hide root window
            root = Tk()
            root.withdraw()
            filepath = filedialog.askopenfilename(
                filetypes=[("All files", "*.*"), ("Encrypted EML", "*.eml.enc")],
                initialdir=os.getcwd(),
                title="Select an .eml.enc file to decrypt"
            )

            root.destroy()

            if not filepath:
                return

            decrypted = decrypt_to_memory(filepath).decode('utf-8', errors='replace')
            self.preview_lines.clear()
            self.current_msg_id = None
            self.preview_source = 'local'

            for line in decrypted.splitlines():
                self.preview_lines.append(urwid.Text(line))

            self.preview_listbox.base_widget.set_focus(0)
            self.preview_lines.append(urwid.Text("📄 Decrypted local .eml file previewed. Press 'b' to clear."))
        except Exception as e:
            self.preview_lines.clear()
            self.preview_lines.append(urwid.Text(f"❌ Failed to open file: {e}"))


