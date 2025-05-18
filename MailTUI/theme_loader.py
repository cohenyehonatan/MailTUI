# theme_loader.py

import os
import json
import urwid

THEMES_DIR = "themes"
DEFAULT_THEME = "default"

def get_available_themes():
    """
    Returns a list of available theme names (no .json extension).
    """
    if not os.path.exists(THEMES_DIR):
        return [DEFAULT_THEME]

    return [
        os.path.splitext(f)[0]
        for f in os.listdir(THEMES_DIR)
        if f.endswith(".json")
    ] or [DEFAULT_THEME]

def load_theme_palette(theme_name=DEFAULT_THEME):
    """
    Loads a theme by name and returns a urwid-compatible palette.
    """
    theme_path = os.path.join(os.path.dirname(__file__), "themes", f"{theme_name}.json")
    theme_path = os.path.abspath(theme_path)

    if not os.path.exists(theme_path):
        print(f"⚠ Theme '{theme_name}' not found. Falling back to default.")
        theme_path = os.path.join(os.path.dirname(__file__), "themes", f"{DEFAULT_THEME}.json")
        theme_path = os.path.abspath(theme_path)

    try:
        print(f"[DEBUG] Loading theme from: {theme_path}")
        with open(theme_path, "r") as f:
            raw = json.load(f)
    except Exception as e:
        raise Exception(f"❌ Failed to load theme '{theme_name}': {e}")

    # Convert { "tag": ["fg", "bg"] } into urwid palette format
    palette = []
    for tag, value in raw.items():
        if isinstance(value, list) and len(value) == 2:
            palette.append((tag, value[0], value[1]))
        else:
            print(f"⚠ Invalid color format for '{tag}' in theme '{theme_name}'")
    return palette