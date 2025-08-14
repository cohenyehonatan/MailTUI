# spinner.py

import sys
import time
import threading

# For terminal mode
def spinner_for_thread(thread, speed=0.1, text=''):
    spin = "⢎⡰⢎⡡⢎⡑⢎⠱⠎⡱⢊⡱⢌⡱⢆⡱"
    i = 0
    while thread.is_alive():
        c1 = spin[(i * 2) % len(spin)]
        c2 = spin[(i * 2 + 1) % len(spin)]
        sys.stdout.write(f'\r{text}{c1}{c2}')
        sys.stdout.flush()
        time.sleep(speed)
        i = (i + 1) % (len(spin) // 2)
    sys.stdout.write('\r' + ' ' * (len(text) + 2) + '\r')
    sys.stdout.flush()

def command_with_spinner(func, text="Working...", *args, **kwargs):
    result = {}
    def target():
        result["value"] = func(*args, **kwargs)

    thread = threading.Thread(target=target)
    thread.start()
    spinner_for_thread(thread, text=text)
    thread.join()
    return result["value"]

# For urwid mode
def urwid_spinner(loop, text_widget, stop_flag, speed=0.1):
    spin = "⢎⡰⢎⡡⢎⡑⢎⠱⠎⡱⢊⡱⢌⡱⢆⡱"
    state = {'i': 0}

    def update(loop, *_):
        if stop_flag[0]:
            text_widget.set_text("")
            return
        i = state['i']
        c1 = spin[(i * 2) % len(spin)]
        c2 = spin[(i * 2 + 1) % len(spin)]
        text_widget.set_text(f"⏳ {c1}{c2}")
        state['i'] = (i + 1) % (len(spin) // 2)
        loop.set_alarm_in(speed, update)

    loop.set_alarm_in(0.01, update)