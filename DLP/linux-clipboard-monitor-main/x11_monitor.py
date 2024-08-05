#!/usr/bin/env python

import sys
import os
import security
import binascii
import subprocess
import pwd

# Change path so we find Xlib
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from Xlib import X, display, Xutil, Xatom
from Xlib.protocol import event

# This script does not implement fancy stuff like INCR or MULTIPLE, so
# put a hard limit on the amount of data we allow sending this way
MAX_SIZE = 50000

CLIPBOARD = None
UTF8_STRING = None
DATA = None

    
def get_process_info_xdotool(window_id):
    try:
        # Get PID
        pid_cmd = f"xdotool getwindowpid {window_id}"
        pid = subprocess.check_output(pid_cmd, shell=True).decode().strip()
        # print(f"Found pid {pid}")

        exe_path = os.readlink(f"/proc/{pid}/exe")
        uid = os.stat(f"/proc/{pid}").st_uid
        username = pwd.getpwuid(uid).pw_name

        # return f"PID: {pid}, Exepath: {exe_path}, User/UserID: {username}/{uid}"
        return (pid, exe_path, username)
    except subprocess.CalledProcessError:
        # return "Unable to retrieve process information"
        return (None, None, None)

def log(msg, *args):
    sys.stderr.write(msg.format(*args) + '\n')

def error(msg, *args):
    log(msg, *args)
    sys.exit(1)

def is_string_type(d, r):
    if r.format == 8:
        if r.property_type == Xatom.STRING or r.property_type == d.get_atom('UTF8_STRING'):
            return True
    return False

def decode_data(d, r):
    value = ""

    if r.format == 8:
        if r.property_type == Xatom.STRING:
            value = r.value.decode('ISO-8859-1')
        elif r.property_type == d.get_atom('UTF8_STRING'):
            value = r.value.decode('UTF-8')
        else:
            value = binascii.hexlify(r.value).decode('ascii')

    elif r.format == 32 and r.property_type == Xatom.ATOM:
        for v in r.value:
            value += '{0}\n'.format(d.get_atom_name(v))

    else:
        for v in r.value:
            value += '{0}\n'.format(v)

    return value 

def output_data(d, r, target_name):
    log('got {0}:{1}, length {2}',
        d.get_atom_name(r.property_type),
        r.format,
        len(r.value))

    print(decode_data(d, r))


def clear_clipboard(d, w):
    global CLIPBOARD, UTF8_STRING

    # Assumes we already own the clipboard
    w.change_property(CLIPBOARD, UTF8_STRING, 8, b"")
    d.flush()

def check_clipboard_value(d, w, clipboard_data, context, app_name, app_user):
    rule_signals = ruleHandler.handle_event(clipboard_data, context, app_name, app_user)
    # Depending on the returned rule actions that were triggered, block the copy/paste
    if 'mask' in rule_signals:
        clipboard_data = security.mask_data(clipboard_data)
    if 'quarantine' in rule_signals:
        # Quarantine clipboard contents and then clear
        security.quarantine(clipboard_data)
        clipboard_data = b""
    if 'block' in rule_signals:
        clipboard_data = b""

    if ('block' in rule_signals or 'quarantine' in rule_signals) and (context == "copy" or context == "all"):
        # This prevents us clearing the clipboard on paste
        clear_clipboard(d, w)
    return clipboard_data

def get_selection(d, w):
    global CLIPBOARD

    # Ask the server who owns this selection, if any
    owner = d.get_selection_owner(CLIPBOARD)
    sel_name = "CLIPBOARD"
    sel_atom = CLIPBOARD

    target_name = "UTF8_STRING"
    target_atom = d.get_atom(target_name)

    if owner == X.NONE:
        # No owner for the selection
        return
        
    # Get metadata for the owning application
    app_pid, app_name, app_user = get_process_info_xdotool(owner.id)

    data_atom = d.get_atom('SEL_DATA')

    # The data_atom should not be set according to ICCCM, and since
    # this is a new window that is already the case here.

    # Ask for the selection.  We shouldn't use X.CurrentTime, but
    # since we don't have an event here we have to.
    w.convert_selection(sel_atom, target_atom, data_atom, X.CurrentTime)

    # Wait for the notification that we got the selection
    while True:
        e = d.next_event()
        if e.type == X.SelectionNotify:
            break

    # Do some sanity checks
    if (e.requestor != w
            or e.selection != sel_atom
            or e.target != target_atom):
        error('SelectionNotify event does not match our request: {0}', e)

    if e.property == X.NONE:
        # log('selection lost or conversion to {0} failed',
            # target_name)
        return

    if e.property != data_atom:
        error('SelectionNotify event does not match our request: {0}', e)

    # Get the data
    r = w.get_full_property(data_atom, X.AnyPropertyType,
                            sizehint=10000)

    # Audit the copied data
    clipboard_data = decode_data(d, r)
    # Only check if the clipboard_data is of a string type
    if is_string_type(d, r):
        clipboard_data = check_clipboard_value(d, w, clipboard_data.encode("utf-8"), "copy", app_name, app_user)
        if isinstance(clipboard_data, str):
            clipboard_data = clipboard_data.encode("utf-8")
    else:
        # The clipboard monitor only handles utf-8 data at this point
        clipboard_data = b""

    return clipboard_data

def grab_selection(d, w, sel_name, sel_atom, sel_time):
    # Grab the selection and make sure we actually got it
    w.set_selection_owner(sel_atom, sel_time)
    if d.get_selection_owner(sel_atom) != w:
        # Failed to take ownership of the selection
        return


def main_loop():
    global CLIPBOARD, UTF8_STRING

    #d = display.Display(":0")
    d = display.Display()

    # Handling arguments that are irrelevant for us
    # Instead of hardcoding the clipboard, we want to grab the current one.
    sel_name = "CLIPBOARD"
    CLIPBOARD = d.get_atom(sel_name)
    sel_atom = CLIPBOARD
    UTF8_STRING = d.get_atom("UTF8_STRING")

    # map type atom -> data
    #types = {d.get_atom('UTF8_STRING'): b"Hello"}

    targets_atom = d.get_atom('TARGETS')

    # Taking over the clipboard
    # We must have a window to own a selection
    w = d.screen().root.create_window(
        0, 0, 10, 10, 0, X.CopyFromParent)

    types = {}
    types[UTF8_STRING] = get_selection(d, w)

    # And to grab the selection we must have a timestamp, get one with
    # a property notify when we're anyway setting wm_name
    w.change_attributes(event_mask=X.PropertyChangeMask)
    w.set_wm_name(os.path.basename(sys.argv[0]))

    e = d.next_event()
    sel_time = e.time
    w.change_attributes(event_mask=0)

    # Grab the selection and make sure we actually got it
    w.set_selection_owner(sel_atom, sel_time)
    if d.get_selection_owner(sel_atom) != w:
        # log('could not take ownership of {0}', sel_name)
        return

    # log('took ownership of selection {0}', sel_name)

    # The event loop, waiting for and processing requests
    while True:
        e = d.next_event()

        if (e.type == X.SelectionRequest
                and e.owner == w
                and e.selection == sel_atom):

            client = e.requestor

            if e.property == X.NONE:
                # log('request from obsolete client!')
                client_prop = e.target  # per ICCCM recommendation
            else:
                client_prop = e.property


            target_name = d.get_atom_name(e.target)

            # log('got request for {0}, dest {1} on 0x{2:08x} {3}',
            #     target_name, d.get_atom_name(client_prop),
            #     client.id, client.get_wm_name())

            # Is the client asking for which types we support?
            if e.target == targets_atom:
                # Then respond with TARGETS and the type
                prop_value = [targets_atom] + list(types.keys())
                prop_type = Xatom.ATOM
                prop_format = 32

            # Request for the offered type
            elif e.target in types:
                # Check before paste 
                app_pid, app_name, app_user = get_process_info_xdotool(e.requestor.id)
                # log(f"request from {app_pid}, {app_name}, {app_user}")
                value = check_clipboard_value(d, w, types[e.target], "paste", app_name, app_user)
                prop_value = value 
                prop_type = e.target
                prop_format = 8

            # Something else, tell client they can't get it
            else:
                # log('refusing conversion to {0}', target_name)
                client_prop = X.NONE

            # Put the data on the dest window, if possible
            if client_prop != X.NONE:
                client.change_property(
                    client_prop, prop_type, prop_format, prop_value)

            # And always send a selection notification
            ev = event.SelectionNotify(
                time=e.time,
                requestor=e.requestor,
                selection=e.selection,
                target=e.target,
                property=client_prop)

            client.send_event(ev)

            # Done!

        elif (e.type == X.SelectionClear
              and e.window == w
              and e.atom == sel_atom):
            # log('lost ownership of selection {0}', sel_name)
            types[UTF8_STRING] = get_selection(d, w)
            grab_selection(d, w, sel_name, sel_atom, e.time)

        # A proper owner would also look for PropertyNotify here on
        # the selector's windows to implement INCR and waiting for
        # acknowledgement that the client has finished copying.

def x11_monitor_main(rHandler):
    global ruleHandler
    ruleHandler = rHandler
    main_loop()
    #try:
    #    main_loop()
    #except Exception:
    #    print("[!] X11 clipboard monitor failed.")

# if __name__ == '__main__':
#     x11_monitor_main()
