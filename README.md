# omastation

**Your [Omarchy](https://omarchy.org/) desktop, from anywhere. It feels like Windows RDP.**

Open Remote Desktop on your laptop, type your password, and you're at your desk: the same
windows and workspaces, fitted to the screen in front of you, with a pointer that never lags.
Disconnect and the desk locks before its screens come back on. Sit down at it later and sign
in: everything is where you left it.

No permission prompts, no second desktop, no unlocked screen glowing at your desk.

- **Your real session**, not a copy. Workspaces move to the client's screens and come back
  exactly as they were; the desk goes dark, its keyboard and mouse fenced, its speakers muted.
- **A pointer that never lags.** Your client draws it, as with Windows.
- **Fits any screen.** Size, DPI and monitors follow your client live, as you resize the window
  or drag it to another display.
- **Built for Omarchy.** It logs you into Omarchy's own lock screen and locks it when you leave,
  even after a crash. Sign in at the desk and the desk takes over.
- **Your keyboard, your bindings.** The client's layout is picked for you, Hyprland bindings
  and key repeat just work, and a Mac gets Option + drag for SUPER + drag.
- **Survives bad Wi-Fi.** Drop out and reconnect within 2 minutes: same session, desk still
  dark. Quality follows your bandwidth, and a still screen sharpens to pixel-perfect.
- **Windows clients just work**, because omastation speaks RDP the way Windows does.
- **And the rest:** sound and microphone, copy and paste with files, your client's drives in
  `~/RDP Drives`, RemoteApp, touch and pen.

## Get started

```sh
git clone https://github.com/realazizk/omastation
cd omastation/packaging/omastation && makepkg -si
cd ../hyprland && makepkg -si                            # the smooth pointer; log out and in after
omastation passwd                                        # your Linux login password
sudo systemctl enable --now omastation-helper@$(id -u)   # fences the desk's input
systemctl --user enable --now omastation                 # the server
sudo ufw allow omastation                                # port 3389, TCP and UDP
```

Then connect from any RDP client with your Linux user name and password.

`packaging/hyprland` is Arch's Hyprland plus omastation's cursor fix. Without it the pointer is
painted into the picture; Arch's next Hyprland update replaces it.

## License

MIT, see [LICENSE](LICENSE).
