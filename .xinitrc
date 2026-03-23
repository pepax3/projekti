#!/bin/sh

[ -f "$HOME/.Xresources" ] && xrdb -merge "$HOME/.Xresources"
[ -f "$HOME/.cache/wal/sequences" ] && cat "$HOME/.cache/wal/sequences"
[ -f "$HOME/.cache/wal/colors.Xresources" ] && xrdb -merge "$HOME/.cache/wal/colors.Xresources"

if [ -f "$HOME/Suckless/Wallpaper/gargantua-black-3840x2160-9621.jpg" ]; then
    feh --bg-fill "$HOME/Suckless/Wallpaper/gargantua-black-3840x2160-9621.jpg" &
fi

if command -v picom >/dev/null 2>&1; then
    if [ -f "$HOME/.config/picom/picom.conf" ]; then
        picom --config "$HOME/.config/picom/picom.conf" &
    else
        picom &
    fi
fi

if command -v polybar >/dev/null 2>&1; then
    if [ -x "$HOME/.config/polybar/launch.sh" ]; then
        "$HOME/.config/polybar/launch.sh" &
    else
        polybar &
    fi
fi

exec dwm
