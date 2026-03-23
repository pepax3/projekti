cat > ~/.xinitrc <<'EOF'
[ -f "$HOME/.Xresources" ] && xrdb -merge "$HOME/.Xresources"
[ -f "$HOME/.cache/wal/sequences" ] && cat "$HOME/.cache/wal/sequences"
[ -f "$HOME/.cache/wal/colors.Xresources" ] && xrdb -merge "$HOME/.cache/wal/colors.Xresources"
[ -f "$HOME/Suckless/Wallpaper/gargantua-black-3840x2160-9621.jpg" ] && feh --bg-fill "$HOME/Suckless/Wallpaper/gargantua-black-3840x2160-9621.jpg" &
if command -v picom >/dev/null 2>&1; then
  [ -f "$HOME/.config/picom/picom.conf" ] && picom --config "$HOME/.config/picom/picom.conf" & || picom &
fi
if command -v polybar >/dev/null 2>&1; then
  [ -x "$HOME/.config/polybar/launch.sh" ] && "$HOME/.config/polybar/launch.sh" & || polybar &
fi
exec dwm
EOF
chmod +x ~/.xinitrc
