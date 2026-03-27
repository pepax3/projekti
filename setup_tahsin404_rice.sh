#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_HOME="/home/p"
TARGET_USER="p"
REPO_ROOT="$TARGET_HOME/.local/src/tahsin404"
SUCKLESS_DIR="$REPO_ROOT/Suckless"
DOTFILES_DIR="$REPO_ROOT/dotfiles"
YAY_DIR="$REPO_ROOT/yay"
WAL_DIR="$TARGET_HOME/.cache/wal"
CONFIG_DIR="$TARGET_HOME/.config"
PICTURES_DIR="$TARGET_HOME/Pictures"
WALLPAPER_DIR="$PICTURES_DIR/Wallpapers/tahsin404"
SCREENSHOT_DIR="$PICTURES_DIR/screenshots"
BACKUP_ROOT="$TARGET_HOME/.local/share/setup-backups/tahsin404/$(date +%F_%H-%M-%S)"

SUCKLESS_URL="https://github.com/Tahsin404/Suckless.git"
DOTFILES_URL="https://github.com/Tahsin404/dotfiles.git"
YAY_URL="https://aur.archlinux.org/yay.git"

PACMAN_PKGS=(
  base-devel git curl wget rsync stow unzip zip pkgconf cmake meson ninja
  xorg-server xorg-xinit xorg-xrandr xorg-xsetroot xorg-xprop xorgproto
  libx11 libxinerama libxft libxrender freetype2 fontconfig yajl jsoncpp
  python python-pywal starship ranger kitty neovim zathura zathura-pdf-mupdf
  hyprland hyprpaper waybar wofi xdg-desktop-portal-gtk xdg-desktop-portal-hyprland
  dolphin udiskie wl-clipboard grim slurp brightnessctl playerctl polkit-kde-agent
  qt5ct qt6ct pipewire wireplumber pavucontrol
  polybar flameshot cava btop fastfetch cmatrix
  spotify-launcher
  ttf-hack-nerd ttf-firacode-nerd ttf-lekton-nerd ttf-monofur-nerd
)

AUR_REQUIRED=(
  polybar-dwm-module
)

AUR_BESTEFFORT=(
  picom-ftlabs-git
  zen-browser-bin
  spicetify-cli
)

log() {
  printf '\n[%s] %s\n' "$(date +%H:%M:%S)" "$*"
}

warn() {
  printf '\n[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2
}

die() {
  printf '\n[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2
  exit 1
}

trap 'die "Command failed on line $LINENO: $BASH_COMMAND"' ERR

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"
}

ensure_not_root() {
  [[ "$(id -u)" -ne 0 ]] || die "Run this as the regular user, not root."
}

ensure_target_home() {
  [[ "$HOME" == "$TARGET_HOME" ]] || die "This script is pinned to $TARGET_HOME. Current HOME is $HOME."
  [[ "$(id -un)" == "$TARGET_USER" ]] || die "This script expects to be run as user '$TARGET_USER'. Current user is '$(id -un)'."
}

ensure_repo() {
  local url="$1"
  local dest="$2"
  local branch="${3:-}"

  mkdir -p "$(dirname "$dest")"

  if [[ -d "$dest/.git" ]]; then
    local remote
    remote="$(git -C "$dest" remote get-url origin 2>/dev/null || true)"
    if [[ -n "$remote" && "$remote" != "$url" ]]; then
      warn "$dest already exists, but origin is '$remote' instead of '$url'. Leaving it alone."
      return 0
    fi

    log "Repo already exists at $dest. Refreshing instead of cloning again."
    git -C "$dest" fetch --all --prune

    if [[ -n "$branch" ]]; then
      git -C "$dest" checkout "$branch" || true
      git -C "$dest" pull --ff-only origin "$branch" || warn "Could not fast-forward $dest. Keeping local checkout."
    else
      local current_branch
      current_branch="$(git -C "$dest" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
      if [[ -n "$current_branch" && "$current_branch" != "HEAD" ]]; then
        git -C "$dest" pull --ff-only origin "$current_branch" || warn "Could not fast-forward $dest. Keeping local checkout."
      fi
    fi
    return 0
  fi

  if [[ -e "$dest" ]]; then
    warn "$dest already exists and is not a git checkout. Skipping clone so I do not stomp your files."
    return 0
  fi

  log "Cloning $url into $dest"
  if [[ -n "$branch" ]]; then
    git clone --depth=1 --branch "$branch" "$url" "$dest"
  else
    git clone --depth=1 "$url" "$dest"
  fi
}

install_pacman_packages() {
  log "Installing official Arch packages"
  sudo pacman -Syu --needed --noconfirm "${PACMAN_PKGS[@]}"
}

install_yay() {
  if command -v yay >/dev/null 2>&1; then
    log "yay already exists"
    return 0
  fi

  ensure_repo "$YAY_URL" "$YAY_DIR"
  log "Building yay"
  (
    cd "$YAY_DIR"
    makepkg -si --noconfirm --needed
  )
}

install_aur_package_required() {
  local pkg="$1"
  log "Installing required AUR package: $pkg"
  yay -S --needed --noconfirm "$pkg"
}

install_aur_package_best_effort() {
  local pkg="$1"
  log "Installing best-effort AUR package: $pkg"
  if ! yay -S --needed --noconfirm "$pkg"; then
    warn "AUR package '$pkg' failed. Continuing."
    return 1
  fi
}

backup_file_if_exists() {
  local target="$1"
  if [[ -e "$target" && ! -e "$BACKUP_ROOT$target" ]]; then
    mkdir -p "$(dirname "$BACKUP_ROOT$target")"
    cp -a "$target" "$BACKUP_ROOT$target"
  fi
}

sync_config_tree() {
  local source_root="$1"
  mkdir -p "$CONFIG_DIR"

  while IFS= read -r -d '' dotconfig_dir; do
    log "Syncing config subtree from $dotconfig_dir"
    rsync -a "$dotconfig_dir/" "$CONFIG_DIR/"
  done < <(find "$source_root" -mindepth 2 -maxdepth 2 -type d -name .config -print0)
}

copy_file() {
  local src="$1"
  local dst="$2"
  [[ -e "$src" ]] || return 0
  mkdir -p "$(dirname "$dst")"
  backup_file_if_exists "$dst"
  cp -af "$src" "$dst"
}

replace_home_path() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  sed -i "s|/home/xelius|$TARGET_HOME|g" "$file"
}

patch_bashrc() {
  local bashrc="$TARGET_HOME/.bashrc"
  [[ -f "$bashrc" ]] || return 0

  replace_home_path "$bashrc"
  sed -i "s|cd ~/dotfiles && stow -R -v -t ~ \*/ && cd -|cd $DOTFILES_DIR \\\&\\\& stow -R -v -t ~ */ \\\&\\\& cd -|g" "$bashrc"
  sed -i "s|alias install='yay -Syu'|alias install='yay -S --needed'|g" "$bashrc"
}

patch_hyprland() {
  local hypr_conf="$CONFIG_DIR/hypr/hyprland.conf"
  local hyprpaper_conf="$CONFIG_DIR/hypr/hyprpaper.conf"
  local wallpaper="$1"

  if [[ -f "$hypr_conf" ]]; then
    sed -i 's|exec-once = quickshell|exec-once = waybar|g' "$hypr_conf"
    sed -i 's|command -v hyprshutdown >/dev/null 2>\\&1 \\&\\& hyprshutdown || hyprctl dispatch exit|hyprctl dispatch exit|g' "$hypr_conf"
    python - "$hypr_conf" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = p.read_text()
marker = "plugin { hyprtrails {"
if marker in text:
    text = text.split(marker, 1)[0].rstrip() + "\n"
p.write_text(text)
PY
  fi

  if [[ -f "$hyprpaper_conf" ]]; then
    python - "$hyprpaper_conf" "$wallpaper" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
wall = sys.argv[2]
text = p.read_text()
text = text.replace("~/Downloads/1325118.png", wall)
p.write_text(text)
PY
  fi
}

patch_suckless_paths() {
  local file
  for file in \
    "$SUCKLESS_DIR/dwm/config.h" \
    "$SUCKLESS_DIR/dmenu/config.h" \
    "$SUCKLESS_DIR/st/config.h"; do
    replace_home_path "$file"
  done
}

install_wal_headers() {
  mkdir -p "$WAL_DIR"
  copy_file "$SUCKLESS_DIR/colors-wal-dwm.h" "$WAL_DIR/colors-wal-dwm.h"
  copy_file "$SUCKLESS_DIR/colors-wal-dmenu.h" "$WAL_DIR/colors-wal-dmenu.h"
  copy_file "$SUCKLESS_DIR/colors-wal-st.h" "$WAL_DIR/colors-wal-st.h"
}

pick_wallpaper() {
  local preferred="$SUCKLESS_DIR/Wallpaper/gargantua-black-3840x2160-9621.jpg"
  if [[ -f "$preferred" ]]; then
    printf '%s\n' "$preferred"
    return 0
  fi

  local first
  first="$(find "$SUCKLESS_DIR/Wallpaper" -maxdepth 1 -type f | sort | head -n1 || true)"
  if [[ -n "$first" ]]; then
    printf '%s\n' "$first"
    return 0
  fi

  return 1
}

install_wallpapers() {
  mkdir -p "$WALLPAPER_DIR"
  if [[ -d "$SUCKLESS_DIR/Wallpaper" ]]; then
    rsync -a "$SUCKLESS_DIR/Wallpaper/" "$WALLPAPER_DIR/"
  fi
}

apply_pywal() {
  local wallpaper="$1"
  mkdir -p "$WAL_DIR"
  if [[ -f "$wallpaper" ]]; then
    log "Generating pywal cache from $wallpaper"
    wal -q -i "$wallpaper" || warn "pywal failed. Keeping the committed header files instead."
  fi
  install_wal_headers
}

create_launch_files() {
  mkdir -p "$SCREENSHOT_DIR"

  if [[ ! -f "$TARGET_HOME/.xinitrc" ]]; then
    cat > "$TARGET_HOME/.xinitrc" <<'XINIT'
#!/usr/bin/env sh
exec dwm
XINIT
    chmod +x "$TARGET_HOME/.xinitrc"
  fi

  sudo install -d /usr/share/xsessions
  sudo tee /usr/share/xsessions/dwm.desktop >/dev/null <<'DESKTOP'
[Desktop Entry]
Name=dwm
Comment=Dynamic window manager
Exec=dwm
Type=Application
DESKTOP
}

copy_repo_configs() {
  log "Normalizing the cooked dotfiles layout into $CONFIG_DIR"
  sync_config_tree "$DOTFILES_DIR"

  copy_file "$DOTFILES_DIR/bashrc/.bashrc" "$TARGET_HOME/.bashrc"
  copy_file "$SUCKLESS_DIR/starship.toml" "$CONFIG_DIR/starship.toml"
  install_wal_headers
  patch_bashrc
}

build_suckless() {
  local component
  for component in dwm dmenu st slstatus; do
    log "Building $component"
    (
      cd "$SUCKLESS_DIR/$component"
      make clean || true
      make
      sudo make install
    )
  done
}

main() {
  need_cmd sudo
  need_cmd pacman
  need_cmd sed
  need_cmd find

  ensure_not_root
  ensure_target_home

  mkdir -p "$REPO_ROOT" "$CONFIG_DIR" "$WAL_DIR" "$BACKUP_ROOT"
  sudo -v

  install_pacman_packages

  need_cmd git
  need_cmd rsync
  need_cmd python
  need_cmd wal

  ensure_repo "$SUCKLESS_URL" "$SUCKLESS_DIR" "main"
  ensure_repo "$DOTFILES_URL" "$DOTFILES_DIR" "master"

  install_yay

  local pkg
  for pkg in "${AUR_REQUIRED[@]}"; do
    install_aur_package_required "$pkg"
  done

  local picom_ftlabs_ok=0
  for pkg in "${AUR_BESTEFFORT[@]}"; do
    if [[ "$pkg" == "picom-ftlabs-git" ]]; then
      if install_aur_package_best_effort "$pkg"; then
        picom_ftlabs_ok=1
      fi
    else
      install_aur_package_best_effort "$pkg" || true
    fi
  done

  if [[ "$picom_ftlabs_ok" -eq 0 ]]; then
    log "Falling back to repo picom because picom-ftlabs-git did not install"
    sudo pacman -S --needed --noconfirm picom
  fi

  copy_repo_configs
  patch_suckless_paths
  install_wallpapers

  local wallpaper
  wallpaper="$(pick_wallpaper || true)"
  if [[ -n "$wallpaper" ]]; then
    apply_pywal "$wallpaper"
    patch_hyprland "$wallpaper"
  else
    warn "No wallpaper found in $SUCKLESS_DIR/Wallpaper. Skipping pywal and hyprpaper path fix."
  fi

  create_launch_files
  build_suckless

  log "Done."
  printf '\n'
  printf 'Repos:\n  %s\n  %s\n' "$SUCKLESS_DIR" "$DOTFILES_DIR"
  printf 'Use X11 with: startx\n'
  printf 'Use Hyprland from a TTY with: Hyprland\n'
}

main "$@"
