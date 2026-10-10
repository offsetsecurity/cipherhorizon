#!/bin/sh
# CipherHorizon machine inventory engine for Linux, version 2.0.1
#
# What it does: runs each signature listed below with one of a few read-only capabilities,
# and writes what it finds to a plain-text facts file you can read before you upload it.
#
#   package    lists installed packages (dpkg, rpm or apk) whose name matches
#   certfiles  copies the CERTIFICATE blocks of certificate files in the named folders
#   file       finds files by name under folders: path, size and SHA-256 (not their content)
#   lines      reads text files and keeps only the lines that match
#
# What it never does: change anything, install anything, make a network connection, enter
# a directory meant for keys, open a file named like a key, or send any block but a
# certificate out of a certificate file.
#
# The signatures (what to collect) come from the CipherHorizon server's signature database
# and are listed just below; the server shows the same list on its Inventory page. To
# collect something new, the database changes, not this engine.
#
# Usage:   sh cipherhorizon-inventory.sh [output-file] [signature-file]
#          (as root for a fuller picture; it works without, and says so)
# Then upload the output file on the Inventory page of your CipherHorizon server.

set -u
# Everything this script writes (the facts file, its temporary file) is readable by its owner only.
umask 077
ENGINE_VERSION=2.0.1
OUT=${1:-cipherhorizon-facts-$(hostname 2>/dev/null || echo host).txt}

# ---- signatures: what to collect, from the CipherHorizon signature database --------------
# The server fills this in when it hands the script out; a second argument reads them from a file.
SIGNATURES=''
#@@SIGNATURES-BEGIN@@
#@@SIGNATURES-END@@
[ -n "${2:-}" ] && SIGNATURES=$(cat "$2")

TAB=$(printf '\t')
KEYNAME='(^|[-_.])(priv|privkey|private|key|keys|secret|pkcs12|p12|pfx|jks|keystore)([-_.]|$)'
b64() { base64 | tr -d '\n'; }
clean() { printf '%s' "$1" | tr '\t\r\n' '   '; }
keyfile() { # a file named like a key is never opened; a .pub public key is allowed
  case "$1" in *.pub) return 1 ;; esac
  basename "$1" | grep -Eiq "$KEYNAME"
}
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1; fi; }

# ---- capabilities ------------------------------------------------------------------------

cap_package() { # match
  if command -v dpkg-query >/dev/null 2>&1; then
    printf 'fact\t%s\tpackage-manager\tdpkg\n' "$id"
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null |
      awk -F'\t' -v re="$p_match" -v id="$id" '$1 ~ /^ii/ && $2 ~ re { printf "fact\t%s\tpackage\tdpkg\t%s\t%s\t%s\n", id, $2, $3, $4 }'
  fi
  if command -v rpm >/dev/null 2>&1 && [ -n "$(rpm -qa 2>/dev/null | head -1)" ]; then
    printf 'fact\t%s\tpackage-manager\trpm\n' "$id"
    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null |
      awk -F'\t' -v re="$p_match" -v id="$id" '$1 ~ re { printf "fact\t%s\tpackage\trpm\t%s\t%s\t%s\n", id, $1, $2, $3 }'
  fi
  if command -v apk >/dev/null 2>&1; then
    printf 'fact\t%s\tpackage-manager\tapk\n' "$id"
    # "name-version-rN arch {origin} (licence) [installed]": the version is the last two "-" fields.
    apk list --installed 2>/dev/null | awk -v re="$p_match" -v id="$id" '{
      n = split($1, p, "-"); if (n < 3) next
      name = p[1]; for (i = 2; i <= n - 2; i++) name = name "-" p[i]
      if (name ~ re) printf "fact\t%s\tpackage\tapk\t%s\t%s-%s\t%s\n", id, name, p[n-1], p[n], $2 }'
  fi
}

cap_certfiles() { # dirs, depth, max
  n=0
  printf '%s\n' "$p_dirs" | tr '|' '\n' | while IFS= read -r d; do
    [ -d "$d" ] || continue
    find -L "$d" -maxdepth "${p_depth:-6}" \
      \( -type d \( -name private -o -name private_keys -o -name keys -o -name keystore -o -name secrets -o -name .git \) -prune \) -o \
      \( -type f \( -name '*.crt' -o -name '*.cer' -o -name '*.pem' \) -size -256k -print \) 2>/dev/null
  done | while IFS= read -r f; do
    keyfile "$f" && continue
    basename "$f" | grep -Eq '^[0-9a-f]{8}\.[0-9]+$' && continue # OpenSSL hash links
    [ -r "$f" ] || continue
    n=$((n + 1)); [ "$n" -gt "${p_max:-5000}" ] && break
    # Only the CERTIFICATE blocks leave this machine; any other block in the file is dropped here.
    blocks=$(awk '/-----BEGIN CERTIFICATE-----/{c=1} c{print} /-----END CERTIFICATE-----/{c=0}' "$f" 2>/dev/null)
    [ -n "$blocks" ] || continue
    printf 'fact\t%s\tcert-file\t%s\t%s\n' "$id" "$(clean "$f")" "$(printf '%s\n' "$blocks" | b64)"
  done
}

cap_file() { # roots, names, depth, max
  set --
  set -f # a pattern such as libssl*.so is for find, never for the shell to expand here
  for nm in $(printf '%s' "$p_names" | tr '|' ' '); do set -- "$@" -o -name "$nm"; done
  set +f
  shift # the leading -o
  printf '%s\n' "$p_roots" | tr '|' '\n' | while IFS= read -r r; do
    [ -d "$r" ] && find "$r" -maxdepth "${p_depth:-4}" -type f \( "$@" \) 2>/dev/null
  done | head -n "${p_max:-500}" | while IFS= read -r f; do
    keyfile "$f" && continue
    printf 'fact\t%s\tfile\t%s\t%s\t%s\t\t\n' "$id" "$(clean "$f")" "$(wc -c < "$f" 2>/dev/null | tr -d ' ')" "$(sha "$f")"
  done
}

cap_lines() { # paths, match, max
  for pattern in $(printf '%s' "$p_paths" | tr '|' ' '); do
    for f in $pattern; do # the shell expands wildcards in the path
      [ -f "$f" ] && [ -r "$f" ] || continue
      keyfile "$f" && continue
      grep -E "$p_match" "$f" 2>/dev/null | grep -v 'PRIVATE KEY' | head -n "${p_max:-50}" | while IFS= read -r l; do
        printf 'fact\t%s\tline\t%s\t%s\n' "$id" "$(clean "$f")" "$(clean "$l" | cut -c1-1000)"
      done
    done
  done
}

# ---- run ---------------------------------------------------------------------------------

priv=user
[ "$(id -u 2>/dev/null)" = 0 ] && priv=admin
# mktemp creates the file itself, owner-only, under a name nobody can predict. Without it the script
# stops rather than guess a name in a shared directory (a symlink planted there could redirect a
# root-owned write).
if ! tmp=$(mktemp 2>/dev/null) || [ -z "$tmp" ]; then
  printf 'cipherhorizon-inventory: mktemp is needed (coreutils or busybox) and was not found; nothing was written\n' >&2
  exit 1
fi
trap 'rm -f "$tmp"' EXIT
trap 'exit 130' INT TERM

{
  printf 'cipherhorizon-machine-facts\t2\n'
  printf 'script\tlinux-sh\t%s\n' "$ENGINE_VERSION"
  printf 'host\tname\t%s\n' "$(clean "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)")"
  printf 'host\tos\tlinux\n'
  printf 'host\tprivilege\t%s\n' "$priv"
  printf 'host\tcollected\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in /etc/os-release /usr/lib/os-release; do
    if [ -r "$f" ]; then printf 'os-release\t%s\n' "$(b64 < "$f")"; break; fi
  done

  printf '%s\n' "$SIGNATURES" | while IFS= read -r sigline; do
    kind=$(printf '%s' "$sigline" | cut -f1)
    if [ "$kind" = signatures ]; then printf 'signatures\t%s\n' "$(printf '%s' "$sigline" | cut -f2)"; continue; fi
    [ "$kind" = sig ] || continue
    id=$(printf '%s' "$sigline" | cut -f2)
    cap=$(printf '%s' "$sigline" | cut -f3)
    p_match='' p_paths='' p_dirs='' p_roots='' p_names='' p_depth='' p_max=''
    rest=$(printf '%s' "$sigline" | cut -f4-)
    oldifs=$IFS; IFS=$TAB; set -f
    for kv in $rest; do
      v=${kv#*=}
      case "$kv" in
        match=*) p_match=$v ;; paths=*) p_paths=$v ;; dirs=*) p_dirs=$v ;; roots=*) p_roots=$v ;;
        names=*) p_names=$v ;; depth=*) p_depth=$v ;; max=*) p_max=$v ;;
      esac
    done
    IFS=$oldifs; set +f
    case "$cap" in
      package) cap_package > "$tmp" ;;
      certfiles) cap_certfiles > "$tmp" ;;
      file) cap_file > "$tmp" ;;
      lines) cap_lines > "$tmp" ;;
      *) printf 'skip\t%s\tcapability %s is not in this engine\n' "$id" "$cap" > "$tmp" ;;
    esac
    cat "$tmp"
    printf 'ran\t%s\t%s\n' "$id" "$(grep -c '^fact' "$tmp")"
  done

  [ "$priv" = admin ] || printf 'note\tRan without root: files only root can read were not listed.\n'
} > "$OUT"
rm -f "$tmp"

printf 'wrote %s (%s lines, %s facts)\n' "$OUT" "$(grep -c '' "$OUT")" "$(grep -c '^fact' "$OUT")" >&2
printf 'next: read it if you like (it is plain text), then upload it on the Inventory page of CipherHorizon.\n' >&2
