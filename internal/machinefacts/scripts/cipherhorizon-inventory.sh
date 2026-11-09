#!/bin/sh
# CipherHorizon machine inventory engine for Linux, version 3.0.0
#
# What it does: runs each signature listed below with one of a few read-only capabilities,
# and writes what it finds to a plain-text facts file you can read before you upload it.
#
#   package    lists installed packages (dpkg, rpm or apk) whose name matches
#   certfiles  copies the CERTIFICATE blocks of certificate files in the named folders
#   file       finds files by name under folders: path, size and SHA-256 (not their content)
#   lines      reads text files and keeps only the lines that match
#   query      runs ONE of the fixed read-only queries listed in this engine (QUERIES below:
#              version and algorithm listings of installed tools, the effective sshd policy,
#              listening sockets, disk encryption state), named by its id; a signature cannot
#              name a command, only pick a query from that table
#   listeners  lists listening sockets with the owning process, its executable and the
#              cryptographic libraries that process has mapped (names only, from /proc)
#
# What it never does: change anything, install anything, make a network connection, enter
# a directory meant for keys, open a file named like a key, read /etc/wireguard, or send any
# block but a certificate out of a certificate file. Every query runs with a timeout.
#
# The signatures (what to collect) come from the CipherHorizon server's signature database
# and are listed just below; the server shows the same list on its Inventory page. To
# collect something new, the database changes, not this engine.
#
# Usage:   sh cipherhorizon-inventory.sh [output-file] [signature-file]
#          (as root for a fuller picture; it works without, and says so)
# Then upload the output file on the Inventory page of your CipherHorizon server.

set -u
# Everything this script writes (the facts file, its temporary files) is readable by its owner only.
umask 077
ENGINE_VERSION=3.0.0
OUT=${1:-cipherhorizon-facts-$(hostname 2>/dev/null || echo host).txt}

# ---- signatures: what to collect, from the CipherHorizon signature database --------------
# The server fills this in when it hands the script out; a second argument reads them from a file.
SIGNATURES=''
#@@SIGNATURES-BEGIN@@
#@@SIGNATURES-END@@
[ -n "${2:-}" ] && SIGNATURES=$(cat "$2")

TAB=$(printf '\t')
KEYNAME='(^|[-_.])(priv|privkey|private|key|keys|secret|pkcs12|p12|pfx|jks|keystore)([-_.]|$)'
# Libraries whose presence in a process's address space says which cryptography it runs with.
CRYPTOLIB='lib(ssl|crypto|gnutls|gcrypt|sodium|nss3|smime3|nspr4|mbedtls|mbedcrypto|mbedx509|wolfssl|botan|ssh|ssh2|k5crypto|krb5|hogweed|nettle|tomcrypt|oqs|tss2|p11-kit|softhsm2|gpgme|cryptsetup)[^/]*\.so'
b64() { base64 | tr -d '\n'; }
clean() { printf '%s' "$1" | tr '\t\r\n' '   '; }
have() { command -v "$1" >/dev/null 2>&1; }
keyfile() { # a file named like a key is never opened; a .pub public key is allowed
  case "$1" in *.pub) return 1 ;; /etc/wireguard/*) return 0 ;; esac
  basename "$1" | grep -Eiq "$KEYNAME"
}
sha() { if have sha256sum; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1; fi; }

# ---- the query table ---------------------------------------------------------------------
# Each query is a fixed, read-only command line written here, never in a signature. A signature
# names the id; the engine checks the tool is installed, runs the line under `timeout`, and keeps
# the lines the signature's `match` selects. QUERIES lists the ids (the server checks this list).
# QUERIES: os.kernel cpu.crypto-flags openssl.version openssl.providers openssl.ciphers
#   openssl.kem-algorithms openssl.signature-algorithms gnutls.version gpg.version curl.version
#   wget.version ssh.version ssh.algorithms sshd.effective ssh.host-keys crypto-policies
#   java.version python.ssl node.versions go.version ruby.openssl php.openssl dotnet.runtimes
#   nginx.build apache.build haproxy.build postfix.tls dovecot.ssl samba.effective bind.build
#   openvpn.version ipsec.version wireguard.interfaces stunnel.version cryptsetup.version
#   disk.encryption secure-boot
query_def() { # sets tool (what must be installed) and cmd (the fixed command line)
  case "$1" in
    os.kernel) tool=uname; cmd='uname -srm' ;;
    cpu.crypto-flags) tool=grep; cmd="grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -Ex 'aes|sha_ni|pclmulqdq|vaes|vpclmulqdq|avx2|avx512f|rdrand|rdseed|sm3|sm4' | paste -sd' ' -" ;;
    openssl.version) tool=openssl; cmd='openssl version -a' ;;
    openssl.providers) tool=openssl; cmd='openssl list -providers' ;;
    openssl.ciphers) tool=openssl; cmd='openssl ciphers -v' ;;
    openssl.kem-algorithms) tool=openssl; cmd='openssl list -kem-algorithms' ;;
    openssl.signature-algorithms) tool=openssl; cmd='openssl list -signature-algorithms' ;;
    gnutls.version) tool=gnutls-cli; cmd='gnutls-cli --version | head -n 1' ;;
    gpg.version) tool=gpg; cmd='gpg --version' ;;
    curl.version) tool=curl; cmd='curl --version | head -n 1' ;;
    wget.version) tool=wget; cmd='wget --version | head -n 1' ;;
    ssh.version) tool=ssh; cmd='ssh -V 2>&1' ;;
    ssh.algorithms) tool=ssh; cmd="for q in kex cipher mac key sig; do printf '%s: ' \"\$q\"; ssh -Q \"\$q\" 2>/dev/null | paste -sd' ' -; done" ;;
    sshd.effective) tool=sshd; cmd='sshd -T 2>/dev/null' ;;
    ssh.host-keys) tool=ssh-keygen; cmd='for f in /etc/ssh/ssh_host_*_key.pub; do [ -f "$f" ] && ssh-keygen -lf "$f" 2>/dev/null; done' ;;
    crypto-policies) tool=update-crypto-policies; cmd='update-crypto-policies --show 2>/dev/null; fips-mode-setup --check 2>/dev/null' ;;
    java.version) tool=java; cmd='java -version 2>&1; readlink -f "$(command -v java)"' ;;
    python.ssl) tool=python3; cmd="python3 -c 'import ssl,sys;print(\"python\",sys.version.split()[0],ssl.OPENSSL_VERSION)'" ;;
    node.versions) tool=node; cmd="node -p 'process.versions.node+\" openssl \"+process.versions.openssl'" ;;
    go.version) tool=go; cmd='go version' ;;
    ruby.openssl) tool=ruby; cmd="ruby -ropenssl -e 'puts \"ruby #{RUBY_VERSION} #{OpenSSL::OPENSSL_LIBRARY_VERSION}\"'" ;;
    php.openssl) tool=php; cmd="php -r 'echo \"php \",PHP_VERSION,\" \",defined(\"OPENSSL_VERSION_TEXT\")?OPENSSL_VERSION_TEXT:\"no openssl extension\",\"\\n\";'" ;;
    dotnet.runtimes) tool=dotnet; cmd='dotnet --list-runtimes' ;;
    nginx.build) tool=nginx; cmd='nginx -V 2>&1' ;;
    apache.build) tool=sh; cmd='apache2ctl -V 2>/dev/null || httpd -V 2>/dev/null || apachectl -V 2>/dev/null' ;;
    haproxy.build) tool=haproxy; cmd='haproxy -vv' ;;
    postfix.tls) tool=postconf; cmd='postconf -n' ;;
    dovecot.ssl) tool=doveconf; cmd='doveconf -n' ;;
    samba.effective) tool=testparm; cmd='testparm -s 2>/dev/null' ;;
    bind.build) tool=named; cmd='named -V' ;;
    openvpn.version) tool=openvpn; cmd='openvpn --version | head -n 2' ;;
    ipsec.version) tool=sh; cmd='ipsec --version 2>/dev/null || swanctl --version 2>/dev/null' ;;
    wireguard.interfaces) tool=wg; cmd='wg show interfaces' ;;
    stunnel.version) tool=stunnel; cmd='stunnel -version 2>&1 | head -n 3' ;;
    cryptsetup.version) tool=cryptsetup; cmd='cryptsetup --version' ;;
    disk.encryption) tool=lsblk; cmd="lsblk -rno NAME,TYPE,FSTYPE,MOUNTPOINT | grep -iE 'crypt|luks'" ;;
    secure-boot) tool=sh; cmd="mokutil --sb-state 2>/dev/null || bootctl status 2>/dev/null | grep -i 'secure boot'" ;;
    *) return 127 ;;
  esac
}

# ---- capabilities ------------------------------------------------------------------------

cap_package() { # match
  if have dpkg-query; then
    printf 'fact\t%s\tpackage-manager\tdpkg\n' "$id"
    dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null |
      awk -F'\t' -v re="$p_match" -v id="$id" '$1 ~ /^ii/ && $2 ~ re { printf "fact\t%s\tpackage\tdpkg\t%s\t%s\t%s\n", id, $2, $3, $4 }'
  fi
  if have rpm && [ -n "$(rpm -qa 2>/dev/null | head -1)" ]; then
    printf 'fact\t%s\tpackage-manager\trpm\n' "$id"
    rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null |
      awk -F'\t' -v re="$p_match" -v id="$id" '$1 ~ re { printf "fact\t%s\tpackage\trpm\t%s\t%s\t%s\n", id, $1, $2, $3 }'
  fi
  if have apk; then
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
      \( -type d \( -name private -o -name private_keys -o -name keys -o -name keystore -o -name secrets -o -name .git -o -name wireguard \) -prune \) -o \
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

# emit_lines reads stdin and writes each matching line as a fact of the given kind and source,
# dropping anything that looks like key material and stopping at the signature's maximum.
emit_lines() { # kind source
  grep -E "${p_match:-.}" 2>/dev/null | grep -v -e 'PRIVATE KEY' -e 'BEGIN OPENSSH' -e 'BEGIN OpenVPN Static key' | head -n "${p_max:-50}" |
    while IFS= read -r l; do printf 'fact\t%s\t%s\t%s\t%s\n' "$id" "$1" "$(clean "$2")" "$(clean "$l" | cut -c1-1000)"; done
}

cap_lines() { # paths, match, max, join
  for pattern in $(printf '%s' "$p_paths" | tr '|' ' '); do
    for f in $pattern; do # the shell expands wildcards in the path
      [ -f "$f" ] && [ -r "$f" ] || continue
      keyfile "$f" && continue
      if [ "${p_join:-}" = backslash ]; then
        # java.security and friends continue a value on the next line with a trailing backslash.
        awk '{ if (sub(/\\[[:space:]]*$/, "")) { buf = buf $0; next } print buf $0; buf = "" } END { if (buf != "") print buf }' "$f" 2>/dev/null | emit_lines line "$f"
      else
        emit_lines line "$f" < "$f"
      fi
    done
  done
}

cap_query() { # query, match, max
  tool='' cmd=''
  if ! query_def "$p_query"; then
    printf 'skip\t%s\tquery %s is not in this engine\n' "$id" "$p_query"; return
  fi
  if ! have "$tool"; then
    printf 'skip\t%s\t%s is not installed\n' "$id" "$tool"; return
  fi
  if have timeout; then timeout -k 5 20 sh -c "$cmd" 2>/dev/null; else sh -c "$cmd" 2>/dev/null; fi | emit_lines query "$p_query"
}

cap_listeners() { # max
  if ! have ss; then printf 'skip\t%s\tss (iproute2) is not installed\n' "$id"; return; fi
  # ss prints one socket per line: netid, state, queues, local address:port, peer, and (for the
  # processes this account may see) users:(("name",pid=N,fd=M)). Root sees every process.
  ss -lntupH 2>/dev/null | awk '{
      proto = $1; local = $5
      i = match(local, /:[^:]*$/); addr = substr(local, 1, i - 1); port = substr(local, i + 1)
      pid = ""; if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
      printf "%s\t%s\t%s\t%s\n", proto, addr, port, pid }' | sort -u | head -n "${p_max:-500}" |
  while IFS="$TAB" read -r proto addr port pid; do
    name='' exe='' libs=''
    if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
      name=$(cat "/proc/$pid/comm" 2>/dev/null)
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null | sed 's/ (deleted)$//')
      # Only the names of mapped files are read from maps, and only library names are kept.
      libs=$(awk 'NF >= 6 { print $6 }' "/proc/$pid/maps" 2>/dev/null | grep -E "$CRYPTOLIB" | sed 's#.*/##' | sort -u | paste -sd, -)
    fi
    printf 'fact\t%s\tlistener\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$proto" "$(clean "$addr")" "$port" "$pid" "$(clean "$name")" "$(clean "$exe")" "$libs"
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
  printf 'cipherhorizon-machine-facts\t3\n'
  printf 'script\tlinux-sh\t%s\n' "$ENGINE_VERSION"
  printf 'host\tname\t%s\n' "$(clean "$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)")"
  printf 'host\tos\tlinux\n'
  printf 'host\tos-version\t%s\n' "$(clean "$(uname -sr 2>/dev/null)")"
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
    p_match='' p_paths='' p_dirs='' p_roots='' p_names='' p_depth='' p_max='' p_join='' p_query=''
    rest=$(printf '%s' "$sigline" | cut -f4-)
    oldifs=$IFS; IFS=$TAB; set -f
    for kv in $rest; do
      v=${kv#*=}
      case "$kv" in
        match=*) p_match=$v ;; paths=*) p_paths=$v ;; dirs=*) p_dirs=$v ;; roots=*) p_roots=$v ;;
        names=*) p_names=$v ;; depth=*) p_depth=$v ;; max=*) p_max=$v ;; join=*) p_join=$v ;; query=*) p_query=$v ;;
      esac
    done
    IFS=$oldifs; set +f
    case "$cap" in
      package) cap_package > "$tmp" ;;
      certfiles) cap_certfiles > "$tmp" ;;
      file) cap_file > "$tmp" ;;
      lines) cap_lines > "$tmp" ;;
      query) cap_query > "$tmp" ;;
      listeners) cap_listeners > "$tmp" ;;
      *) printf 'skip\t%s\tcapability %s is not in this engine\n' "$id" "$cap" > "$tmp" ;;
    esac
    cat "$tmp"
    printf 'ran\t%s\t%s\n' "$id" "$(grep -c '^fact' "$tmp")"
  done

  [ "$priv" = admin ] || printf 'note\tRan without root: files only root can read were not listed, the effective sshd policy could not be asked, and other users'"'"' processes show no executable or libraries.\n'
} > "$OUT"
rm -f "$tmp"

printf 'wrote %s (%s lines, %s facts)\n' "$OUT" "$(grep -c '' "$OUT")" "$(grep -c '^fact' "$OUT")" >&2
printf 'next: read it if you like (it is plain text), then upload it on the Inventory page of CipherHorizon.\n' >&2
