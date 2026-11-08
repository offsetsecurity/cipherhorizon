package machinefacts

import (
	"context"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Version 3 facts, as the Linux engine writes them on a Debian-family host with OpenSSL 3.5,
// OpenSSH 10 and nginx (PRD-019). Shaped on a real run; the values are a lab's.
const linuxV3Facts = `cipherhorizon-machine-facts	3
script	linux-sh	3.0.0
host	name	web-01
host	os	linux
host	os-version	Linux 6.18.3
host	privilege	admin
host	collected	2026-11-09T10:00:00Z
signatures	2026.11.09
fact	linux.platform.kernel	query	os.kernel	Linux 6.18.3-amd64 x86_64
ran	linux.platform.kernel	1
fact	linux.platform.fips	line	/proc/sys/crypto/fips_enabled	1
ran	linux.platform.fips	1
fact	linux.platform.cpu-crypto	query	cpu.crypto-flags	pclmulqdq aes rdrand sha_ni
ran	linux.platform.cpu-crypto	1
fact	linux.platform.tpm	line	/sys/class/tpm/tpm0/tpm_version_major	2
ran	linux.platform.tpm	1
fact	linux.platform.disk-encryption	query	disk.encryption	nvme0n1p3_crypt crypt ext4 /
ran	linux.platform.disk-encryption	1
fact	linux.platform.password-hashing	line	/etc/login.defs	ENCRYPT_METHOD YESCRYPT
fact	linux.platform.password-hashing	line	/etc/pam.d/common-password	password [success=1 default=ignore] pam_unix.so obscure yescrypt
ran	linux.platform.password-hashing	2
fact	linux.packages	package-manager	dpkg
fact	linux.packages	package	dpkg	openssl	3.5.5-1	amd64
fact	linux.packages	package	dpkg	nginx	1.28.3-2	amd64
ran	linux.packages	2
fact	linux.openssl.build	query	openssl.version	OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
fact	linux.openssl.build	query	openssl.version	built on: Tue Aug 18 11:56:34 2026 UTC
fact	linux.openssl.build	query	openssl.version	OPENSSLDIR: "/usr/lib/ssl"
fact	linux.openssl.build	query	openssl.version	MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"
ran	linux.openssl.build	4
fact	linux.openssl.providers	query	openssl.providers	Providers:
fact	linux.openssl.providers	query	openssl.providers	  default
fact	linux.openssl.providers	query	openssl.providers	    name: OpenSSL Default Provider
fact	linux.openssl.providers	query	openssl.providers	    version: 3.5.5
fact	linux.openssl.providers	query	openssl.providers	    status: active
ran	linux.openssl.providers	5
fact	linux.openssl.provider-modules	file	/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so	123456	0000000000000000000000000000000000000000000000000000000000000000
ran	linux.openssl.provider-modules	1
fact	linux.openssl.kem	query	openssl.kem-algorithms	  { 2.16.840.1.101.3.4.4.2, id-alg-ml-kem-768, ML-KEM-768, MLKEM768 } @ default
fact	linux.openssl.kem	query	openssl.kem-algorithms	  X25519MLKEM768 @ default
ran	linux.openssl.kem	2
fact	linux.openssl.signatures	query	openssl.signature-algorithms	  { 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65, MLDSA65 } @ default
fact	linux.openssl.signatures	query	openssl.signature-algorithms	  { 1.3.101.112, ED25519, Ed25519 } @ default
ran	linux.openssl.signatures	2
fact	linux.openssl.default-ciphers	query	openssl.ciphers	TLS_AES_256_GCM_SHA384         TLSv1.3 Kx=any      Au=any   Enc=AESGCM(256)            Mac=AEAD
fact	linux.openssl.default-ciphers	query	openssl.ciphers	ECDHE-ECDSA-AES256-GCM-SHA384  TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256)            Mac=AEAD
ran	linux.openssl.default-ciphers	2
fact	linux.openssl.defaults	line	/etc/ssl/openssl.cnf	openssl_conf = openssl_init
fact	linux.openssl.defaults	line	/etc/ssl/openssl.cnf	MinProtocol = TLSv1.2
ran	linux.openssl.defaults	2
fact	linux.gnutls.config	line	/etc/gnutls/config	disabled-version = tls1.0
ran	linux.gnutls.config	1
fact	linux.curl.build	query	curl.version	curl 8.18.0 (x86_64-pc-linux-gnu) libcurl/8.18.0 OpenSSL/3.5.5 zlib/1.3.1 libssh2/1.11.1 mit-krb5/1.22.1
ran	linux.curl.build	1
fact	linux.python.ssl	query	python.ssl	python 3.14.4 OpenSSL 3.5.5 27 Jan 2026
ran	linux.python.ssl	1
fact	linux.gpg.build	query	gpg.version	gpg (GnuPG) 2.4.8
fact	linux.gpg.build	query	gpg.version	libgcrypt 1.12.0
fact	linux.gpg.build	query	gpg.version	Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
fact	linux.gpg.build	query	gpg.version	Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
fact	linux.gpg.build	query	gpg.version	        CAMELLIA128, CAMELLIA192, CAMELLIA256
fact	linux.gpg.build	query	gpg.version	Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
ran	linux.gpg.build	6
fact	linux.ssh.version	query	ssh.version	OpenSSH_10.2p1 Debian-3, OpenSSL 3.5.5 27 Jan 2026
ran	linux.ssh.version	1
fact	linux.ssh.supported	query	ssh.algorithms	kex: diffie-hellman-group14-sha256 curve25519-sha256 sntrup761x25519-sha512 mlkem768x25519-sha256
fact	linux.ssh.supported	query	ssh.algorithms	cipher: aes256-gcm@openssh.com chacha20-poly1305@openssh.com
fact	linux.ssh.supported	query	ssh.algorithms	mac: hmac-sha2-256 umac-128-etm@openssh.com
fact	linux.ssh.supported	query	ssh.algorithms	key: ssh-ed25519 ssh-rsa ecdsa-sha2-nistp256
fact	linux.ssh.supported	query	ssh.algorithms	sig: ssh-ed25519 rsa-sha2-512
ran	linux.ssh.supported	5
fact	linux.ssh.server-config	line	/etc/ssh/sshd_config	Include /etc/ssh/sshd_config.d/*.conf
fact	linux.ssh.server-config	line	/etc/ssh/sshd_config	HostKey /etc/ssh/ssh_host_ed25519_key
ran	linux.ssh.server-config	2
fact	linux.ssh.server-effective	query	sshd.effective	kexalgorithms mlkem768x25519-sha256,curve25519-sha256
fact	linux.ssh.server-effective	query	sshd.effective	ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
fact	linux.ssh.server-effective	query	sshd.effective	hostkeyalgorithms ssh-ed25519,rsa-sha2-512
fact	linux.ssh.server-effective	query	sshd.effective	requiredrsasize 1024
fact	linux.ssh.server-effective	query	sshd.effective	hostkey /etc/ssh/ssh_host_rsa_key
ran	linux.ssh.server-effective	5
fact	linux.ssh.client-config	line	/etc/ssh/ssh_config	Host *
ran	linux.ssh.client-config	1
fact	linux.ssh.host-keys	line	/etc/ssh/ssh_host_ed25519_key.pub	ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGUqsIHNlk7JEVuvpt7n3vVUeDFPeJP83WkMDHvNeI26 root@web-01
fact	linux.ssh.host-keys	line	/etc/ssh/ssh_host_rsa_key.pub	ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDc root@web-01
ran	linux.ssh.host-keys	2
fact	linux.ssh.host-key-sizes	query	ssh.host-keys	256 SHA256:JIF9eNizGRMki+bOu+zx2jtFO2hjjDpnL3KKaUuWmkU root@web-01 (ED25519)
fact	linux.ssh.host-key-sizes	query	ssh.host-keys	3072 SHA256:nkF/+ewQhBpvsmretap1/3ulRDA3g09OYSMvLko2ngc root@web-01 (RSA)
ran	linux.ssh.host-key-sizes	2
fact	linux.nginx.tls	line	/etc/nginx/nginx.conf	 ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3 (POODLE), TLS 1.0, 1.1
fact	linux.nginx.tls	line	/etc/nginx/sites-enabled/web	    ssl_certificate /etc/letsencrypt/live/web.example/fullchain.pem;
fact	linux.nginx.tls	line	/etc/nginx/sites-enabled/web	    ssl_certificate_key /etc/letsencrypt/live/web.example/privkey.pem;
ran	linux.nginx.tls	3
fact	linux.nginx.build	query	nginx.build	nginx version: nginx/1.28.3
fact	linux.nginx.build	query	nginx.build	built with OpenSSL 3.5.5 27 Jan 2026
ran	linux.nginx.build	2
fact	linux.kerberos.config	line	/etc/krb5.conf	permitted_enctypes = aes256-cts-hmac-sha1-96 rc4-hmac
ran	linux.kerberos.config	1
fact	linux.openvpn.config	line	/etc/openvpn/server/office.conf	data-ciphers AES-256-GCM:CHACHA20-POLY1305
fact	linux.openvpn.config	line	/etc/openvpn/server/office.conf	tls-version-min 1.2
ran	linux.openvpn.config	2
fact	linux.ipsec.config	line	/etc/swanctl/swanctl.conf	            proposals = aes256gcm16-prfsha384-ecp384-ke1_mlkem768
ran	linux.ipsec.config	1
fact	linux.platform.kernel-crypto	line	/proc/crypto	name         : aes
fact	linux.platform.kernel-crypto	line	/proc/crypto	name         : sha256
fact	linux.platform.kernel-crypto	line	/proc/crypto	name         : crc32c
ran	linux.platform.kernel-crypto	3
fact	linux.bound.listeners	listener	tcp	0.0.0.0	443	197	nginx	/usr/sbin/nginx	libcrypto.so.3,libssl.so.3
fact	linux.bound.listeners	listener	tcp	0.0.0.0	443	198	nginx	/usr/sbin/nginx	libcrypto.so.3,libssl.so.3
fact	linux.bound.listeners	listener	tcp	[::]	22	1	systemd	/usr/lib/systemd/systemd	libcrypto.so.3
fact	linux.bound.listeners	listener	udp	127.0.0.1	323	241	chronyd	/usr/sbin/chronyd	libgnutls.so.30.41.1,libnettle.so.8.11
fact	linux.bound.listeners	listener	tcp	0.0.0.0	61264
fact	linux.bound.listeners	listener	tcp	0.0.0.0	9000	555	demo	/opt/demo/demo
ran	linux.bound.listeners	6
skip	linux.java.build	java is not installed
ran	linux.java.build	0
fact	linux.wireguard.interfaces	query	wireguard.interfaces	wg0
ran	linux.wireguard.interfaces	1
`

// The Windows engine on a workstation as a standard user, with the effective Schannel suites,
// TPM-held keys, authentication policy and the listening processes (PRD-019).
const windowsV3Facts = `cipherhorizon-machine-facts	3
script	windows-powershell	3.0.0
host	name	WS-01
host	os	windows
host	os-version	Microsoft Windows 11 Pro 10.0.26200
host	privilege	user
host	collected	2026-11-09T10:00:00Z
signatures	2026.11.09
fact	win.platform.role	query	host.role	domain-role: member workstation
fact	win.platform.role	query	host.role	part-of-domain: True
ran	win.platform.role	2
fact	win.platform.fips	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy	Enabled	0
ran	win.platform.fips	1
fact	win.platform.secure-boot	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State	UEFISecureBootEnabled	1
ran	win.platform.secure-boot	1
fact	win.platform.device-guard	query	deviceguard	vbs-status: 2
fact	win.platform.device-guard	query	deviceguard	services-running: 1,2
ran	win.platform.device-guard	2
fact	win.platform.tpm	query	tpm	present: not readable (no TPM, or Administrator rights are needed)
ran	win.platform.tpm	1
fact	win.platform.cng-providers	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers		Microsoft Platform Crypto Provider
fact	win.platform.cng-providers	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Providers		Microsoft Software Key Storage Provider
ran	win.platform.cng-providers	2
fact	win.schannel.protocols	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server	Enabled	0
ran	win.schannel.protocols	1
fact	win.schannel.effective	query	tls.cipher-suites	TLS_AES_256_GCM_SHA384
fact	win.schannel.effective	query	tls.cipher-suites	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
ran	win.schannel.effective	2
fact	win.schannel.effective-curves	query	tls.curves	curve25519
fact	win.schannel.effective-curves	query	tls.curves	NistP256
ran	win.schannel.effective-curves	2
fact	win.dotnet.framework	registry	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full	Release	533320
ran	win.dotnet.framework	1
fact	win.winhttp.tls	registry	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp	DefaultSecureProtocols	2560
ran	win.winhttp.tls	1
fact	win.auth.kerberos	registry	HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters	SupportedEncryptionTypes	28
ran	win.auth.kerberos	1
fact	win.auth.ntlm	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa	LmCompatibilityLevel	5
ran	win.auth.ntlm	1
fact	win.auth.rdp	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp	SecurityLayer	2
fact	win.auth.rdp	registry	HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp	UserAuthentication	1
ran	win.auth.rdp	2
fact	win.auth.smb-effective	query	smb.server	EnableSMB1Protocol: False
fact	win.auth.smb-effective	query	smb.server	RequireSecuritySignature: True
ran	win.auth.smb-effective	2
fact	win.key-providers	query	certstore.providers	My "Personal"
fact	win.key-providers	query	certstore.providers	================ Certificate 0 ================
fact	win.key-providers	query	certstore.providers	Subject: CN=ws-01.corp.example, O=Example
fact	win.key-providers	query	certstore.providers	Cert Hash(sha1): f37224444d09ce967019d2c335c9dacda28f4d25
fact	win.key-providers	query	certstore.providers	  Key Container = 0e051b7d-12f1-4d6e-87bb-b5417204f21a
fact	win.key-providers	query	certstore.providers	  Provider = Microsoft Platform Crypto Provider
fact	win.key-providers	query	certstore.providers	================ Certificate 1 ================
fact	win.key-providers	query	certstore.providers	Subject: CN=code-signing
fact	win.key-providers	query	certstore.providers	Cert Hash(sha1): 2c85c7f9d45bd0663e317f8d448ad05ea000115c
fact	win.key-providers	query	certstore.providers	  Provider = Microsoft Software Key Storage Provider
ran	win.key-providers	10
fact	win.bound.http-sslcert	query	http.sslcert	    IP:port                      : 0.0.0.0:443
fact	win.bound.http-sslcert	query	http.sslcert	    Certificate Hash             : f37224444d09ce967019d2c335c9dacda28f4d25
fact	win.bound.http-sslcert	query	http.sslcert	    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
fact	win.bound.http-sslcert	query	http.sslcert	    Certificate Store Name       : MY
ran	win.bound.http-sslcert	4
fact	win.ssh.supported	query	ssh.algorithms	kex: curve25519-sha256 mlkem768x25519-sha256
fact	win.ssh.supported	query	ssh.algorithms	version: 9.5.0.0 (file version of ssh.exe)
ran	win.ssh.supported	2
fact	win.runtimes	file	C:\Program Files\nodejs\node.exe	80000000	0000000000000000000000000000000000000000000000000000000000000000	22.11.0	Node.js
ran	win.runtimes	1
fact	win.java.security	line	C:\Program Files\Eclipse Adoptium\jdk-21.0.5.11-hotspot\conf\security\java.security	jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 1024
fact	win.java.security	line	C:\Program Files\Eclipse Adoptium\jdk-21.0.5.11-hotspot\conf\security\java.security	security.provider.1=SUN
ran	win.java.security	2
fact	win.bound.listeners	listener	tcp	0.0.0.0	443	4	System
fact	win.bound.listeners	listener	tcp	127.0.0.1	9416	12404	msedge	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	ncrypt.dll,rsaenh.dll
fact	win.bound.listeners	listener	tcp	127.0.0.1	9417	12405	msedge	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	ncrypt.dll,rsaenh.dll
fact	win.bound.listeners	listener	tcp	[::1]	42050	19448	OneDrive.Sync.Service	C:\Users\u\AppData\Local\Microsoft\OneDrive\OneDrive.Sync.Service.exe	libcrypto-3-x64.dll,libssl-3-x64.dll,schannel.DLL
fact	win.bound.listeners	listener	tcp	0.0.0.0	49664	1228	lsass
ran	win.bound.listeners	5
skip	win.platform.features	query failed: needs elevation
ran	win.platform.features	0
`

func propsOfComponent(c cdx.Component) map[string]string {
	m := map[string]string{}
	if c.Properties == nil {
		return m
	}
	for _, p := range *c.Properties {
		if _, dup := m[p.Name]; dup {
			m[p.Name] += " | " + p.Value
		} else {
			m[p.Name] = p.Value
		}
	}
	return m
}

func componentsByRef(bom *cdx.BOM) map[string]cdx.Component {
	out := map[string]cdx.Component{}
	if bom.Components == nil {
		return out
	}
	for _, c := range *bom.Components {
		out[c.BOMRef] = c
	}
	return out
}

func wantProp(t *testing.T, c cdx.Component, name, contains string) {
	t.Helper()
	v, ok := propsOfComponent(c)["cipherhorizon:"+name]
	if !ok || !strings.Contains(v, contains) {
		t.Errorf("%s: property %s = %q, want it to contain %q", c.Name, name, v, contains)
	}
}

// PRD-019 REQ-HI-3: version 3 facts from a Linux host become structured components: the
// platform record, the installed OpenSSL with its post-quantum algorithms, the installed OpenSSH's
// available and effective policies, host key sizes, server TLS configuration with its certificate,
// runtimes with their TLS backend, authentication and VPN algorithms, listening services with the
// libraries they loaded, and the kernel's algorithms.
func TestLinuxV3FactsBecomeStructuredComponents(t *testing.T) {
	f, err := Parse([]byte(linuxV3Facts))
	if err != nil {
		t.Fatal(err)
	}
	if f.Dropped != 0 {
		t.Errorf("dropped %d", f.Dropped)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	byRef := componentsByRef(bom)
	byName := components(bom)

	platform, ok := byRef["config/platform"]
	if !ok {
		t.Fatal("no platform record")
	}
	wantProp(t, platform, "platform:fips-mode", "on")
	wantProp(t, platform, "platform:kernel", "Linux 6.18.3")
	wantProp(t, platform, "platform:tpm", "TPM 2.0")
	wantProp(t, platform, "platform:disk-encryption", "nvme0n1p3_crypt")
	wantProp(t, platform, "platform:cpu-crypto", "aes")

	ossl, ok := byRef["software/openssl-installed"]
	if !ok || ossl.Version != "3.5.5" {
		t.Fatalf("OpenSSL (installed): %+v", ossl)
	}
	wantProp(t, ossl, "kem-algorithms", "ML-KEM-768")
	wantProp(t, ossl, "kem-algorithms", "X25519MLKEM768")
	wantProp(t, ossl, "signature-algorithms", "ML-DSA-65")
	wantProp(t, ossl, "providers", "default")
	wantProp(t, ossl, "provider-modules", "legacy.so")
	for _, want := range []string{"ML-KEM-768", "X25519MLKEM768", "ML-DSA-65", "Ed25519"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("algorithm %q the installed OpenSSL lists is not a component", want)
		}
	}
	defaults := byRef["config/protocol/openssl-defaults"]
	if defaults.CryptoProperties == nil || defaults.CryptoProperties.ProtocolProperties.CipherSuites == nil || len(*defaults.CryptoProperties.ProtocolProperties.CipherSuites) != 2 {
		t.Errorf("the OpenSSL defaults carry the default suites: %+v", defaults.CryptoProperties)
	}
	wantProp(t, defaults, "openssl:minprotocol", "TLSv1.2")

	avail := byRef["config/protocol/ssh-available"]
	wantProp(t, avail, "ssh:available:kex", "mlkem768x25519-sha256")
	eff := byRef["config/protocol/ssh-server-effective"]
	wantProp(t, eff, "ssh:kexalgorithms", "mlkem768x25519-sha256")
	wantProp(t, eff, "ssh:requiredrsasize", "1024")
	if _, ok := byName["X25519MLKEM768"]; !ok {
		t.Error("the hybrid key exchange the effective policy names is an algorithm component")
	}
	// HostKey lines are settings, never algorithm names.
	for name := range byName {
		if strings.HasPrefix(name, "/etc/ssh") {
			t.Errorf("a host key path became an algorithm: %q", name)
		}
	}
	rsaKey := byRef["config/ssh/host-key/ssh-rsa"]
	wantProp(t, rsaKey, "key-bits", "3072")
	wantProp(t, rsaKey, "fingerprint", "SHA256:")

	nginx := byRef["config/tls/linux.nginx.tls"]
	wantProp(t, nginx, "setting:ssl_protocols", "TLSv1.2 TLSv1.3")
	if v := propsOfComponent(nginx)["cipherhorizon:setting:ssl_protocols"]; strings.Contains(v, "#") {
		t.Errorf("a trailing comment stayed in the value: %q", v)
	}
	wantProp(t, nginx, "versions-named", "TLSv1.3")
	wantProp(t, nginx, "certificates", "fullchain.pem")
	if v := propsOfComponent(nginx)["cipherhorizon:certificates"]; strings.Contains(v, "privkey") {
		t.Errorf("a key file path is listed as a certificate: %q", v)
	}
	gnutls := byRef["config/tls/linux.gnutls.config"]
	wantProp(t, gnutls, "setting:disabled-version", "tls1.0")

	curl := byRef["software/runtime/curl.version"]
	if curl.Version != "8.18.0" {
		t.Errorf("curl version %q", curl.Version)
	}
	wantProp(t, curl, "crypto-backend", "OpenSSL 3.5.5")
	wantProp(t, byRef["software/runtime/python.ssl"], "crypto-backend", "OpenSSL 3.5.5")
	ssh := byRef["software/runtime/ssh.version"]
	if ssh.Version != "10.2p1" {
		t.Errorf("OpenSSH version %q", ssh.Version)
	}
	wantProp(t, ssh, "crypto-backend", "OpenSSL 3.5.5")
	ng := byRef["software/runtime/nginx.build"]
	if ng.Version != "1.28.3" {
		t.Errorf("nginx version %q", ng.Version)
	}
	wantProp(t, ng, "crypto-backend", "OpenSSL 3.5.5")
	gpg := byRef["software/runtime/gnupg"]
	wantProp(t, gpg, "crypto-backend", "libgcrypt 1.12.0")
	wantProp(t, gpg, "algorithms:cipher", "CAMELLIA256")
	for _, want := range []string{"IDEA", "CAST5", "Blowfish", "Twofish", "RIPEMD-160"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("GnuPG's %s is not a component", want)
		}
	}

	krb := byRef["config/auth/linux.kerberos.config"]
	wantProp(t, krb, "setting:permitted_enctypes", "rc4-hmac")
	if _, ok := byName["RC4"]; !ok {
		t.Error("RC4 from the Kerberos enctypes is an algorithm component")
	}
	pw := byRef["config/auth/linux.platform.password-hashing"]
	wantProp(t, pw, "setting:ENCRYPT_METHOD", "YESCRYPT")
	if _, ok := byName["yescrypt"]; !ok {
		t.Error("yescrypt is an algorithm component")
	}

	ovpn := byRef["config/vpn/linux.openvpn.config"]
	wantProp(t, ovpn, "setting:data-ciphers", "AES-256-GCM")
	wantProp(t, ovpn, "versions-named", "TLS 1.2")
	if _, ok := byName["ChaCha20-Poly1305"]; !ok {
		t.Error("ChaCha20-Poly1305 from OpenVPN is an algorithm component")
	}
	ipsec := byRef["config/vpn/linux.ipsec.config"]
	if ipsec.CryptoProperties == nil || ipsec.CryptoProperties.ProtocolProperties.Type != cdx.CryptoProtocolTypeIPSec {
		t.Error("the IPsec configuration is an IPsec protocol component")
	}
	wg := byRef["config/vpn/linux.wireguard.interfaces"]
	wantProp(t, wg, "interface", "wg0")

	nginxSvc, ok := byRef["service/nginx-nginx"]
	if !ok {
		t.Fatal("nginx is a listening service")
	}
	wantProp(t, nginxSvc, "pid", "197, 198")
	wantProp(t, nginxSvc, "process-count", "2")
	wantProp(t, nginxSvc, "listens", "tcp 0.0.0.0:443")
	wantProp(t, nginxSvc, "crypto-stack", "OpenSSL 3")
	wantProp(t, byRef["service/chronyd-chronyd"], "crypto-stack", "GnuTLS")
	wantProp(t, byRef["service/demo-demo"], "crypto-stack", "none seen")
	wantProp(t, byRef["service/unidentified"], "listens", "61264")

	kernel := byRef["config/platform/kernel-crypto"]
	wantProp(t, kernel, "algorithms", "aes, crc32c, sha256")
	wantProp(t, kernel, "algorithm-count", "3")

	props := metaProps(bom)
	for _, want := range []string{"sensor=linux.java.build status=complete scope=Java version and location: java is not installed", "signature-db=2026.11.09", "collected-by=inventory script linux-sh 3.0.0"} {
		if !strings.Contains(props, want) {
			t.Errorf("metadata lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(props), "private key-----") {
		t.Error("key material in the CBOM")
	}
}

// PRD-019 REQ-HI-3 on Windows: the effective Schannel suites and curves, platform facts in
// words, registry values translated (Kerberos enctypes, WinHTTP mask, RDP, .NET release), key
// providers with hardware-bound keys, HTTP.sys bindings, the Java policy, and processes merged.
func TestWindowsV3FactsBecomeStructuredComponents(t *testing.T) {
	f, err := Parse([]byte(windowsV3Facts))
	if err != nil {
		t.Fatal(err)
	}
	bom, err := ToCBOM(context.Background(), f, Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	byRef := componentsByRef(bom)
	byName := components(bom)

	platform := byRef["config/platform"]
	wantProp(t, platform, "platform:fips-mode", "off")
	wantProp(t, platform, "platform:secure-boot", "on")
	wantProp(t, platform, "platform:vbs:vbs-status", "running")
	wantProp(t, platform, "platform:vbs:services-running", "Credential Guard, HVCI")
	wantProp(t, platform, "platform:domain-role", "member workstation")
	wantProp(t, platform, "platform:tpm:present", "not readable")

	sch := byRef["config/protocol/windows-schannel"]
	if sch.CryptoProperties == nil || sch.CryptoProperties.ProtocolProperties.CipherSuites == nil || len(*sch.CryptoProperties.ProtocolProperties.CipherSuites) != 2 {
		t.Fatalf("Schannel carries the effective suites: %+v", sch)
	}
	wantProp(t, sch, "schannel:suite-order", "effective order")
	wantProp(t, sch, "schannel:curves-effective", "curve25519, NistP256")
	wantProp(t, sch, "schannel:protocols", "TLS 1.0 (server): disabled")

	wantProp(t, byRef["config/tls/win.winhttp.tls"], "setting:DefaultSecureProtocols", "TLS 1.1, TLS 1.2 (2560)")
	rdp := byRef["config/tls/win.auth.rdp"]
	wantProp(t, rdp, "setting:SecurityLayer", "TLS required")
	wantProp(t, rdp, "setting:UserAuthentication", "Network Level Authentication required")
	krb := byRef["config/auth/win.auth.kerberos"]
	wantProp(t, krb, "setting:SupportedEncryptionTypes", "rc4-hmac, aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96")
	if _, ok := byName["RC4"]; !ok {
		t.Error("RC4 from the Kerberos policy is an algorithm component")
	}
	wantProp(t, byRef["config/auth/win.auth.ntlm"], "setting:LmCompatibilityLevel", "5: send NTLMv2 only, refuse LM and NTLM")
	wantProp(t, byRef["config/auth/win.auth.smb-effective"], "setting:EnableSMB1Protocol", "False")

	dotnet := byRef["software/runtime/dotnet-framework"]
	if dotnet.Version != "4.8.1" {
		t.Errorf(".NET Framework release 533320 reads as %q", dotnet.Version)
	}
	node := byRef["software/runtime/c-program-files-nodejs-node.exe"]
	if node.Name != "Node.js" || node.Version != "22.11.0" {
		t.Errorf("node: %+v", node)
	}
	wantProp(t, node, "crypto-backend", "bundled OpenSSL")

	kp := byRef["config/pki/key-providers"]
	wantProp(t, kp, "hardware-bound-keys", "1")
	wantProp(t, kp, "provider-count", "Microsoft Platform Crypto Provider: 1")
	wantProp(t, kp, "key", "ws-01.corp.example → Microsoft Platform Crypto Provider")
	cng := byRef["config/pki/win.platform.cng-providers"]
	wantProp(t, cng, "hardware-providers", "Microsoft Platform Crypto Provider")

	bind := byRef["config/tls/bindings"]
	wantProp(t, bind, "binding", "0.0.0.0:443 → certificate f37224444d09ce967019d2c335c9dacda28f4d25 (store MY)")

	var java cdx.Component
	for ref, c := range byRef {
		if strings.HasPrefix(ref, "config/tls/java-") {
			java = c
		}
	}
	if !strings.Contains(java.Name, "jdk-21.0.5.11-hotspot") {
		t.Errorf("the Java policy is named after its JDK: %q", java.Name)
	}
	wantProp(t, java, "setting:jdk.tls.disabledAlgorithms", "TLSv1.1")
	wantProp(t, java, "setting:security.providers", "1=SUN")

	wantProp(t, byRef["config/protocol/ssh-available"], "ssh:available:kex", "mlkem768x25519-sha256")

	edge := byRef["service/msedge-msedge"]
	wantProp(t, edge, "process-count", "2")
	wantProp(t, edge, "crypto-stack", "CNG key storage, CAPI (legacy)")
	wantProp(t, byRef["service/onedrive.sync.service-onedrive.sync.service"], "crypto-stack", "OpenSSL 3")
	wantProp(t, byRef["service/onedrive.sync.service-onedrive.sync.service"], "crypto-stack", "Schannel")
	wantProp(t, byRef["service/lsass"], "crypto-stack", "not readable")

	props := metaProps(bom)
	if !strings.Contains(props, "sensor=win.platform.features status=complete scope=Windows optional features enabled: query failed: needs elevation") {
		t.Errorf("a skipped query is in the coverage:\n%s", props)
	}
}
