# Run the service

Open appsettings.json set the path to the windows sdk signtool.exe and modify the signtool options.

Open powershell and run:

```powershelll
$env:ASPNETCORE_URLS="http://+:5000"; .\TownSuite.CodeSigning.Service.exe
```

## Create and use a Self signed cert for the server

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/C=US/ST=State/L=City/O=YourOrganization/CN=YourName"


openssl pkcs12 -export -out certificate.pfx -inkey server.key -in server.crt
```

use the cert
```powershelll
$env:ASPNETCORE_URLS="http://+:5000;https://+:5001";$env:ASPNETCORE_Kestrel__Certificates__Default__Password="PLACEHOLDER"; $env:ASPNETCORE_Kestrel__Certificates__Default__Path: "/path/to/placeholder/certificate.pfx" .\TownSuite.CodeSigning.Service.exe
```

# curl example

```bash
curl --location 'https://localhost:7153/sign' \
--header 'Content-Type: application/x-msdownload' \
--data '@/C:/the/file/to/upload/and/sign.dll' \
-o output-signed-file.dll
```

# TownSuite.CodeSigning.Client examples

See ./TownSuite.CodeSigning.Client.exe -help for more information

## Single folder

Sign all matching files in one folder using `-folder` and `-file`.

```bash
./TownSuite.CodeSigning.Client -folder "/path/to/folder/with/assemblies" -file "*.dll;*.exe" -timeout 30000 -url "https://localhost:5000" -token "the token"
```

## Multiple folders with per-folder file lists

Each `-folders` entry pairs a folder path with its own file patterns separated by `|`. Files within are `;` separated. Can be specified multiple times.

Duplicate files across folders are detected by SHA-256 hash and only signed once. After signing, the signed copy is distributed to all duplicate locations.

```powershell
.\TownSuite.CodeSigning.Client.exe -folders "C:\publish\win-x64|*.dll;*.exe" -folders "C:\publish\linux-x64|mylib.dll;*.so" -timeout 30000 -url "https://localhost:5000" -token "the token"
```

## Recursive folder scan

Use `-rfolder` to recursively scan a parent folder and all its subdirectories for matching files. Same `folder|patterns` syntax as `-folders`. Can be specified multiple times.

This is useful in CI where multiple publish outputs (e.g. `win-x64/`, `linux-x64/`, `win-arm64/`) live under a common parent directory and may contain duplicate files.

```powershell
.\TownSuite.CodeSigning.Client.exe -rfolder "C:\publish|*.dll;*.exe" -timeout 30000 -url "https://localhost:5000" -token "the token"
```

Multiple recursive roots with different patterns:

```powershell
.\TownSuite.CodeSigning.Client.exe -rfolder "C:\publish|*.dll;*.exe" -rfolder "C:\other|mylib.dll" -timeout 30000 -url "https://localhost:5000" -token "the token"
```

## Combining options

All folder modes can be combined. Files from every source are merged, deduplicated by SHA-256, signed once, and the signed copy is copied back to all duplicate locations.

```powershell
.\TownSuite.CodeSigning.Client.exe -file "extra.dll" -folder "C:\extras" -folders "C:\publish\win-x64|*.dll;*.exe" -rfolder "C:\publish\shared|*.dll" -timeout 30000 -url "https://localhost:5000" -token "the token"
```


## Detached signing (zip/update package)

You can create a detached PKCS#7 (.sig) for an update package (zip). This is useful when your build server produces an update .zip that should be signed separately from the individual exe/dll code signing.

Client usage example (opt-in detached signing):

```powershell
.\TownSuite.CodeSigning.Client.exe -file "update-package.zip" -timeout 30000 -url "https://your-codesign-server:5000" -token "the token" -detached
```

The client will upload the zip as a batch and poll for result. When detached signing is requested the client will save the returned signature next to the original file as `update-package.zip.sig` instead of overwriting the zip.

Curl example (upload zip directly and save signature):

**Step 1**: submit batch signing request (returns an ID in the response)
```bash
curl --location 'https://localhost:7153/sign/batch' \
  --header 'Content-Type: application/zip' \
  --header 'X-Detached: true' \
  --header 'X-BatchId: PLACEHOLDER' \
  --header 'X-BatchReady: true' \
  --data-binary '@./update-package.zip'
```

**Step 2**: poll for the completed signature using the returned ID
# Replace <id-from-step-1> with the actual ID returned by Step 1

```bash
curl --location "https://localhost:7153/sign/batch?id=<id-returned-from-step-1>" \
  --header 'Content-Type: application/zip' \
  --header 'X-Detached: true' \
  --header 'X-BatchId: PLACEHOLDER'
```

Server behavior:
- The service parses your existing `SignToolOptions` to locate the certificate (sha1/subject or referenced PFX). If the configured signer uses a hardware token / CSP that is registered in the certificate store, the detached signer will use that key (no separate PFX required).
- The detached signature produced is a PKCS#7 detached signature suitable for verification by standard tools.

Recursive example (sign all zips under a parent folder)

```powershell
.\TownSuite.CodeSigning.Client.exe -rfolder "C:\builds|*.zip" -timeout 30000 -url "https://your-codesign-server:5000" -token "the token" -detached
```

Notes:
- `-rfolder "C:\builds|*.zip"` will recursively scan `C:\builds` and all subfolders for files matching `*.zip` and upload them for detached signing.
- The client will save a signature file next to each zip as `your-package.zip.sig` (it will not overwrite the original zip).
- Duplicate zip content across multiple folders is deduplicated by the client; signatures are created once and copied to duplicates.


# Health endpoints

| Endpoint | Checks | Use for |
|---|---|---|
| `/health/live` | Process is up and answering. | Liveness probe — restart the container when this fails. |
| `/health/ready` | Signing canary + signing queue is draining. | Readiness probe — pull the instance out of rotation when this fails. |
| `/healthz` | Both of the above. | Backwards compatible; kept for existing monitors. |

All three respond immediately. They read state from memory and never invoke `signtool`, touch the
filesystem, or call the timestamp server on the request path.

The readiness signing canary — which signs a throwaway PE file to prove the private key is still
usable — runs on a background timer instead, because `signtool` contacts the timestamp server and
takes seconds (up to `SigntoolTimeoutInMs`) or stalls outright. `HealthCheckCacheInMs` sets that
refresh interval (default 30s), so it controls how quickly a signing failure is *noticed*, not how
fast probes respond. Two consequences worth knowing:

- Before the first canary run finishes, readiness reports `Degraded` (HTTP 200) rather than failing
  a container that is merely still starting.
- If the canary result goes older than three refresh intervals the refresher has stopped, so
  readiness reports `Degraded` with a staleness message instead of a stale `Healthy`.

# Admin status dashboard

A browser dashboard is available at `/admin/` showing service uptime/version, signing queue depth/in-flight/completed/failed counts, worker health, concurrency slots, configured certificate expiry, and pending batch job folders. It polls `GET /admin/status`, which returns the same data as JSON for monitoring tools:

```bash
curl --location 'https://localhost:7153/admin/status'
```

**Anonymous by design**: both `/admin/` and `/admin/status` are reachable without a JWT, the same as `/healthz` and `/health/*`, even when JWT auth is enabled for `/sign*`. This is a deliberate trade-off for services running on a trusted internal network — the endpoint discloses machine name, queue counters, certificate subject/thumbprint/expiry, and the batch temp-folder path. If the service is exposed beyond a trusted network, put it behind a reverse proxy that restricts access to `/admin/*`.

To include certificate expiry in the dashboard, set these under `Settings` (and `Settings:OpenSSL` for the detached-signing cert) in `appsettings.json` — both are optional and skipped when empty:

```jsonc
"Settings": {
  "CertificatePath": "{BaseDirectory}testcert.pfx",
  "CertificatePassword": "password",
  "CertificateWarningDays": 30,
  "OpenSSL": {
    "SignerCertPath": "{BaseDirectory}testcert.crt"
  }
}
```

`CertificateWarningDays` controls when a certificate's status flips from `ok` to `warning` in the dashboard (default 30 days before expiry).

# Windows Defender Exclusion

For increased performance add the services working directory to the windows defender exclusion path.

**Important Note:**
- **Security Risks**: Be cautious when excluding directories from antivirus scans, as this can potentially expose your system to threats if malicious files are placed in these directories.


```powershell
Add-MpPreference -ExclusionPath "C:\Users\[USER]\AppData\Local\Temp\1\townsuite\codesigning"
```




# OpenSSL


## Definitions
### Certificate & Key Extensions
| Extension | 	Purpose |	Format/Encoding|
|---|---|---|
|.pem	| Generic container for any cryptographic data. |	Text-based (Base64). Starts with -----BEGIN....
|.crt	| Standard "Certificate" file. Common in Linux/Unix. | Usually PEM (text), but can be DER (binary).
|.cer	| Standard "Certificate" file. Common in Windows.	| Usually DER (binary), but can be PEM (text).
|.key	| Conventional name for a Private Key. | Usually PEM (text). Should be kept secret.

Key distinction: .crt and .cer are almost interchangeable; if one doesn't work, renaming the extension often fixes it unless the encoding (binary vs. text) is wrong for the application

### Signature Extensions
- `.p7s` (PKCS#7 Signature)
  - Standard: The formal extension for a PKCS#7/CMS detached signature.
- `.sig` (Generic Signature)
  - Standard: No single technical standard; it is a generic naming convention.



## create a cert for detached signatures


```bash
sudo apt install -y osslsigncode openssl libengine-pkcs11-openssl gnutls-bin xxd
```

- https://github.com/mtrojnar/osslsigncode/releases/download/2.13/osslsigncode-2.13-windows-x64-mingw.zip
`sha256:c6d3ec8f383a6ed204503a9d4445788f2d3e71da87f3604c42e40167ad9ceb8e`


- https://github.com/OpenSC/libp11/releases
- https://slproweb.com/products/Win32OpenSSL.html


### Create a Self-Signed Certificate 

- key is private, keep safe
- crt is for public verification, distribute widely

rsa example
```bash
openssl genrsa -aes256 -out server.key 4096
openssl req -x509 -nodes -key server.key -out server.crt -days 365 -subj "/C=US/ST=State/L=City/O=YourOrganization/CN=YourName"
```

mldsa65 example

```bash
openssl genpkey -aes256 -algorithm mldsa65 -out server.key
openssl req -x509 -nodes -key server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=YourOrganization/CN=YourName"
```


### create a detached signature

```bash
openssl cms -sign -in "{FilePath}" -signer "/path/to/server.crt" -inkey "/path/to/server.key" -keyform P12 -passin pass:password -out "{FilePath}.sig" -outform DER -md sha256 -binary
```

`-binary` is required. Without it OpenSSL treats the input as S/MIME text and rewrites every line
ending to CRLF before computing the digest, so the signature covers the canonicalized form rather
than the bytes on disk. That is OpenSSL behaviour, not OS behaviour - it happens identically on
Windows and Linux. It only goes unnoticed when the input already uses CRLF throughout; for LF text
and for any binary (zip, dll, exe, msi) the resulting `.sig` does not match the file being shipped.

`-binary` must be used on **both** sides. Signatures issued before this flag was added verify only
*without* `-binary`; signatures issued after it verify only *with* it.

### Timestamp a detached signature

```bash
osslsigncode add -t "http://timestamp.digicert.com" -in "{FilePath}.sig" -out "{FilePath}.timestamped.sig"
```

### Inspecting the signature

```bash
openssl pkcs7 -inform DER -in signature.sig -print_certs -text -noout
```


### extract private key and public cer from a pfx

#### extract unencrypted private key
```bash
openssl pkcs12 -in "server.pfx" -nocerts -nodes -out "server.key"
```

#### extract certificate(s) in PEM
```bash
openssl pkcs12 -in "server.pfx" -nokeys -out "server.cer"
```

### verify a zip file

```bash
openssl cms -verify -binary -inform DER -in archive.zip.sig -content archive.zip -CAfile server.cer > /dev/null
```

The `-binary` here must match the flag used at signing time (see above), otherwise the digest is
computed over differently canonicalized bytes and verification fails.

