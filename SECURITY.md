# Security Policy
Vx.0=Vx.6/Vx.8 (eg:V1.0=V1.6/V1.8)
Vx.x0=Vx.x6/Vx.x8 (eg:V1.20=V1.26/V1.28)
Vx.30=Vx.32 (eg:V3.30=V3.32)
Product Overview
## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

Use this section to tell people how to report a vulnerability.

Tell them where to go, how often they can expect to get an update on a
reported vulnerability, what to expect if the vulnerability is accepted or
declined, etc.

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories
(the **Security → Advisories** tab of this repository) or by encrypted email to
the maintainer key below. Do not open public issues for security reports.

## Verifying Releases

Release artifacts are published with a `SHA256SUMS.txt` manifest and a detached
PGP signature `SHA256SUMS.txt.asc` produced by the maintainer release key.

1. Import the release-signing key:

   ```sh
   gpg --keyserver hkps://keys.openpgp.org --recv-keys "777F E81F 8CC0 77FD 3D08  055E 852C 2B31 90F5 B928"
   ```

2. Verify the manifest signature:

   ```sh
   gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
   ```

   Confirm the "Good signature" is from the fingerprint below.

3. Verify a downloaded artifact against the manifest:

   ```sh
   sha256sum --check --ignore-missing SHA256SUMS.txt
   ```

If `SHA256SUMS.txt.asc` is absent from a release, that release was published
unsigned (the signing key was not configured in CI) — treat it with caution.

## Release-Signing Key

| Name | Fingerprint |
|------|-------------|
| defenwycke | `777F E81F 8CC0 77FD 3D08  055E 852C 2B31 90F5 B928` |

(Key id `852C2B3190F5B928`, ed25519.)
