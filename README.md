# ne30x-app

**Independent applications for the NE30x device platform.**

`ne30x-app` provides applications, development tools, and packaging utilities for NE30x devices, starting with **NE301**.

Applications can be installed, updated, and managed independently without rebuilding the main firmware, provided the device has a compatible App Host.

**Device firmware:** [camthink-ai/ne301 `app-host` branch](https://github.com/camthink-ai/ne301/tree/app-host)

## Applications

### Line Crossing

An AI-powered line-crossing application featuring:

- Real-time IN/OUT counting
- Configurable counting lines and detection settings
- Live video, statistics, and crossing events
- Persistent configuration and cumulative counts
- MQTT and Webhook reporting
- Integrated web interface

## Repository Structure

```text
apps/       Application source code and Web UI
package/    NEAPP packaging, verification, and release utilities
tests/      Current application, runtime, and package tests
.github/    CI workflows
```

## Build and Package

### Requirements

- Python 3.12
- Node.js 22 and pnpm 11.5.2
- ARM GNU Toolchain (`arm-none-eabi-gcc`)
- GNU Make

### 1. Clone

```bash
git clone https://github.com/camthink-ai/ne30x-app.git
cd ne30x-app
```

### 2. Build the Web UI

```bash
pnpm --dir tests/line-crossing-ui install \
  --frozen-lockfile --ignore-scripts

npm ci \
  --prefix tests/line-crossing-ui/browser-runner \
  --ignore-scripts

node tests/line-crossing-ui/browser-runner/build.mjs
```

### 3. Build and Package the App

```bash
make -C apps/line-crossing/app clean-v4
make -C apps/line-crossing/app elf-v4
make -C apps/line-crossing/app neapp-v5
```

Or run the whole chain (Web UI, ELF, package, independent verification,
checksums, and provenance metadata) with one command:

```bash
bash package/release/build_neapp.sh
```

**Output:**

```text
apps/line-crossing/app/build/pkg/line-crossing-<product-version>.neapp
apps/line-crossing/app/build/pkg/line-crossing-<product-version>.neapp.sha256
apps/line-crossing/app/build/pkg/line-crossing-<product-version>.neapp.provenance.json
apps/line-crossing/app/build/pkg/line-crossing-<product-version>.verification.json
apps/line-crossing/app/build/pkg/line-crossing-<product-version>.oldhost-gate.json
apps/line-crossing/app/build/pkg/candidate.json
```

The user-facing package file name uses the **product version** (Makefile
default `V5_PRODUCT_VERSION`, e.g. `1.0.2`), which is the only version line
shown to users. The internal Native and UI component versions (Makefile
defaults `V4_APP_VERSION`, `V5_UI_VERSION`) keep increasing independently for
diagnostics and device upgrade checks; they are recorded in the package
provenance and are not the repository release version. Product-version
packages carry the trusted carrier asset `product-version.json` inside the
UI asset tree and require the `CAP_PRODUCT_VERSION` gate bit (`0x400`, see
`required_host_caps`), so Hosts that predate product metadata refuse the
package before install; the build records that refusal as
`*.oldhost-gate.json`.

### 4. Verify

```bash
# Simulating the current (pre-product-metadata) Host: refused.
python3 package/unsigned/neapp_verify_v5.py \
  --package apps/line-crossing/app/build/pkg/line-crossing-<product-version>.neapp \
  --compact

# Simulating a product-version-capable Host (0x7ff = 0x3ff | 0x400): PASS.
python3 package/unsigned/neapp_verify_v5.py \
  --package apps/line-crossing/app/build/pkg/line-crossing-<product-version>.neapp \
  --host-caps-hex 0x7ff --compact
```

A successful verification returns `PASS` and reports `product_version`.

## Testing

```bash
# Line Crossing algorithm
bash tests/line-crossing/run_tests.sh

# Current native application and ABI v4 tests
bash tests/line-crossing-app/run_tests.sh

# Package verification
python3 -m unittest discover -s tests/unsigned -v

# Web UI and runtime
pnpm --dir tests/line-crossing-ui test
```

UI tests require prepared dependencies and browser-testing tools. Automated tests do not replace real-device validation.

## Packaging and Releases

Applications use the **NEAPP** package format, combining native code and Web UI into one `.neapp` file. The current container format is **v5**.

Current NEAPP container v5 packages are unsigned. Checksums verify file integrity, while installation permissions are enforced by the device.

The standard delivery workflow is:

**Build → Test → Package → Verify → Release Notes → Archive**

Every PR and `main` CI run builds the production candidate with
`package/release/build_neapp.sh`, independently verifies it, and uploads the
real `.neapp` as a downloadable CI artifact named
`neapp-ci-candidate-*` together with its SHA-256, provenance metadata, and
verification report. CI artifacts are candidates, not official releases.

Releases run through **Actions → Release App → Run workflow** with a single
input `vX.Y.Z`. The workflow validates the version strictly, requires it to
match the packaged product version line, fails closed on any existing
tag/release/draft conflict, builds and verifies the package, generates
English release notes (changes, package identity with the product version as
the only user-facing version line — internal native/UI versions stay in the
attached provenance file — compatibility, verification results, known
limitations), and creates an **unpublished draft release** carrying the
`.neapp`, SHA-256, provenance, and verification attachments. The workflow
never publishes.

Publishing a draft is a separate, per-version human action after explicit
User Release GO. Existing tags and release assets are never overwritten.
Current pipeline limitations are listed in
[package/release/known-limitations.md](package/release/known-limitations.md).

## Installation

On a compatible NE301 device:

1. Open the CamThink Web management interface.
2. Install the `.neapp` file through App management.
3. Start the application and open its interface from App Status.

Applications can be stopped, updated, or uninstalled through the device's management interface.

## Contributing

Submit changes through Pull Requests. Run relevant tests and document changes affecting functionality, compatibility, or packaging.
