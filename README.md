# ne30x-app

**Independent applications for the NE30x device platform.**

`ne30x-app` provides applications, development tools, and packaging utilities for NE30x devices, starting with **NE301**.

Applications can be installed, updated, and managed independently without rebuilding the main firmware, provided the device has a compatible App Host.

**Device firmware:** [camthink-ai/ne301](https://github.com/camthink-ai/ne301)

## Applications

### Line Crossing

An AI-powered line-crossing application featuring:

- Real-time IN/OUT counting
- Configurable counting lines and detection settings
- Live video, statistics, and crossing events
- Persistent configuration and cumulative counts
- MQTT and Webhook reporting
- Integrated web interface

### Hello App

A minimal example of a standalone native NE301 application.

## Repository Structure

```text
apps/       Application source code and Web UI
package/    .neapp packaging and verification
tests/      Automated tests
tools/      Development utilities
docs/       Technical documentation
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
git clone https://github.com/harryhua-ai/ne30x-app.git
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
apps/line-crossing/app/build/pkg/line-crossing-<version>.neapp
apps/line-crossing/app/build/pkg/line-crossing-<version>.neapp.sha256
apps/line-crossing/app/build/pkg/line-crossing-<version>.neapp.provenance.json
apps/line-crossing/app/build/pkg/line-crossing-<version>.verification.json
apps/line-crossing/app/build/pkg/candidate.json
```

Packaged versions follow the Makefile defaults (`V4_APP_VERSION`,
`V5_UI_VERSION`). They are recorded separately in the package provenance;
they are not the repository release version.

### 4. Verify

```bash
python3 package/unsigned/neapp_verify_v5.py \
  --package apps/line-crossing/app/build/pkg/line-crossing-<version>.neapp \
  --compact
```

A successful verification returns `PASS`.

## Testing

```bash
# Line Crossing algorithm
bash tests/line-crossing/run_tests.sh

# Native application
bash tests/line-crossing-app/run_tests.sh

# Package verification
python3 -m unittest discover -s tests/unsigned -v

# Web UI and runtime
pnpm --dir tests/line-crossing-ui test
```

UI tests require prepared dependencies and browser-testing tools. Automated tests do not replace real-device validation.

## Packaging and Releases

Applications use the **NEAPP05** format, combining native code and Web UI into one `.neapp` file.

NEAPP05 packages are unsigned. Checksums verify file integrity, while installation permissions are enforced by the device.

The standard delivery workflow is:

**Build → Test → Package → Verify → Release Notes → Archive**

Every PR and `main` CI run builds the production candidate with
`package/release/build_neapp.sh`, independently verifies it, and uploads the
real `.neapp` as a downloadable CI artifact named
`neapp-ci-candidate-*` together with its SHA-256, provenance metadata, and
verification report. CI artifacts are candidates, not official releases.

Releases run through **Actions → Release App → Run workflow** with a single
input `vX.Y.Z`. The workflow validates the version strictly, fails closed on
any existing tag/release/draft conflict, builds and verifies the package,
generates English release notes (changes, package identity with repository
version and packaged native/UI versions recorded separately, compatibility,
verification results, known limitations), and creates an **unpublished draft
release** carrying the `.neapp`, SHA-256, provenance, and verification
attachments. The workflow never publishes.

Publishing a draft is a separate, per-version human action after explicit
User Release GO. The first official release version has not been approved
yet. Current pipeline limitations are listed in
[docs/release-known-limitations.md](docs/release-known-limitations.md).

## Installation

On a compatible NE301 device:

1. Open the CamThink Web management interface.
2. Install the `.neapp` file through App management.
3. Start the application and open its interface from App Status.

Applications can be stopped, updated, or uninstalled through the device's management interface.

## Contributing

Submit changes through Pull Requests. Run relevant tests and document changes affecting functionality, compatibility, or packaging.
