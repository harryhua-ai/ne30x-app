# ne30x-app

**Independent applications for the NE30x device platform.**

`ne30x-app` provides applications, development tools, and packaging utilities for NE30x devices, starting with **NE301**.

Applications can be installed, updated, and managed independently without rebuilding the main firmware, provided the device has a compatible App Host.

**Device firmware:** [ne301](https://github.com/harryhua-ai/ne301)

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

make -C apps/line-crossing/app elf-v4 \
  V4_APP_VERSION=4.0.0

make -C apps/line-crossing/app neapp-v5 \
  V4_APP_VERSION=4.0.0 \
  V5_UI_VERSION=1.1.1
```

**Output:**

```text
apps/line-crossing/app/build/pkg/line-crossing-4.0.0.neapp
```

Versions above are build examples, not the latest official release.

### 4. Verify

```bash
python3 package/unsigned/neapp_verify_v5.py \
  --package apps/line-crossing/app/build/pkg/line-crossing-4.0.0.neapp \
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

Expected release artifacts:

```text
line-crossing-X.Y.Z.neapp
line-crossing-X.Y.Z.neapp.sha256
line-crossing-X.Y.Z.neapp.provenance.json
verification.json
RELEASE_NOTES.md
```

Release Notes should summarize features, fixes, compatibility, known issues, and verification results.

Package generation and verification are available. Automated Release Notes and installable CI artifact distribution are still to be implemented. Official GitHub Releases require separate approval.

## Installation

On a compatible NE301 device:

1. Open the CamThink Web management interface.
2. Install the `.neapp` file through App management.
3. Start the application and open its interface from App Status.

Applications can be stopped, updated, or uninstalled through the device's management interface.

## Contributing

Submit changes through Pull Requests. Run relevant tests and document changes affecting functionality, compatibility, or packaging.
