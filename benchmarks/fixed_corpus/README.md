# Fixed whole-RAM corpus workflow

This workflow saves **replayable** QEMU ELF physical-memory images, unlike the earlier GitHub Actions studies that retained aggregate results only. It starts with synthetic loopback HTTP URLs in Tor Browser. There is no Tor circuit or onion service in this fixture. Keep the RAM, guest key, disk, full hit table, and target URLs in a private directory outside this repository until a content audit permits release.

## Guest and capture

Use an Ubuntu 24.04 Minimal AMD64 cloud image, QEMU x86-64, Tor Browser Linux x86-64, and its matching geckodriver. Verify the Ubuntu image against its published `SHA256SUMS` and verify Tor Browser and geckodriver detached signatures against the Tor Browser Developers key. Our first pilot used Tor Browser 16.0.1, Volatility 3 2.28.2, QEMU 11.1.3, two virtual CPUs, and 1536 MiB RAM. The [pilot report](../../docs/fixed-corpus-2026-11-16.md) records input hashes and observed results.

Create a fresh cloud-init user and **disposable, experiment-only** SSH key with a neutral comment. Boot a fresh QEMU overlay with a Unix QMP socket, guest SSH forwarded to localhost, and the `cidata` cloud-init seed. On macOS, use a short symlink for the QMP socket path; the full workspace path can exceed the Unix socket path limit. **Attach the seed as a virtio drive (`if=virtio`), not a CD-ROM**: the first clean-VM boot with a CD-ROM seed did not configure networking. Install the browser runtime libraries, Python venv, `selenium==4.38.0`, and `psutil==7.1.3` in the guest. Copy `guest_fixture.py` and `../local_socks.py` into the same guest directory alongside the verified browser and driver. The local SOCKS relay accepts only loopback HTTP destinations. Allow about 5 GiB of host scratch space for one 1.5 GiB ELF, its compressed archive, and the VM overlay.

The following QEMU command is the working Mac setup after creating a `cidata` seed containing `user-data` and `meta-data`, an Ubuntu-image-backed qcow2 overlay, and a short symlink to the private directory. Keep the signing key, SSH key, cloud-init files, and overlay outside this repository. Use a fresh overlay when changing the seed; cloud-init may treat an already booted overlay as initialized.

One way to create those files on macOS, after downloading and hashing the official Ubuntu cloud image, is:

```sh
CORPUS_DIR=/absolute/private/corpus
mkdir -p "$CORPUS_DIR/seed"
ssh-keygen -q -t ed25519 -N '' -C tor-corpus -f "$CORPUS_DIR/guest-key"
printf 'instance-id: tor-corpus-1\nlocal-hostname: tor-corpus-guest\n' \
  > "$CORPUS_DIR/seed/meta-data"
cat > "$CORPUS_DIR/seed/user-data" <<EOF
#cloud-config
users:
  - name: ubuntu
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$CORPUS_DIR/guest-key.pub")
ssh_pwauth: false
disable_root: true
EOF
hdiutil makehybrid -iso -joliet -default-volume-name cidata \
  -o "$CORPUS_DIR/seed.iso" "$CORPUS_DIR/seed"
qemu-img create -f qcow2 -F qcow2 \
  -b "$CORPUS_DIR/downloads/ubuntu-24.04-minimal-cloudimg-amd64.img" \
  "$CORPUS_DIR/guest.qcow2"
ln -s "$CORPUS_DIR" /private/tmp/tor-corpus
cd "$CORPUS_DIR"
```

```sh
qemu-system-x86_64 -machine q35,accel=tcg -cpu qemu64 -smp 2 -m 1536 \
  -drive file=guest.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.iso,if=virtio,format=raw,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2223-:22 \
  -device virtio-net-pci,netdev=net0 -display none -serial file:console.log \
  -qmp unix:/private/tmp/tor-corpus/qmp.sock,server=on,wait=off
```

On the first boot, pin the guest host key into the private known-hosts file before using `capture.py`:

```sh
ssh -i guest-key -o StrictHostKeyChecking=accept-new \
  -o UserKnownHostsFile=known_hosts -p 2223 ubuntu@127.0.0.1 'uname -r'
```

In the Ubuntu guest, install `python3-venv`, `libgtk-3-0`, `libdbus-glib-1-2`, `libasound2t64`, `libxt6`, `libx11-xcb1`, `libnss3`, `libatk-bridge2.0-0`, `libxcomposite1`, `libxdamage1`, `libxrandr2`, `libgbm1`, `libdrm2`, and `libxkbcommon0` with `apt-get install --no-install-recommends`. Extract the verified Tor Browser and geckodriver archives under the guest user's home. Create a guest venv and install the pinned Selenium and psutil versions. To generate symbols for the *running* kernel, use `/sys/kernel/btf/vmlinux` and `/boot/System.map-$(uname -r)` with btf2json 0.1.0:

```sh
./btf2json --btf vmlinux.btf --map System.map \
  --banner "$(cat /proc/version)" > current.json
xz -T0 current.json
```

Copy `current.json.xz` to the host's private `symbols/linux/` directory. Volatility 3 2.28.2 needs the BTF provenance pattern in `schema-6.2.0.json` extended as specified in [btf2json's Volatility patch instructions](https://github.com/vobst/btf2json#volatility-patch). The repository's [Linux whole-image workflow](../../.github/workflows/tor-whole-linux.yml) shows the exact schema edit. Use the exact guest kernel's symbols; a version string match alone is insufficient.

For each scenario, start a **new browser process** in the guest, with a distinct output directory:

```sh
python guest_fixture.py --scenario absent --replicate 1 \
  --browser /home/ubuntu/tor-browser/Browser/firefox \
  --driver /home/ubuntu/geckodriver \
  --output-dir /home/ubuntu/cases/absent-1
```

Choose `absent`, `link_only`, or `clicked`. The guest writes `ready.json` after checking the page, live browser PIDs, and its HTTP request count, then holds the browser open. Run the host capture script while `ready.json` exists:

```sh
python benchmarks/fixed_corpus/capture.py \
  --qmp /private/tmp/short-qmp-path/qmp.sock \
  --ssh-key PRIVATE/guest-key --known-hosts PRIVATE/known_hosts \
  --guest-dir /home/ubuntu/cases/absent-1 \
  --private-dir PRIVATE/cases/absent-1 \
  --symbols PRIVATE/symbols --vol PRIVATE/venv/bin/vol
```

The script hashes and verifies the HTTP journal before/after acquisition, runs `linux.pslist` and the TorSessionTrace Linux adapter over the recorded PIDs, stores their complete JSON output, compresses the ELF image, independently checks the restored SHA-256, writes `capture-manifest.json`, and then removes the uncompressed temporary copy. Failure leaves the raw image in place. If a local analysis or archive step fails after acquisition, use `--resume`; if analysis already passed, use `--resume --archive-only` with the same arguments. The first pilot required these recovery modes because of a cache-path error and low host disk space; the report discloses both.

## Replay

```sh
python benchmarks/fixed_corpus/replay.py \
  --case PRIVATE/cases/absent-1 \
  --symbols PRIVATE/symbols --vol PRIVATE/venv/bin/vol
```

Replay verifies the archive, ground truth, symbols, and source hashes, restores the exact ELF image, reruns Volatility, and compares stable scores and full process/hit JSON. It needs enough free scratch space for one uncompressed image. Keep each image's raw archive, manifest, HTTP journal, control record, and full analysis outputs together. Images from the same VM are distinct captures but should **not** be treated as independent host populations or pooled with the onion-service study.

## Release gate

Before distribution, inspect each whole-RAM image for guest keys, credentials, profile data, user identifiers, and unexpected process content. A simple string scan cannot prove an image is safe. If content is unsuitable, recapture with a cleaner guest; do not silently alter original bytes. Publish the exact image and symbol hashes, source revision, browser version, complete target/request ground truth, failures, and replay command alongside any approved archive. Until then, `private_pending_content_audit` means the image exists only in the author's private workspace.
