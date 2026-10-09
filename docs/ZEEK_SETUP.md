# Zeek sensor setup

ThreatFusion analyzes **completed Zeek logs**. It does not capture packets
itself. This guide sets up a small Zeek sensor whose logs the collector can read.
The recipe below (Docker, pinned Zeek 8.0.6, one interface) is the one used for
the project's own real-traffic test; options marked *not yet validated* have
not been run end to end.

## 1. Decide what the sensor can see

Zeek only sees packets that pass through the interface it listens on.

| Placement | What is visible | Needs | Status |
| --- | --- | --- | --- |
| This computer's own interface | This computer's traffic only (a Wi-Fi card in normal mode never sees other devices) | Nothing extra | Validated |
| This computer as gateway for a wired PC | That PC's traffic on the shared Ethernet port | Ethernet cable, NetworkManager connection sharing | Not yet validated |
| This computer's Wi-Fi hotspot | Devices you join to the hotspot | A Wi-Fi card that supports AP mode alongside client mode | Not yet validated |
| Whole network | Every device | Router/switch port mirroring, or an OpenWrt router | Not yet validated |

Monitor only networks and devices you own or are allowed to monitor. If other
people's devices are visible, ask them first.

## 2. Run Zeek

Requirements: Docker, and the right to capture packets. Membership of the
`docker` group is equivalent to root on that machine.

Find the interface name (for example `wlp63s0` for Wi-Fi or `enp64s0` for
Ethernet):

```bash
ip -br link
```

Create a private folder and a Zeek script that writes **only connection and DNS
logs**, as tab-separated text, rotated every hour:

```bash
mkdir -m 700 -p ~/zeek-sensor/logs
cat > ~/zeek-sensor/threatfusion.zeek <<'EOF'
@load base/protocols/conn
@load base/protocols/dns
redef LogAscii::use_json = F;
redef Log::default_rotation_interval = 1 hr;
EOF
```

Start Zeek (replace `wlp63s0` with your interface):

```bash
docker run -d --name tf-zeek --restart unless-stopped --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v ~/zeek-sensor:/w -w /w/logs \
  zeek/zeek@sha256:f0582e7ba4a81fb55145fc03eddb6aefe70dbceee1d47df69f9bb781be952f6d \
  zeek -b -C -i wlp63s0 /w/threatfusion.zeek
```

- `-b` loads only the two scripts above: no HTTP, TLS, certificate or file logs.
- `-C` ignores checksums; a computer capturing its own outgoing packets usually
  sees invalid checksums because the network card computes them later.
- Hourly rotation matters. The collector imports a log only after Zeek closes it
  (the last line starts with `#close`). Without rotation, Zeek keeps writing one
  file and nothing is imported until Zeek stops.

Stop Zeek with `docker stop tf-zeek`; it closes and rotates its open files.

## 3. Check the logs

After the first full hour, the folder holds rotated files:

```bash
ls ~/zeek-sensor/logs          # conn.2026-10-10-02-00-00.log, dns.….log, conn.log (still open)
tail -n 1 ~/zeek-sensor/logs/conn.2026-*.log | head   # each closed file ends with #close
```

The open `conn.log` / `dns.log` are skipped until rotation.

## 4. Connect ThreatFusion

```bash
threatfusion-ai collect --input-dir ~/zeek-sensor/logs
```

Open the app and choose **Collected connections**. Details are in the
[user guide](USER_GUIDE.md#collector).

## What is recorded, and privacy

- `conn.log`: which device connected to which IP and port, when, for how long
  and how many bytes. No content.
- `dns.log`: which names were looked up and the answers. This is effectively a
  list of the sites you visited (names, not pages).
- Encrypted content (HTTPS) is not visible: passwords, page addresses and form
  contents are never recorded.
- Logs stay in your private folder. Do not commit, upload or share them.

## Encrypted DNS hides names

If the system or browser sends DNS encrypted (DNS-over-TLS or DNS-over-HTTPS),
`dns.log` stays nearly empty and the DNS queue has nothing to show. Connection
analysis still works. To check the system resolver:

```bash
resolvectl status | grep -E "Current DNS|DNSOverTLS"
```

`DNSOverTLS=yes` or `opportunistic` with a resolver that supports it means
system DNS is encrypted. Changing it is a privacy trade-off; ThreatFusion does
not require it.

## Laptops: sleep creates gaps

A sleeping or shut-down sensor records nothing. Empty hours are coverage gaps,
not proof of a quiet network. To keep a laptop awake while capturing:

```bash
systemd-inhibit --what=sleep:idle --why="Zeek capture" sleep infinity
```

Closing the lid may still suspend the machine, depending on its settings.
