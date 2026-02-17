# Installation Guide — Power Meter for HA v1.0

## Prerequisites

Before you start, ensure you have:

- [ ] Home Assistant running (any install type: OS, Supervised, Container, Core)
- [ ] ESPHome add-on installed in HA (or standalone ESPHome)
- [ ] All hardware components assembled and wired (see `schematics/wiring_diagram.md`)
- [ ] ESP32-C6 connected to your computer via USB-C for first flash

---

## Part 1 — First Flash via USB

### 1. Install ESPHome Add-on (if not already)

In Home Assistant:
1. Go to **Settings → Add-ons → Add-on Store**
2. Search for **ESPHome**
3. Install and Start
4. Open the ESPHome Web UI

### 2. Create Your Secrets File

In ESPHome, open `secrets.yaml` (top-right menu) and add:

```yaml
wifi_ssid: "YourWiFiName"
wifi_password: "YourWiFiPassword"
api_encryption_key: "paste-your-32-byte-key-here"
ota_password: "choose-a-password"
ap_password: "fallback-ap-password"
```

**To generate an API key:**
- In ESPHome dashboard → click **+ New Device** → follow the wizard
- Copy the encryption key it generates
- Delete the wizard device — you'll use the YAML from this project instead

### 3. Add the Config File

1. In ESPHome dashboard, click **+ New Device**
2. Choose **Skip** (we'll paste our own config)
3. Click the new device's **Edit** button
4. Replace all content with the contents of `esphome/prepaid_power_monitor.yaml`
5. Click **Save**

### 4. Flash via USB

1. Click **Install** → **Plug into this computer**
2. ESPHome will compile (2–5 minutes first time)
3. Your browser will show a serial port selection dialog — select your ESP32-C6 port
4. Flash will begin — takes about 30 seconds
5. Device will reboot and connect to your WiFi

> 💡 If the port doesn't appear: hold the **BOOT** button on the ESP32-C6 while clicking Install

---

## Part 2 — Add to Home Assistant

Once the ESP32 is online, HA will auto-discover it:

1. Go to **Settings → Devices & Services**
2. You should see **ESPHome** with a new device notification
3. Click **Configure** → enter your API encryption key
4. Device is now fully integrated!

---

## Part 3 — Install Prepaid Electricity Tracker (Optional)

If you want the OLED display page 3 (showing prepaid balance & days remaining), install the companion package.

### 3a. Copy Package Files

Copy these files to your Home Assistant `/config` directory:
```
homeassistant/prepaid_electricity_tracker_v2.yaml
```

### 3b. Add Package Reference to configuration.yaml

```yaml
homeassistant:
  packages:
    prepaid_tracker: !include prepaid_electricity_tracker_v2.yaml
```

### 3c. Restart Home Assistant

**Settings → System → Restart**

### 3d. Set Your Initial Balance

1. Navigate to the Prepaid Electricity dashboard
2. Enter your current meter balance in the **Sync** field
3. Press **Sync Balance to Meter**

---

## Part 4 — Set Up the Dashboard

### Quick Option: Import Card Config

1. Go to your HA dashboard
2. Click **Edit** → **Add Card** → **Manual**
3. Paste cards from `homeassistant/prepaid_electricity_dashboard_v2.yaml`

### Recommended Dashboard Layout

```
Row 1: Three Gauges (Balance, Power, Days Left)
Row 2: Live Power Stats | Top-up & Sync
Row 3: Usage Statistics | Cost & Tariff
Row 4: Power History Graph (24h)
Row 5: Balance History Graph (7 days)
```

---

## Part 5 — CT Clamp Installation

> ⚠️ Read the safety notes in `schematics/wiring_diagram.md` before proceeding.

### Recommended Location

Install the CT clamp on the **grid incoming live wire**, before the main DB board. This measures ALL power consumed by your home.

### Steps

1. Locate your main incoming cable from the City Power meter to your DB board
2. Identify the **Live** (Active) wire — usually brown or red
3. Open the CT clamp by pressing the release button/tab
4. Pass the Live wire through the centre of the open clamp
5. Close the clamp firmly — it should click shut with no gap
6. Route the CT clamp cable back to your ESP32 enclosure

### Verify Installation

1. With CT clamp installed, check HA: `sensor.grid_power`
2. Turn on a known load (kettle, heater)
3. Power should jump up when load is on, and return to baseline when off
4. If reading stays at zero: check the clamp is closed and only one wire is through it

---

## Part 6 — Calibration

See `docs/calibration_guide.md` for full calibration instructions.

**Quick summary:**
1. Run a kettle or heater
2. Note the reading vs the appliance label wattage
3. Set **Current Calibration** = Label Watts ÷ Measured Watts
4. Done — no reflash needed

---

## Part 7 — Switch Prepaid Tracker Source

Once calibrated and running alongside your existing sensor for 24 hours:

1. In HA, go to your Prepaid Electricity dashboard
2. Open **Settings** card → **Grid Import Sensor**
3. Select `sensor.grid_energy_daily` (the ESP32 sensor)
4. Do a **Sync Balance** with your current physical meter reading

---

## OTA Updates (Future Updates)

All future firmware updates are wireless:

1. Make changes to the YAML in ESPHome dashboard
2. Click **Install** → **Wirelessly**
3. No USB cable needed

---

## Uninstalling

To remove the integration:
1. ESPHome dashboard → delete the device config
2. HA Settings → Devices & Services → ESPHome → remove the device
3. Remove the `packages:` line from `configuration.yaml` if added
