# ⚡ Power Meter for Home Assistant v1.0

A DIY, accurate, local-first prepaid electricity power meter for Home Assistant using an ESP32-C6, a CT clamp, and a 0.91" OLED display. Designed specifically for South African City Power / prepaid electricity setups, but adaptable for any single-phase grid.

![Power Meter](docs/images/banner.png)

---

## 🎯 Why This Project?

Commercial smart plugs and inverter CT clamps (like the Sonoff ZJSB9-80) can accumulate significant measurement errors over time. This project was born from a **200 kWh/month discrepancy** found in an existing monitoring setup — costing real money on a prepaid meter.

This solution gives you:
- ✅ Full local control — no cloud dependency
- ✅ Adjustable calibration
- ✅ Real-time OLED display
- ✅ Deep Home Assistant integration
- ✅ Works alongside the [Prepaid Electricity Tracker](https://github.com/your-repo/prepaid-electricity-tracker)

---

## 📷 Features

| Feature | Detail |
|---|---|
| **Real-time power** | Live watts, amps on OLED and HA |
| **Daily energy** | kWh accumulation, resets midnight |
| **Total energy** | Lifetime kWh counter |
| **Calibration** | Adjustable from HA UI |
| **OLED Display** | 3-page cycling: Power / Usage / Balance |
| **HA Integration** | Full ESPHome native API |
| **Prepaid Tracker** | Pulls balance & days remaining to display |
| **WiFi Fallback** | Hotspot if WiFi drops |
| **OTA Updates** | Update firmware wirelessly |

---

## 🛒 Parts List

| Component | Specification | Source |
|---|---|---|
| **Microcontroller** | ESP32-C6 (any variant) | Communica / Micro-Tech |
| **CT Clamp** | SCTD-016-T 100A / 0-5VDC | Livestainable |
| **OLED Display** | 0.91" SSD1306 I2C 128x32 | Communica / AliExpress |
| **Resistors** | 2x 10kΩ ¼W (part: CFR25J-10K) | Communica |
| **Breadboard** | 400-point mini | Communica |
| **Jumper Wires** | Mixed M-M / M-F pack | Communica |
| **Project Box** | Small ABS enclosure | Communica / hardware store |

**Estimated total cost: R500–R700**

> ⚠️ The SCTD-016-T has a **0-5VDC voltage output** (built-in burden resistor). Do NOT use a current-output CT clamp with this circuit without modification.

---

## 🔌 Wiring Diagram

```
SCTD-016-T CT Clamp          ESP32-C6
───────────────────          ────────
 + (Signal) ──┬── 10kΩ ───► GPIO2
              │
            10kΩ
              │
 - (GND) ─────┴──────────►  GND


0.91" OLED Display           ESP32-C6
──────────────────           ────────
 GND  ──────────────────────► GND
 VCC  ──────────────────────► 3.3V   ⚠️ NOT 5V!
 SCK  ──────────────────────► GPIO7  (I2C Clock)
 SDA  ──────────────────────► GPIO6  (I2C Data)
```

### Voltage Divider Explanation

The CT clamp outputs 0–5V but the ESP32-C6 ADC safely reads only 0–3.3V.
The two 10kΩ resistors form a voltage divider that scales 5V → 2.5V max.
The ESPHome config compensates by multiplying the reading back by 2.

```
CT (+) ──── 10kΩ ──┬──── GPIO2 (ADC)
                   │
                 10kΩ
                   │
CT (-) ────────────┴──── GND
```

---

## 📌 ESP32-C6 Pin Reference

| Pin | Function | Notes |
|---|---|---|
| GPIO2 | CT Clamp ADC | ADC1_CH2 — WiFi-safe |
| GPIO6 | OLED SDA | I2C Data |
| GPIO7 | OLED SCK/SCL | I2C Clock |
| 3.3V | OLED Power | Do NOT use 5V |
| GND | Common Ground | |

> ⚠️ **ESP32-C6 specific notes:**
> - Requires `esp-idf` framework (Arduino framework NOT supported)
> - ADC pins are GPIO0–GPIO6 only (unlike classic ESP32)
> - GPIO8 = onboard RGB LED — do not use
> - Avoid strapping pins: GPIO4, GPIO5, GPIO8, GPIO9, GPIO15

---

## 💾 ESPHome Setup

### 1. Prerequisites

- [Home Assistant](https://www.home-assistant.io/) installed
- [ESPHome Add-on](https://esphome.io/guides/getting_started_hassio) installed in HA
- ESP32-C6 board connected via USB for first flash

### 2. Secrets File

Create or edit your ESPHome `secrets.yaml`:

```yaml
wifi_ssid: "YourWiFiName"
wifi_password: "YourWiFiPassword"
api_encryption_key: "your-32-byte-base64-key-here"
ota_password: "your-ota-password"
ap_password: "fallback-ap-password"
```

> Generate an API key: ESPHome dashboard → New Device → copy the key shown

### 3. Flash the Device

1. Copy `esphome/prepaid_power_monitor.yaml` to your ESPHome config folder
2. In ESPHome dashboard, click **Install** → **Plug into this computer**
3. After first flash, all future updates can be done **OTA wirelessly**

---

## 🎛️ Calibration

Calibration is done entirely from the Home Assistant UI — no reflashing needed.

### Step 1: Find a Known Load

Use a **pure resistive load** for best accuracy:
- Electric kettle (2000–3000W) ✅ ideal
- Toaster
- Incandescent light bulb

### Step 2: Calculate Your Factor

```
Calibration Factor = Rated Watts (from label) ÷ Measured Watts (from HA)

Example:
  Kettle label:   2760W (Russell Hobbs 2520-3000W at 230V midpoint)
  HA reading:     2625W
  Factor:         2760 ÷ 2625 = 1.051
```

### Step 3: Set in Home Assistant

Navigate to your ESP32 device in HA → find **Current Calibration** → enter your value.

### Step 4: Verify

Run the kettle again. Reading should now match the label within 1–2%.

### Reference Loads for SA (at 230V)

| Appliance | Expected Current | Expected Power |
|---|---|---|
| 2400W Kettle | 10.4A | 2400W |
| 2760W Kettle | 12.0A | 2760W |
| 3000W Geyser | 13.0A | 3000W |
| 2000W Heater | 8.7A | 2000W |
| 100W Bulb | 0.43A | 100W |

---

## 🏠 Home Assistant Integration

### Sensors Exposed to HA

| Entity | Description |
|---|---|
| `sensor.grid_power` | Real-time watts |
| `sensor.grid_current` | Real-time amps |
| `sensor.grid_energy_daily` | Today's kWh (resets midnight) |
| `sensor.grid_energy_total` | Lifetime kWh |
| `sensor.ct_voltage_raw` | Raw CT voltage (for diagnostics) |
| `sensor.daily_cost` | Today's cost in Rand |
| `sensor.wifi_signal` | WiFi RSSI |
| `sensor.uptime` | Device uptime |

### Controls in HA

| Entity | Description |
|---|---|
| `number.current_calibration` | Calibration multiplier (0.5–1.5) |
| `number.voltage_setpoint` | Grid voltage reference (220–240V) |
| `number.power_factor` | Power factor (0.80–1.00) |
| `button.restart_monitor` | Remote restart |

---

## 🔗 Integration with Prepaid Electricity Tracker

This project is designed to work alongside the **Prepaid Electricity Tracker** package. Once installed and calibrated, switch the tracker's source sensor to use the ESP32:

In `prepaid_electricity_tracker_v2.yaml`, update the `input_select`:

```yaml
input_select:
  prepaid_electricity_source:
    name: Grid Import Source Sensor
    options:
      - sensor.grid_energy_daily        # ← ESP32 CT Clamp (most accurate)
      - sensor.sonoff_grid_energy_daily
      - sensor.deyeinvertercombined_summary_day_grid_import_buy
    initial: sensor.grid_energy_daily   # ← set as default
    icon: mdi:flash
```

The OLED display page 3 will automatically show your **prepaid balance and days remaining** pulled from the tracker.

---

## 📺 OLED Display Pages

The display cycles through 3 pages every 5 seconds:

```
┌──────────────────────────────┐
│ 2.84kW                       │  ← Large, instant readout
│ 12.35A  230V                 │  Page 1: Live Power
└──────────────────────────────┘

┌──────────────────────────────┐
│ 4.231 kWh today              │  ← Running daily total
│ Cost: R16.53                 │  Page 2: Daily Usage & Cost
└──────────────────────────────┘

┌──────────────────────────────┐
│ Bal: 187.4 kWh               │  ← From Prepaid Tracker
│ Days left: 14.2              │  Page 3: Prepaid Status
└──────────────────────────────┘
```

---

## 🔧 Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| OLED blank | Wrong I2C address | Change `0x3C` → `0x3D` in config |
| OLED blank | SCK/SDA swapped | Check GPIO6=SDA, GPIO7=SCK |
| Always reads 0W | CT clamp not closed | Ensure clamp clicks fully shut |
| Always reads 0W | CT on both wires | Clamp ONE wire only |
| Reading too high/low | Needs calibration | Adjust Current Calibration in HA |
| Ghost energy accumulation | ADC noise on boot | Config has 30s startup delay — normal |
| Won't flash | ESP32-C6 boot mode | Hold BOOT button while clicking Upload |
| HA API disconnects | Normal reconnect cycle | `CONNECTION_CLOSED` warnings are normal |

---

## 📐 Accuracy Notes

- **CT clamp accuracy:** SCTD-016-T rated ±1% at full load
- **Minimum detectable load:** ~100W (noise gate threshold)
- **Power factor:** Set to 1.00 for resistive loads (kettle, geyser, heater). Set to 0.95–0.98 for mixed household loads
- **Voltage reference:** Fixed at 230V. For better accuracy, add a voltage sensor module (future enhancement)

---

## 🗺️ Roadmap / Future Enhancements

- [ ] Add ZMPT101B voltage sensor for true power factor measurement
- [ ] Add second CT clamp channel for solar/battery monitoring  
- [ ] Export to MQTT for broader platform support
- [ ] PCB design for permanent installation
- [ ] 3D printable enclosure design

---

## 📁 Repository Structure

```
power-meter-ha-v1.0/
├── README.md                          # This file
├── LICENSE
├── esphome/
│   └── prepaid_power_monitor.yaml     # Main ESPHome config
├── homeassistant/
│   ├── prepaid_electricity_tracker_v2.yaml   # Prepaid tracker package
│   └── prepaid_electricity_dashboard_v2.yaml # Dashboard cards
├── schematics/
│   └── wiring_diagram.md              # Detailed wiring reference
└── docs/
    └── calibration_guide.md           # Step-by-step calibration
```

---

## 🤝 Contributing

Pull requests welcome! Please open an issue first to discuss major changes.

---

## 📜 License

MIT License — free to use, modify, and share. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [ESPHome](https://esphome.io/) — incredible firmware framework
- [Home Assistant](https://home-assistant.io/) — the best home automation platform
- [OpenEnergyMonitor](https://openenergymonitor.org/) — CT clamp theory and calibration methodology
- Built with ❤️ in Johannesburg, South Africa 🇿🇦
