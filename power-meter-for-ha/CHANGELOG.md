# Changelog

All notable changes to Power Meter for HA will be documented here.

---

## [v1.0.0] — 2026-02-14

### Initial Release 🎉

**Hardware:**
- ESP32-C6 with esp-idf framework
- SCTD-016-T 100A/0-5VDC CT clamp from Livestainable
- 0.91" SSD1306 I2C OLED display (128x32)
- 2x 10kΩ voltage divider resistors

**ESPHome Features:**
- Real-time grid power (W) and current (A)
- Daily energy accumulation (kWh, resets midnight)
- Lifetime total energy counter
- 3-page OLED display with 5-second cycling
- Calibration adjustable from HA UI (no reflash)
- Power factor and voltage setpoint controls
- High power alert (>7kW)
- WiFi fallback AP
- OTA firmware updates
- Web server on port 80

**Home Assistant Integration:**
- Full ESPHome native API
- All sensors, controls and diagnostics exposed
- Companion Prepaid Electricity Tracker package included
- Complete Lovelace dashboard cards included

**Calibration:**
- Tested with Russell Hobbs 2520-3000W kettle
- Calibration factor: 1.051 (at 230V SA grid)
- Expected accuracy: ±2-3% of true consumption

---

## Roadmap

### Planned for v1.1
- ZMPT101B voltage sensor for true RMS power factor measurement
- Remove fixed 230V assumption

### Planned for v1.2
- Second CT clamp channel (solar/battery monitoring)
- Per-channel power display on OLED

### Planned for v2.0
- Custom PCB design
- 3D-printable enclosure
- DIN rail mount option
