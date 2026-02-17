# Wiring Diagram — Power Meter for HA v1.0

## Overview

This document covers all physical connections for the ESP32-C6 power meter.

---

## Components

```
┌─────────────────────────────────────────────────────────┐
│  1. ESP32-C6 development board                          │
│  2. SCTD-016-T 100A/0-5VDC CT clamp                    │
│  3. 0.91" SSD1306 I2C OLED display (128x32)            │
│  4. 2x 10kΩ resistors (¼W carbon film)                 │
│  5. Breadboard or prototyping PCB                       │
│  6. Jumper wires                                        │
└─────────────────────────────────────────────────────────┘
```

---

## CT Clamp Voltage Divider Circuit

The SCTD-016-T outputs 0–5V DC, but the ESP32-C6 ADC safely reads
only 0–3.3V. Two 10kΩ resistors divide the voltage by half (5V → 2.5V).
The ESPHome config compensates with a ×2 multiply filter.

```
CT Clamp (+) ──────────────────────────────────────────────
                                                           |
                                                        [ 10kΩ ]   R1
                                                           |
                                                           ├──────── GPIO2 (ADC)
                                                           |
                                                        [ 10kΩ ]   R2
                                                           |
CT Clamp (-) ──────────────────────────────────────────────┴──────── GND
```

### Why a Voltage Divider?

```
CT Output:    0V (no load) → 5V (100A full load)
ESP32 ADC:    Rated for max 3.3V input

Without divider: 5V → ADC damage
With divider:    2.5V max → ADC safe
Compensation:    multiply: 2.0 in ESPHome restores correct value
```

---

## Full Wiring Table

| From | To | Wire Colour (suggested) |
|---|---|---|
| CT Clamp (+) | R1 leg 1 | Red |
| R1 leg 2 | ESP32 GPIO2 | Orange |
| R1 leg 2 | R2 leg 1 | Orange (same node) |
| R2 leg 2 | GND | Black |
| CT Clamp (-) | GND | Black |
| OLED GND | GND | Black |
| OLED VCC | 3.3V | Red |
| OLED SCK | GPIO7 | Yellow |
| OLED SDA | GPIO6 | Blue |

---

## Breadboard Layout (Top View)

```
                    ESP32-C6
         ┌──────────────────────────┐
    3.3V ┤ 3V3                      ├
     GND ┤ GND                      ├
  GPIO2  ┤ 2    (ADC)               ├
  GPIO6  ┤ 6    (I2C SDA)           ├
  GPIO7  ┤ 7    (I2C SCL)           ├
         └──────────────────────────┘
              │    │    │    │
              │    │    │    └── OLED SCK
              │    │    └─────── OLED SDA
              │    └──────────── GND rail
              │
       ┌──────┴───────┐
    CT(+) ── R1(10kΩ) ──┬── GPIO2
                        │
                     R2(10kΩ)
                        │
                       GND
```

---

## OLED Display Pinout

Your 0.91" display has pins in this order (left to right):

```
[ GND ][ VCC ][ SCK ][ SDA ]
   │       │      │      │
  GND    3.3V  GPIO7  GPIO6
```

> ⚠️ SCK on the display = SCL (clock). They are the same thing with different labels.

---

## CT Clamp Installation

### Correct Installation

```
Grid Incoming Cable
        │
   ┌────┴────┐     ← Only ONE wire through the clamp
   │  CT     │       (Live OR Neutral — not both)
   │ Clamp   │
   └────┬────┘
        │
   To DB Board
```

### Rules

1. **One wire only** — clamping both live AND neutral cancels the magnetic fields → reads zero
2. **Click closed** — the clamp must close completely, no gap
3. **Arrow direction** — the arrow on the clamp body points toward your load (house side)
4. **Away from other CTs** — keep 50–100mm clearance from other current transformers

### Where to Install

```
City Power Meter
      │
      │ ← IDEAL: Clamp here (measures ALL consumption)
      │
   Main DB Board
   ┌──┴────────────┐
   │  Circuit 1    │
   │  Circuit 2    │
   │  Circuit 3    │
   └───────────────┘
```

---

## Safety Notes

> ⚡ **IMPORTANT: Working near your DB board involves mains voltage (230V AC).**
> The CT clamp is designed to clamp around an INSULATED cable — you do NOT
> need to disconnect or cut any wires. However:
>
> - If unsure, ask a qualified electrician to clamp the CT
> - The ESP32 and all its wiring operates at safe 3.3V/5V DC
> - Never touch exposed mains conductors
> - The CT clamp itself is electrically isolated — safe to handle while powered

---

## Power Supply

The ESP32-C6 is powered via its USB-C port.

For permanent installation, use:
- A 5V USB charger/adapter mounted inside the DB enclosure, OR
- A 5V USB power supply rail if your setup has one

Current draw: ~150mA typical, ~500mA peak (WiFi transmit)
