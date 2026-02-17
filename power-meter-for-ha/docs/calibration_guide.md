# Calibration Guide — Power Meter for HA v1.0

## Overview

The SCTD-016-T CT clamp is rated ±1% accuracy at full load. However, component tolerances in the voltage divider and ADC can introduce small offsets. Calibration corrects these to achieve real-world accuracy of ±2–3%.

**Good news:** Calibration is done entirely from the Home Assistant UI. No reflashing required.

---

## What You Need

- A **resistive load** with a known wattage rating on its label
- Your power meter running and connected to HA

### Best Calibration Loads

| Appliance | Why It's Good |
|---|---|
| Electric kettle | High wattage (easy to measure), pure resistive, power factor = 1.00 |
| Toaster | 800–1200W, pure resistive |
| Electric heater | 1000–2400W, pure resistive |
| Incandescent bulb | Low wattage but very accurate reference |

> ⚠️ Do NOT use motors, fluorescent lights, LED bulbs, or anything with a power supply for calibration. These have non-unity power factors that make the math unreliable.

---

## Step-by-Step Calibration

### Step 1: Read the Appliance Label

Find the rated power on the label of your calibration appliance.

**Example — Russell Hobbs kettle:**
```
Model: 15090
220-240V~ 50/60Hz
2520-3000W
```

If the label shows a range (e.g., 2520–3000W), calculate the midpoint for your supply voltage:

```
At 220V → lower wattage
At 230V → midpoint wattage   ← use this for South Africa
At 240V → higher wattage

For 2520–3000W kettle at 230V:
  Power = Rated Current × 230V
  Or use linear interpolation:
  2520 + (230-220)/(240-220) × (3000-2520) = 2760W
```

### Step 2: Take a Baseline Reading

1. Ensure **only your calibration appliance** is drawing power (turn off everything else if possible, or note the baseline idle load)
2. Turn on your calibration appliance
3. In Home Assistant, navigate to your ESP32 Power Monitor device
4. Note the reading of **Grid Power** — wait 10–15 seconds for it to stabilise

### Step 3: Calculate the Calibration Factor

```
Calibration Factor = Known Watts ÷ Measured Watts

Example:
  Kettle label at 230V:  2760W
  HA reading:            2625W
  Factor = 2760 ÷ 2625 = 1.051
```

If the meter reads **high** (e.g., measured 2900W for a 2760W kettle):
```
Factor = 2760 ÷ 2900 = 0.951
```

### Step 4: Enter the Calibration Factor

1. In HA, go to your Power Monitor device
2. Find **Current Calibration** (under Controls or Configuration)
3. Enter your calculated value (e.g., `1.051`)
4. The reading will update immediately — no restart needed

### Step 5: Verify

1. With the appliance still running, check the **Grid Power** reading again
2. It should now be within 1–2% of the label value

```
Example after calibration:
  Target:       2760W
  Reading:      2754W   ← within 0.2% ✅
  Acceptable:   2700–2820W (±2%)
```

### Step 6: Fine-Tune (Optional)

If the reading is close but not exact, run one more iteration:

```
New Factor = Target Watts ÷ New Reading × Current Factor

Example:
  Target:          2760W
  New reading:     2754W
  Current factor:  1.051
  New factor:      2760 ÷ 2754 × 1.051 = 1.053
```

---

## Reference Table — Common SA Appliances at 230V

| Appliance | Typical Rating | Expected Current |
|---|---|---|
| Russell Hobbs kettle 2520-3000W | 2760W | 12.0A |
| Generic 2400W kettle | 2400W | 10.4A |
| 3000W geyser element | 3000W | 13.0A |
| 1500W fan heater | 1500W | 6.5A |
| 2000W panel heater | 2000W | 8.7A |
| 1200W toaster | 1200W | 5.2A |
| 750W microwave (input) | ~1100W | ~4.8A |
| 60W incandescent bulb | 60W | 0.26A |
| 100W incandescent bulb | 100W | 0.43A |

---

## Troubleshooting Calibration

### Reading stays at 0W with appliance running

- CT clamp is not closed properly — open and re-close with a firm click
- CT clamp has both Live and Neutral wires through it — remove one wire
- Appliance is below the 100W noise gate — use a larger load

### Reading is very unstable (fluctuating ±20%)

- ADC noise — wait 30 seconds after boot before reading
- Loose connection in voltage divider — check resistor legs
- Try increasing the moving average window in the config (from 20 to 40)

### Reading is consistently 50% of expected

- Voltage divider multiply is missing — check `multiply: 2.0` in config
- Wrong ADC attenuation — should be `12db` for ESP32-C6 with esp-idf

### Reading is consistently 2× expected

- `multiply: 2.0` applied twice — check for duplicate filters

### Factor goes above 1.3 or below 0.7

- Something is wrong with the circuit, not just calibration offset
- Check resistor values (confirm 10kΩ each with a multimeter)
- Check ADC pin is GPIO2 and divider is connected to the same pin
- Re-examine wiring diagram

---

## Power Factor Adjustment

The default power factor is `1.00` which is correct for resistive loads.

For **real household loads** (a mix of everything), the true power factor is lower.
Once calibrated with a resistive load, you can adjust the power factor to better match your smart meter:

1. Note your physical City Power meter reading
2. Run your household normally for 1–2 hours
3. Note how much kWh the physical meter consumed
4. Compare to the HA daily energy reading
5. Adjust power factor: `PF = Meter kWh ÷ HA kWh`

Typical SA household power factor: **0.92–0.98**

---

## Keeping Calibration Accurate

- Re-calibrate if you change the CT clamp position
- Re-calibrate if you replace any component
- Check monthly against your physical meter reading using the **Sync** feature in the Prepaid Electricity Tracker
- Calibration is stored in ESP32 flash memory and survives power cuts and reboots
