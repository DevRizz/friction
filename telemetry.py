"""
telemetry.py — Generate 200-parameter ARINC-717 FDR telemetry + CVR audio.
Outputs: output/telemetry_raw.bin, output/cvr_audio.wav
"""

import math, os, random, struct, wave

import config as cfg

os.makedirs("output", exist_ok=True)

# ── 200 ARINC-717 parameters: (name, rate_hz, waveform, lo, hi) ───────────────
PARAMS = [
    # Flight dynamics
    ("Altitude_ft",         4, "sin",    0,     45000),
    ("Airspeed_kts",        4, "sin",  100,       550),
    ("Pitch_deg",           8, "osc",  -20,        20),
    ("Roll_deg",            8, "osc",  -45,        45),
    ("Yaw_deg",             4, "sin",    0,       360),
    ("Pitch_rate_dps",      8, "noise", -5,         5),
    ("Roll_rate_dps",       8, "noise", -5,         5),
    ("Yaw_rate_dps",        4, "noise", -3,         3),
    ("Vertical_speed_fpm",  4, "osc", -2000,     2000),
    ("Heading_true_deg",    4, "ramp",   0,       360),
    ("Heading_mag_deg",     1, "ramp",   0,       360),
    ("Ground_speed_kts",    4, "sin",    0,       550),
    ("Track_angle_deg",     2, "ramp",   0,       360),
    ("Latitude_deg",        2, "ramp",  -90,       90),
    ("Longitude_deg",       2, "ramp", -180,      180),
    ("GPS_alt_ft",          1, "sin",    0,     45000),
    ("Mach",                4, "sin",    0,      0.95),
    ("AOA_L_deg",           4, "sin",   -5,        20),
    ("AOA_R_deg",           4, "sin",   -5,        20),
    ("Radio_alt_ft",        4, "sin",    0,      2500),
    ("Load_factor_g",       8, "osc",   -1,         4),
    ("Sideslip_deg",        4, "osc",   -5,         5),
    ("Roll_accel_dps2",     8, "noise", -10,       10),
    ("Pitch_accel_dps2",    8, "noise", -10,       10),
    # Engines (4 engines for wide-body coverage)
    ("Eng1_N1_pct",         4, "steady", 70,      100),
    ("Eng1_N2_pct",         4, "steady", 72,      100),
    ("Eng2_N1_pct",         4, "steady", 70,      100),
    ("Eng2_N2_pct",         4, "steady", 72,      100),
    ("Eng3_N1_pct",         4, "steady", 70,      100),
    ("Eng3_N2_pct",         4, "steady", 72,      100),
    ("Eng4_N1_pct",         4, "steady", 70,      100),
    ("Eng4_N2_pct",         4, "steady", 72,      100),
    ("Eng1_EGT_degC",       2, "steady", 400,      900),
    ("Eng2_EGT_degC",       2, "steady", 400,      900),
    ("Eng3_EGT_degC",       2, "steady", 400,      900),
    ("Eng4_EGT_degC",       2, "steady", 400,      900),
    ("Eng1_FF_kgh",         2, "steady", 1500,    5000),
    ("Eng2_FF_kgh",         2, "steady", 1500,    5000),
    ("Eng3_FF_kgh",         2, "steady", 1500,    5000),
    ("Eng4_FF_kgh",         2, "steady", 1500,    5000),
    ("Eng1_OilPress_psi",   1, "steady",   40,      80),
    ("Eng2_OilPress_psi",   1, "steady",   40,      80),
    ("Eng3_OilPress_psi",   1, "steady",   40,      80),
    ("Eng4_OilPress_psi",   1, "steady",   40,      80),
    ("Eng1_OilTemp_degC",   1, "steady",   80,     150),
    ("Eng2_OilTemp_degC",   1, "steady",   80,     150),
    ("Eng3_OilTemp_degC",   1, "steady",   80,     150),
    ("Eng4_OilTemp_degC",   1, "steady",   80,     150),
    ("Eng1_Vibration",      2, "noise",     0,       5),
    ("Eng2_Vibration",      2, "noise",     0,       5),
    ("Eng3_Vibration",      2, "noise",     0,       5),
    ("Eng4_Vibration",      2, "noise",     0,       5),
    ("Eng1_ITT_degC",       2, "steady",  700,    1100),
    ("Eng2_ITT_degC",       2, "steady",  700,    1100),
    ("Eng1_TRQ_pct",        4, "steady",   60,     100),
    ("Eng2_TRQ_pct",        4, "steady",   60,     100),
    ("Eng1_EPR",            4, "steady",  1.0,    1.55),
    ("Eng2_EPR",            4, "steady",  1.0,    1.55),
    # Flight controls
    ("Flap_pos_deg",        2, "step",     0,      40),
    ("Slat_pos_deg",        2, "step",     0,      25),
    ("Gear_pos",            1, "binary",   0,       1),
    ("Spoiler_pos_deg",     2, "noise",    0,      60),
    ("Aileron_L_deg",       8, "osc",    -20,      20),
    ("Aileron_R_deg",       8, "osc",    -20,      20),
    ("Elevator_L_deg",      8, "osc",    -25,      25),
    ("Elevator_R_deg",      8, "osc",    -25,      25),
    ("Rudder_deg",          8, "osc",    -25,      25),
    ("Stab_trim_deg",       2, "steady",  -5,       5),
    ("Speedbrake_pos_deg",  4, "noise",    0,      45),
    ("Stick_pitch_L",       8, "osc",    -1.0,    1.0),
    ("Stick_roll_L",        8, "osc",    -1.0,    1.0),
    ("Stick_pitch_R",       8, "osc",    -1.0,    1.0),
    ("Stick_roll_R",        8, "osc",    -1.0,    1.0),
    ("Pedal_L_pos",         4, "osc",    -1.0,    1.0),
    ("Pedal_R_pos",         4, "osc",    -1.0,    1.0),
    ("Tiller_pos",          2, "noise",  -1.0,    1.0),
    # Atmosphere & navigation
    ("Baro_press_mb",       1, "steady",  980,    1035),
    ("OAT_degC",            1, "sin",     -60,      30),
    ("SAT_degC",            1, "sin",     -60,      30),
    ("TAT_degC",            2, "sin",     -50,      40),
    ("Wind_speed_kts",      1, "steady",    0,     120),
    ("Wind_dir_deg",        1, "ramp",      0,     360),
    ("ISA_dev_degC",        1, "sin",     -20,      20),
    ("Density_alt_ft",      1, "sin",       0,   50000),
    ("TAS_kts",             4, "sin",     100,     600),
    ("IAS_kts",             4, "sin",     100,     550),
    # Navigation
    ("ILS_LOC_dev_ddm",     4, "osc",    -0.5,    0.5),
    ("ILS_GS_dev_ddm",      4, "osc",    -0.5,    0.5),
    ("VOR_dev_deg",         2, "osc",     -10,     10),
    ("DME_dist_nm",         1, "ramp",      0,    400),
    ("GPS_HDOP",            1, "steady",    0,      5),
    ("GPS_VDOP",            1, "steady",    0,      5),
    ("GPS_sats",            1, "binary",    4,     12),
    ("GPS_speed_kts",       4, "sin",       0,    600),
    ("GPS_track_deg",       2, "ramp",      0,    360),
    ("GPS_lat_fine",        4, "ramp",    -90,     90),
    ("GPS_lon_fine",        4, "ramp",   -180,    180),
    ("Baro_alt_fine_ft",    4, "sin",       0,  45000),
    # Autopilot & FMS
    ("AP_mode_code",        1, "binary",    0,      7),
    ("Autothrottle_code",   1, "binary",    0,      3),
    ("FD_pitch_cmd_deg",    4, "osc",     -10,     10),
    ("FD_roll_cmd_deg",     4, "osc",     -10,     10),
    ("FMS_track_error_nm",  2, "osc",    -5.0,   5.0),
    ("FMS_vs_cmd_fpm",      2, "osc",   -2000,  2000),
    ("FMS_speed_cmd_kts",   2, "steady",  200,    450),
    ("FMS_alt_cmd_ft",      1, "step",      0,  43000),
    # Systems warnings
    ("TCAS_RA_code",        2, "binary",    0,      7),
    ("GPWS_code",           1, "binary",    0,      7),
    ("Windshear_flag",      1, "binary",    0,      1),
    ("Stall_warn",          2, "binary",    0,      1),
    ("Overspeed_warn",      2, "binary",    0,      1),
    ("Ground_prox_code",    1, "binary",    0,      7),
    ("Master_warn",         1, "binary",    0,      1),
    ("Master_caution",      1, "binary",    0,      1),
    ("Fire_eng1",           1, "binary",    0,      1),
    ("Fire_eng2",           1, "binary",    0,      1),
    # Cabin & environmental
    ("Cabin_alt_ft",        1, "steady",    0,   8000),
    ("Cabin_dp_psi",        1, "steady",    0,      9),
    ("Cabin_temp_degC",     1, "steady",   18,     26),
    ("Pack1_flow_kgh",      1, "steady",  100,    500),
    ("Pack2_flow_kgh",      1, "steady",  100,    500),
    ("Bleed1_press_psi",    1, "steady",   20,     50),
    ("Bleed2_press_psi",    1, "steady",   20,     50),
    ("Bleed3_press_psi",    1, "steady",   20,     50),
    ("Zone1_temp_degC",     1, "steady",   18,     26),
    ("Zone2_temp_degC",     1, "steady",   18,     26),
    ("Zone3_temp_degC",     1, "steady",   18,     26),
    ("Recirc_fan1",         1, "binary",    0,      1),
    ("Recirc_fan2",         1, "binary",    0,      1),
    ("Outflow_valve_pct",   1, "steady",    0,    100),
    ("Safety_valve_pos",    1, "binary",    0,      1),
    # Hydraulics (3 systems)
    ("Hyd1_press_psi",      1, "steady", 2800,   3100),
    ("Hyd2_press_psi",      1, "steady", 2800,   3100),
    ("Hyd3_press_psi",      1, "steady", 2800,   3100),
    ("Hyd1_qty_L",          1, "steady",    0,     30),
    ("Hyd2_qty_L",          1, "steady",    0,     30),
    ("Hyd3_qty_L",          1, "steady",    0,     30),
    ("Hyd1_temp_degC",      1, "steady",   20,    100),
    ("Hyd2_temp_degC",      1, "steady",   20,    100),
    # Fuel
    ("Fuel_total_kg",       1, "ramp",   5000,  20000),
    ("Fuel_L_wing_kg",      2, "ramp",   2000,   8000),
    ("Fuel_R_wing_kg",      2, "ramp",   2000,   8000),
    ("Fuel_ctr_kg",         1, "ramp",   1000,   4000),
    ("Fuel_aux_kg",         1, "ramp",      0,   3000),
    ("Fuel_flow_total_kgh", 2, "steady", 3000,  12000),
    ("Fuel_used_kg",        1, "ramp",      0,  15000),
    ("Fuel_imbal_kg",       1, "osc",     -200,   200),
    # Electrical
    ("AC_bus1_V",           1, "steady",  110,    120),
    ("AC_bus2_V",           1, "steady",  110,    120),
    ("AC_bus3_V",           1, "steady",  110,    120),
    ("DC_bus1_V",           1, "steady",   27,     29),
    ("DC_bus2_V",           1, "steady",   27,     29),
    ("Battery_V",           1, "steady",   24,     28),
    ("APU_N1_pct",          1, "binary",    0,    100),
    ("Gen1_load_pct",       1, "steady",    0,    100),
    ("Gen2_load_pct",       1, "steady",    0,    100),
    ("IDG1_temp_degC",      1, "steady",   60,    150),
    ("IDG2_temp_degC",      1, "steady",   60,    150),
    ("AC_freq_Hz",          1, "steady",  399,    401),
    # Brakes & landing gear
    ("Brake_press_L_psi",   2, "noise",     0,   3000),
    ("Brake_press_R_psi",   2, "noise",     0,   3000),
    ("Brake_temp_L_degC",   1, "steady",   20,    600),
    ("Brake_temp_R_degC",   1, "steady",   20,    600),
    ("Tire_press_L_psi",    1, "steady",  150,    200),
    ("Tire_press_R_psi",    1, "steady",  150,    200),
    ("NWS_angle_deg",       2, "osc",     -60,     60),
    ("WOW_L",               1, "binary",    0,      1),
    ("WOW_R",               1, "binary",    0,      1),
    ("WOW_nose",            1, "binary",    0,      1),
    ("Antiskid_L",          1, "binary",    0,      1),
    ("Antiskid_R",          1, "binary",    0,      1),
    # Ice & rain
    ("Wing_anti_ice_L",     1, "binary",    0,      1),
    ("Wing_anti_ice_R",     1, "binary",    0,      1),
    ("Eng1_anti_ice",       1, "binary",    0,      1),
    ("Eng2_anti_ice",       1, "binary",    0,      1),
    ("TAT_probe_heat",      1, "binary",    0,      1),
    ("Pitot_heat_L",        1, "binary",    0,      1),
    ("Pitot_heat_R",        1, "binary",    0,      1),
    ("Wiper_L_speed",       1, "binary",    0,      3),
    ("Wiper_R_speed",       1, "binary",    0,      3),
    # Communications & ACARS
    ("VHF1_freq_MHz",       1, "step",   118.0,  136.9),
    ("VHF2_freq_MHz",       1, "step",   118.0,  136.9),
    ("HF1_freq_kHz",        1, "step",  2000,   30000),
    ("SATCOM_active",       1, "binary",     0,      1),
    ("ACARS_msg_cnt",       1, "ramp",       0,    200),
    # DFDR system health
    ("FDR_timestamp",       1, "ramp",       0,   3600),
    ("FDR_record_rate_hz",  1, "steady",     0,   1024),
    ("CVR_status",          1, "binary",     0,      1),
    ("QAR_status",          1, "binary",     0,      1),
    ("ACMS_status",         1, "binary",     0,      1),
    # Structural / load
    ("Bending_L_wing_g",    4, "osc",    -2.0,    4.0),
    ("Bending_R_wing_g",    4, "osc",    -2.0,    4.0),
    ("Lateral_accel_g",     8, "noise",  -0.5,    0.5),
    ("Normal_accel_g",      8, "noise",   0.5,    2.0),
    ("Long_accel_g",        8, "noise",  -0.5,    0.5),
    ("Fwd_cg_pct_mac",      1, "steady",  15,      35),
    ("Aft_cg_pct_mac",      1, "steady",  15,      35),
    ("Gross_weight_kg",     1, "ramp",  60000, 280000),
    # Extra system flags
    ("Sys_flags_1",         1, "binary",    0,  0xFFF),
    ("Sys_flags_2",         1, "binary",    0,  0xFFF),
    ("Sys_flags_3",         1, "binary",    0,  0xFFF),
    ("Sys_flags_4",         1, "binary",    0,  0xFFF),
    ("Sys_flags_5",         1, "binary",    0,  0xFFF),
]

assert len(PARAMS) >= 200, f"Only {len(PARAMS)} params defined"


def _generate(name, rate_hz, waveform, lo, hi, duration_sec):
    """Produce float samples for one parameter."""
    rng = random.Random(hash(name) & 0xFFFFFFFF)
    n   = int(rate_hz * duration_sec)
    mid = (hi + lo) / 2
    amp = (hi - lo) / 2
    out = []
    for i in range(n):
        t = i / rate_hz
        if waveform == "sin":
            v = mid + amp * 0.7 * math.sin(2 * math.pi * (1 / max(duration_sec * 0.3, 10)) * t)
        elif waveform == "osc":
            f = 0.1 + rng.random() * 0.2
            v = mid + amp * 0.5 * math.sin(2 * math.pi * f * t) + rng.gauss(0, amp * 0.05)
        elif waveform == "ramp":
            v = lo + (hi - lo) * (t / duration_sec)
        elif waveform == "steady":
            v = mid + rng.uniform(-amp * 0.1, amp * 0.1) + rng.gauss(0, amp * 0.02)
        elif waveform == "noise":
            v = mid + rng.gauss(0, amp * 0.4)
        elif waveform == "step":
            steps = [lo, lo + (hi - lo) * 0.25, lo + (hi - lo) * 0.5, hi]
            v = steps[min(int(t / duration_sec * len(steps)), len(steps) - 1)]
        elif waveform == "binary":
            v = out[-1] if out else lo
            if rng.random() < 0.005:
                v = rng.choice([lo, hi])
        else:
            v = mid
        out.append(max(lo, min(hi, v)))
    return out


def _to_12bit(val, lo, hi):
    """Quantise float to 12-bit ARINC word."""
    return int(round((val - lo) / (hi - lo) * 4095)) & 0xFFF


def _from_12bit(word, lo, hi):
    return lo + (word / 4095.0) * (hi - lo)


def generate_telemetry():
    """Build raw binary: each parameter packed as uint16 (12-bit word, upper 4 bits zero)."""
    rows = []
    for (name, rate_hz, wf, lo, hi) in PARAMS[:200]:
        samples = _generate(name, rate_hz, wf, lo, hi, cfg.DURATION_SEC)
        words   = [_to_12bit(s, lo, hi) for s in samples]
        rows.append((name, rate_hz, wf, lo, hi, samples, words))

    # Interleave: one uint16 per (param, sample) in time order
    # Layout: for each second, emit one sample per param at 1Hz baseline
    # Higher-rate params emit multiple words per second block
    buf = bytearray()
    max_rate = max(r[1] for r in rows)
    for sec in range(cfg.DURATION_SEC):
        for (name, rate_hz, wf, lo, hi, samples, words) in rows:
            for tick in range(int(rate_hz)):
                idx = sec * int(rate_hz) + tick
                if idx < len(words):
                    buf += struct.pack(">H", words[idx])

    path = "output/telemetry_raw.bin"
    with open(path, "wb") as f:
        f.write(bytes(buf))
    print(f"Telemetry : {len(PARAMS)} params × {cfg.DURATION_SEC}s → {len(buf):,}B → {path}")
    return bytes(buf), rows


def generate_audio(duration_sec=30):
    """Synthetic 8kHz 8-bit mono cockpit ambient. Returns raw PCM bytes."""
    sr  = 8000
    rng = random.Random(42)
    out = bytearray()
    for i in range(sr * duration_sec):
        t   = i / sr
        sig = 20 * math.sin(2 * math.pi * 80 * t)
        sig += rng.gauss(0, 10)
        if rng.random() < 0.002:
            sig += 60 * math.sin(2 * math.pi * 300 * t)
        out.append(max(0, min(255, int(sig + 128))))

    path = "output/cvr_audio.wav"
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1); wf.setsampwidth(1); wf.setframerate(sr)
        wf.writeframes(bytes(out))
    print(f"Audio     : {duration_sec}s @ {sr}Hz → {len(out):,}B → {path}")
    return bytes(out)


if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)
    tele, _ = generate_telemetry()
    audio   = generate_audio()
    print(f"Combined raw: {len(tele) + len(audio):,}B")
