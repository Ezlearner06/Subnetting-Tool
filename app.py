#!/usr/bin/env python3
"""
SubnetLab — Streamlit Web Application
IP Subnet Calculator & Network Analyzer
Run:  streamlit run app.py
"""

import streamlit as st
import pandas as pd
from core import (
    validate_ip, parse_input, classify_ip, ip_to_int, int_to_ip,
    cidr_to_mask, wildcard_mask, calculate_network_id, calculate_broadcast,
    to_binary_str, to_binary_octets, host_id, is_private, is_loopback,
    is_apipa, is_multicast, analyze_ip,
)

# ═══════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════

st.set_page_config(
    page_title="SubnetLab — IP Subnet Calculator",
    page_icon="🌐",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ═══════════════════════════════════════════
# SESSION STATE
# ═══════════════════════════════════════════

if "result" not in st.session_state:
    st.session_state.result = None
if "subnets" not in st.session_state:
    st.session_state.subnets = []
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

# ═══════════════════════════════════════════
# THEME COLORS
# ═══════════════════════════════════════════

dark = st.session_state.dark_mode

if dark:
    BG = "#0a0f1a"; PANEL = "#111827"; CYAN = "#00e5ff"; ORANGE = "#ff6b35"
    GREEN = "#39ff14"; RED = "#ff2d55"; PURPLE = "#bf5fff"; YELLOW = "#ffd700"
    TEXT = "#c8e6f5"; DIM = "#4a7a9b"; BORDER = "#1e3a5f"
    CLS_BG = {"A": "#0f2a0f", "B": "#0a1f2a", "C": "#2a1500", "D": "#1a0a2a", "E": "#2a0a0f"}
    RANGE_BG = "#0d1f35"; ALT_ROW = "#0d1a2a"
else:
    BG = "#f0f2f5"; PANEL = "#ffffff"; CYAN = "#0077b6"; ORANGE = "#e65100"
    GREEN = "#2e7d32"; RED = "#c62828"; PURPLE = "#7b1fa2"; YELLOW = "#f57f17"
    TEXT = "#1a1a2e"; DIM = "#607d8b"; BORDER = "#cfd8dc"
    CLS_BG = {"A": "#e8f5e9", "B": "#e1f5fe", "C": "#fff3e0", "D": "#f3e5f5", "E": "#fce4ec"}
    RANGE_BG = "#e3f2fd"; ALT_ROW = "#f5f5f5"

CLS_CLR = {"A": GREEN, "B": CYAN, "C": ORANGE, "D": PURPLE, "E": RED}

# ═══════════════════════════════════════════
# COMPACT CSS
# ═══════════════════════════════════════════

st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');

/* ── kill streamlit padding ── */
.stApp {{ background: {BG}; }}
.block-container {{ 
    padding-top: 0.5rem !important; 
    padding-bottom: 0 !important; 
    max-width: 1200px !important; 
    margin: 0 auto; 
}}
header[data-testid="stHeader"] {{ display: none !important; }}
div[data-testid="stVerticalBlock"] > div {{ gap: 0rem; }}
.element-container {{ margin-bottom: 0 !important; }}
div[data-testid="stHorizontalBlock"] {{ gap: 0.4rem; }}

/* ── top bar ── */
.topbar {{
    display: flex; align-items: center; justify-content: space-between;
    background: {PANEL}; padding: 6px 18px; border-bottom: 2px solid {BORDER};
    margin: 0 -1rem; position: sticky; top: 0; z-index: 999;
}}
.topbar-left {{ display: flex; align-items: center; gap: 14px; }}
.topbar-title {{
    font-family: 'Inter'; font-size: 1.6rem; font-weight: 900;
    background: linear-gradient(90deg, {CYAN}, {GREEN});
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}}
.topbar-sub {{ color: {DIM}; font-size: 0.75rem; }}
.theme-btn {{
    background: {BORDER}; color: {TEXT}; border: none; padding: 5px 14px;
    border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 600;
}}

/* ── input bar ── */
.inp-bar {{
    background: {PANEL}; padding: 8px 18px; display: flex; align-items: center;
    gap: 10px; margin: 0 -1rem; border-bottom: 1px solid {BORDER};
    flex-wrap: wrap; /* allow wrapping on small screens */
}}
.inp-label {{ color: {CYAN}; font-size: 0.7rem; font-weight: 700; font-family: 'Inter'; white-space: nowrap; }}
.class-badge {{
    background: {BORDER}; color: {TEXT}; padding: 2px 8px; border-radius: 4px;
    font-size: 0.7rem; font-weight: 700; font-family: 'Inter';
}}

/* ── cards ── */
.card {{
    background: {PANEL}; border-radius: 6px; padding: 8px 12px;
    border-top: 2px solid {CYAN}; min-height: 60px;
    flex: 1 1 min-content; /* Make cards shrink to fit but expand to fill */
}}
.card-lbl {{ color: {DIM}; font-size: 0.55rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 2px; }}
.card-val {{ font-family: 'JetBrains Mono'; font-size: 1rem; font-weight: 700; color: {CYAN}; line-height: 1.2; }}
.card-sub {{ color: {DIM}; font-size: 0.65rem; font-family: 'JetBrains Mono'; }}
.card-val.big {{ font-size: 1.5rem; }}

/* ── range card ── */
.rcard {{ background: {RANGE_BG}; border-radius: 6px; padding: 8px 14px; }}
.rcard-title {{ color: {CYAN}; font-size: 0.7rem; font-weight: 700; margin-bottom: 4px; }}
.rcard-row {{ display: flex; align-items: center; padding: 1px 0; font-family: 'JetBrains Mono'; font-size: 0.8rem; }}
.rcard-label {{ color: {DIM}; width: 160px; font-size: 0.75rem; }}
.rcard-arrow {{ color: {DIM}; margin: 0 6px; }}
.rcard-val {{ font-weight: 700; }}

/* ── class card ── */
.ccard {{ border-radius: 6px; padding: 10px 14px; display: flex; gap: 20px; align-items: flex-start; }}
.ccard-letter {{ font-size: 1.3rem; font-weight: 900; font-family: 'Inter'; }}
.ccard-desc {{ color: {TEXT}; font-size: 0.8rem; }}
.ccard-props {{ font-size: 0.7rem; color: {DIM}; font-family: 'JetBrains Mono'; }}
.ccard-props b {{ color: {DIM}; }}
.ccard-props span {{ color: {TEXT}; }}

/* ── badges ── */
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.65rem; font-weight: 700; margin-right: 4px; }}

/* ── binary ── */
.bx {{ background: {BG}; border-radius: 6px; padding: 8px 12px; font-family: 'JetBrains Mono'; font-size: 0.82rem; line-height: 1.6; overflow-x: auto; }}
.bn {{ color: {CYAN}; font-weight: 700; }}
.bh {{ color: {ORANGE}; font-weight: 700; }}
.b1 {{ color: {GREEN}; font-weight: 700; }}
.b0 {{ color: {ORANGE}; font-weight: 700; }}
.bd {{ color: {DIM}; }}
.by {{ color: {YELLOW}; font-weight: 700; }}

/* ── NH blocks ── */
.nh {{ display: inline-block; width: 18px; height: 20px; line-height: 20px; text-align: center; font-family: 'JetBrains Mono'; font-size: 0.65rem; font-weight: 700; border-radius: 2px; margin: 1px; }}
.nh-n {{ background: {CYAN}; color: {BG}; }}
.nh-h {{ background: {ORANGE}; color: {BG}; }}
.nh-dot {{ background: transparent; color: {DIM}; width: 8px; }}

/* ── section ── */
.sec {{ background: {PANEL}; border-radius: 6px; padding: 8px 14px; margin-bottom: 6px; }}
.sec-title {{ color: {CYAN}; font-size: 0.75rem; font-weight: 700; margin-bottom: 6px; font-family: 'Inter'; }}

/* ── tabs ── */
.stTabs [data-baseweb="tab-list"] {{ gap: 2px; background: {PANEL}; padding: 0 4px; border-radius: 6px 6px 0 0; }}
.stTabs [data-baseweb="tab"] {{ background: {BORDER}; color: {CYAN}; border-radius: 6px 6px 0 0; font-weight: 700; padding: 5px 12px; font-size: 0.75rem; }}
.stTabs [aria-selected="true"] {{ background: {PANEL} !important; }}
.stTabs [data-baseweb="tab-panel"] {{ padding-top: 6px !important; }}

/* ── input overrides ── */
.stTextInput > div > div > input {{
    background: {BG} !important; color: {CYAN} !important;
    border: 1.5px solid {BORDER} !important; border-radius: 6px !important;
    font-family: 'JetBrains Mono' !important; font-size: 0.9rem !important;
    padding: 4px 10px !important; height: 34px !important;
}}
.stTextInput > div > div > input:focus {{ border-color: {CYAN} !important; }}
.stTextInput > label {{ display: none !important; }}
div[data-testid="stTextInput"] {{ margin-bottom: 0 !important; }}

/* ── button overrides ── */
.stButton > button {{
    height: 34px !important; padding: 0 16px !important;
    font-size: 0.75rem !important; font-weight: 700 !important;
    border-radius: 6px !important;
}}
button[kind="primary"] {{
    background: linear-gradient(135deg, {CYAN}, {"#00b8cc" if dark else "#005f8a"}) !important;
    color: {BG} !important; border: none !important;
}}

/* ── dataframe ── */
.stDataFrame {{ border-radius: 6px; overflow: hidden; }}
div[data-testid="stDataFrame"] > div {{ margin-bottom: 0 !important; }}

/* ── expander ── */
.streamlit-expanderHeader {{ font-size: 0.8rem !important; font-weight: 700 !important; }}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════
# HEADER + THEME TOGGLE
# ═══════════════════════════════════════════

h1, h2 = st.columns([6, 1])
with h1:
    st.markdown(f"""<div style="display:flex;align-items:baseline;gap:12px;padding:4px 0;">
        <span style="font-family:Inter;font-size:1.6rem;font-weight:900;background:linear-gradient(90deg,{CYAN},{GREEN});-webkit-background-clip:text;-webkit-text-fill-color:transparent;">🌐 SubnetLab</span>
        <span style="color:{DIM};font-size:0.75rem;">IP Subnet Calculator & Network Analyzer</span>
    </div>""", unsafe_allow_html=True)
with h2:
    icon = "☀️ Light" if dark else "🌙 Dark"
    if st.button(icon, key="theme_toggle", use_container_width=True):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()


# ═══════════════════════════════════════════
# INPUT BAR
# ═══════════════════════════════════════════

c_lbl, c_inp, c_badge, c_btn1, c_btn2, c_btn3 = st.columns([1.2, 3, 0.8, 1, 0.8, 0.8])
with c_lbl:
    st.markdown(f'<div style="color:{CYAN};font-size:0.7rem;font-weight:700;padding-top:8px;">IP ADDRESS / CIDR:</div>', unsafe_allow_html=True)
with c_inp:
    ip_input = st.text_input("IP", placeholder="e.g. 192.168.1.1/24", label_visibility="collapsed", key="ip_input")

# Live class badge
with c_badge:
    badge_html = ""
    if ip_input:
        ip_part = ip_input.split("/")[0].split()[0]
        if validate_ip(ip_part):
            cls = classify_ip(ip_part)
            c = cls["class"]
            clr = CLS_CLR.get(c, CYAN)
            badge_html = f'<div style="background:{clr};color:{BG};padding:4px 10px;border-radius:4px;font-size:0.7rem;font-weight:700;text-align:center;margin-top:4px;">Class {c}</div>'
    st.markdown(badge_html, unsafe_allow_html=True)

with c_btn1:
    analyze_clicked = st.button("🔍 ANALYZE", type="primary", use_container_width=True)
with c_btn2:
    clear_clicked = st.button("CLEAR", use_container_width=True)
with c_btn3:
    add_table_clicked = st.button("+ TABLE", use_container_width=True)

# Handle actions
if analyze_clicked and ip_input:
    try:
        ip, prefix = parse_input(ip_input)
        st.session_state.result = analyze_ip(ip, prefix)
    except ValueError as e:
        st.error(f"✗ {e}")

if clear_clicked:
    st.session_state.result = None
    st.rerun()

if add_table_clicked:
    r = st.session_state.result
    if r:
        net_int = ip_to_int(r["network"])
        exists = any(s["ni"] == net_int and s["p"] == r["prefix"] for s in st.session_state.subnets)
        if not exists:
            bcast = r["broadcast"]; bi = ip_to_int(bcast); prefix = r["prefix"]
            hb = 32 - prefix; total = 2 ** hb
            if prefix == 32: usable, first, last = 1, r["network"], r["network"]
            elif prefix == 31: usable, first, last = 2, r["network"], bcast
            else: usable = total - 2; first = int_to_ip(net_int + 1); last = int_to_ip(bi - 1)
            st.session_state.subnets.append({
                "net": r["network"], "p": prefix, "mask": r["mask"], "bcast": bcast,
                "ni": net_int, "bi": bi, "first": first, "last": last,
                "total": total, "usable": usable, "hb": hb, "cls": r["cls"],
            })
            st.toast(f"✓ Added {r['network']}/{prefix}")
        else:
            st.toast(f"⚠ Already exists")
    else:
        st.toast("⚠ Analyse first")


# ═══════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════

r = st.session_state.result

tab_dash, tab_bin, tab_nh, tab_tbl, tab_rt = st.tabs([
    "⌂ DASHBOARD", "⊕ BINARY ANALYSIS", "≡ NH PATTERN", "▦ SUBNET TABLE", "⊞ ROUTING TABLE"
])


# ═══════════════════════════════════════════
# TAB 1 — DASHBOARD
# ═══════════════════════════════════════════

with tab_dash:
    if r is None:
        st.markdown(f'<div style="color:{DIM};text-align:center;padding:40px;">Enter an IP address above and click <b>ANALYZE</b></div>', unsafe_allow_html=True)
    else:
        cls_letter = r["cls"]["class"]
        cc = CLS_CLR.get(cls_letter, CYAN)

        # Row 1: 4 cards
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(f'<div class="card"><div class="card-lbl">IP Address</div><div class="card-val">{r["ip"]}</div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="card" style="border-top-color:{cc}"><div class="card-lbl">IP Class</div><div class="card-val big" style="color:{cc}">{cls_letter}</div><div class="card-sub">{r["cls"]["range"]}</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="card" style="border-top-color:{ORANGE}"><div class="card-lbl">Subnet Mask</div><div class="card-val" style="color:{ORANGE}">{r["mask"]}</div></div>', unsafe_allow_html=True)
        with c4:
            st.markdown(f'<div class="card" style="border-top-color:{GREEN}"><div class="card-lbl">CIDR Notation</div><div class="card-val big" style="color:{GREEN}">/{r["prefix"]}</div></div>', unsafe_allow_html=True)

        # Row 2: 3 cards
        c5, c6, c7 = st.columns(3)
        with c5:
            st.markdown(f'<div class="card"><div class="card-lbl">Network Address (First IP)</div><div class="card-val">{r["network"]}</div><div class="card-sub">← Network ID</div></div>', unsafe_allow_html=True)
        with c6:
            st.markdown(f'<div class="card" style="border-top-color:{ORANGE}"><div class="card-lbl">Broadcast Address (Last IP)</div><div class="card-val" style="color:{ORANGE}">{r["broadcast"]}</div><div class="card-sub">← Last address, not usable</div></div>', unsafe_allow_html=True)
        with c7:
            hb = r["host_bits"]
            st.markdown(f'<div class="card" style="border-top-color:{YELLOW}"><div class="card-lbl">Host Capacity</div><div class="card-val" style="color:{YELLOW};font-size:1.3rem;">{r["total_hosts"]:,}</div><div class="card-sub">Total: {r["total_hosts"]:,}  |  Usable: {r["usable_hosts"]:,}</div><div class="card-sub">2^{hb} = {r["total_hosts"]:,}   2^{hb}-2 = {r["usable_hosts"]:,}</div></div>', unsafe_allow_html=True)

        # Row 3: Usable Host Range
        range_data = [
            ("First Usable Host", r["first_usable"], GREEN),
            ("Last Usable Host",  r["last_usable"],  ORANGE),
            ("Network ID",        r["network"],       CYAN),
            ("Host ID",           r["host_id"],       YELLOW),
        ]
        rows_html = ""
        for lbl, val, clr in range_data:
            rows_html += f'<div class="rcard-row"><span class="rcard-label">{lbl}</span><span class="rcard-arrow">→</span><span class="rcard-val" style="color:{clr}">{val}</span></div>'
        st.markdown(f'<div class="rcard"><div class="rcard-title">USABLE HOST RANGE</div>{rows_html}</div>', unsafe_allow_html=True)

        # Row 4: Class Info
        badges = ""
        if is_private(r["ip"]): badges += f'<span class="badge" style="background:{GREEN};color:{BG}">🔒 PRIVATE IP</span>'
        if is_loopback(r["ip"]): badges += f'<span class="badge" style="background:{YELLOW};color:{BG}">↩ LOOPBACK</span>'
        if is_apipa(r["ip"]): badges += f'<span class="badge" style="background:{ORANGE};color:{BG}">⚠ APIPA</span>'
        if is_multicast(r["ip"]): badges += f'<span class="badge" style="background:{PURPLE};color:{BG}">📡 MULTICAST</span>'

        props = f'<div class="ccard-props"><b>Default Mask:</b> <span>{r["cls"]["default_mask"]}</span><br><b>Address Range:</b> <span>{r["cls"]["range"]}</span><br>'
        if "private_range" in r["cls"]:
            props += f'<b>Private Range:</b> <span>{r["cls"]["private_range"]}</span><br>'
        props += f'<b>Use Case:</b> <span>{r["cls"]["description"]}</span></div>'

        cls_bg = CLS_BG.get(cls_letter, PANEL)
        st.markdown(f"""<div class="ccard" style="background:{cls_bg};border-left:3px solid {cc}">
            <div><div class="ccard-letter" style="color:{cc}">CLASS {cls_letter}</div><div class="ccard-desc">{r["cls"]["description"]}</div><div style="margin-top:4px">{badges}</div></div>
            <div style="flex:1">{props}</div>
        </div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════
# TAB 2 — BINARY ANALYSIS
# ═══════════════════════════════════════════

with tab_bin:
    if r is None:
        st.markdown(f'<div style="color:{DIM};text-align:center;padding:40px;">Analyse an IP address first.</div>', unsafe_allow_html=True)
    else:
        prefix = r["prefix"]

        # Section 1: AND operation
        st.markdown(f'<div class="sec"><div class="sec-title">AND OPERATION — Step by Step</div>', unsafe_allow_html=True)
        ip_o, mask_o, net_o = r["ip"].split("."), r["mask"].split("."), r["network"].split(".")
        h = '<div class="bx">'
        h += '<span class="bd">  IP Address    :  </span>' + '<span class="bd">  .  </span>'.join(f'<span class="bn">{int(o):>3}</span>' for o in ip_o) + '<br>'
        h += '<span class="bd">  Subnet Mask   :  </span>' + '<span class="bd">  .  </span>'.join(f'<span class="bh">{int(o):>3}</span>' for o in mask_o) + '<br>'
        h += '<span class="bd">                   ' + '─' * 47 + '</span><br>'
        h += '<span class="bd">  AND (Network) :  </span>' + '<span class="bd">  .  </span>'.join(f'<span class="b1">{int(o):>3}</span>' for o in net_o)
        h += '</div></div>'
        st.markdown(h, unsafe_allow_html=True)

        # Section 2: Octet Binary Table
        st.markdown(f'<div class="sec"><div class="sec-title">OCTET BINARY TABLE</div>', unsafe_allow_html=True)
        ip_bin, mask_bin, net_bin = to_binary_octets(r["ip"]), to_binary_octets(r["mask"]), to_binary_octets(r["network"])

        def color_bits(bits, offset, mode):
            out = ""
            for bi, ch in enumerate(bits):
                gp = offset + bi
                if mode == "ip": c = "bn" if gp < prefix else "bh"
                elif mode == "mask": c = "b1" if ch == "1" else "b0"
                else: c = "bn" if gp < prefix else "bd"
                out += f'<span class="{c}">{ch}</span>'
            return out

        t = '<div class="bx"><table style="border-collapse:collapse;width:100%;">'
        t += '<tr><th style="color:' + DIM + ';text-align:left;padding:2px 8px;width:120px;"></th>'
        for i in range(4): t += f'<th style="color:{CYAN};text-align:left;padding:2px 8px;font-size:0.8rem;">Octet {i+1}</th>'
        t += '</tr>'
        for ri, (lbl, data, mode) in enumerate([
            ("IP Address", ip_bin, "ip"), ("Subnet Mask", mask_bin, "mask"),
            ("AND Result", net_bin, "net"), ("Network (Dec)", r["network"].split("."), None)
        ]):
            t += f'<tr><td style="color:{DIM};padding:2px 8px;font-weight:700;font-size:0.75rem;">{lbl}</td>'
            for ci in range(4):
                if mode: val = color_bits(data[ci], ci*8, mode)
                else: val = f'<span class="b1">{data[ci]}</span>'
                t += f'<td style="padding:2px 8px;">{val}</td>'
            t += '</tr>'
        t += '</table></div></div>'
        st.markdown(t, unsafe_allow_html=True)

        # Section 3: Broadcast Derivation
        inv_int = (~ip_to_int(r["mask"])) & 0xFFFFFFFF
        inv_ip = int_to_ip(inv_int)
        st.markdown(f"""<div class="sec"><div class="sec-title">BROADCAST ADDRESS DERIVATION</div><div class="bx">
<span class="bd">  Network ID      :  </span><span class="bn">{to_binary_str(r["network"])}</span><br>
<span class="bd">  Inverted Mask   :  </span><span class="bh">{to_binary_str(inv_ip)}</span><br>
<span class="bd">                     {'─'*39}</span><br>
<span class="bd">  OR Result       :  </span><span class="b1">{to_binary_str(r["broadcast"])}</span><br>
<span class="bd">  Broadcast Addr  :  </span><span class="bh">{r["broadcast"]}</span>
</div></div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════
# TAB 3 — NH PATTERN
# ═══════════════════════════════════════════

with tab_nh:
    if r is None:
        st.markdown(f'<div style="color:{DIM};text-align:center;padding:40px;">Analyse an IP address first.</div>', unsafe_allow_html=True)
    else:
        prefix = r["prefix"]; host_bits = r["host_bits"]

        # Visual NH pattern
        nh_html = '<div class="sec"><div class="sec-title">VISUAL NH BIT PATTERN</div><div style="margin-bottom:8px;">'
        for i in range(32):
            if i > 0 and i % 8 == 0: nh_html += '<span class="nh nh-dot">.</span>'
            is_n = i < prefix
            nh_html += f'<span class="nh {"nh-n" if is_n else "nh-h"}">{"N" if is_n else "H"}</span>'
        nh_html += '</div>'
        nh_html += f'<div style="font-family:JetBrains Mono;font-size:0.8rem;"><span style="color:{CYAN};font-weight:700;">Network Bits (N): {prefix}</span><br><span style="color:{ORANGE};font-weight:700;">Host Bits   (H): {host_bits}</span></div>'
        nh_str = "".join(("." if i > 0 and i % 8 == 0 else "") + ("N" if i < prefix else "H") for i in range(32))
        nh_html += f'<div style="color:{TEXT};font-family:JetBrains Mono;font-size:0.75rem;margin-top:4px;">NH Pattern: {nh_str}</div></div>'
        st.markdown(nh_html, unsafe_allow_html=True)

        # What NH tells us
        ip_bin_s, net_bin_s, hid_bin_s = to_binary_str(r["ip"]), to_binary_str(r["network"]), to_binary_str(r["host_id"])

        def colorize_binary(bin_str, prefix, mode="ip"):
            out, ci = "", 0
            for ch in bin_str:
                if ch == ".": out += f'<span class="bd">.</span>'
                else:
                    if mode == "ip": out += f'<span class="{"bn" if ci < prefix else "bh"}">{ch}</span>'
                    elif mode == "nh": out += f'<span class="{"bn" if ci < prefix else "bh"}">{"N" if ci < prefix else "H"}</span>'
                    ci += 1
            return out

        st.markdown(f"""<div class="sec"><div class="sec-title">WHAT NH PATTERN TELLS US</div><div class="bx">
<span class="bd">  IP in binary   : </span>{colorize_binary(ip_bin_s, prefix, "ip")}<br>
<span class="bd">  NH Pattern     : </span>{colorize_binary(ip_bin_s, prefix, "nh")}<br><br>
<span class="bd">  Network ID     : Keep all N-bits, set H-bits to 0</span><br>
<span class="bd">               = </span><span class="bn">{net_bin_s}</span><br>
<span class="bd">               = </span><span class="b1">{r["network"]}</span><span class="bd">  ← This is the Network ID</span><br><br>
<span class="bd">  Host ID        : Keep only H-bits (host portion of THIS IP)</span><br>
<span class="bd">               = </span><span class="bh">{hid_bin_s}</span><br>
<span class="bd">               = </span><span class="by">{r["host_id"]}</span><span class="bd">  ← This host is #{ip_to_int(r["host_id"])} in the subnet</span>
</div></div>""", unsafe_allow_html=True)

        # Legend
        st.markdown(f"""<div class="sec"><div class="sec-title">PATTERN LEGEND</div>
<span class="nh nh-n">N</span> <span style="color:{CYAN};font-family:JetBrains Mono;font-size:0.75rem;">= Network bit (1 in mask) → Fixed, identifies the network</span><br>
<span class="nh nh-h">H</span> <span style="color:{ORANGE};font-family:JetBrains Mono;font-size:0.75rem;">= Host bit (0 in mask) → Variable, identifies the host</span><br>
<div style="color:{TEXT};font-family:JetBrains Mono;font-size:0.75rem;margin-top:6px;">Total N bits = Prefix length = /{prefix}<br>Total H bits = 32 - {prefix} = {host_bits} (host space)<br><span style="color:{YELLOW};">2^{host_bits} = {r["total_hosts"]:,} total host addresses</span></div>
</div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════
# TAB 4 — SUBNET TABLE
# ═══════════════════════════════════════════

with tab_tbl:
    if r is None:
        st.markdown(f'<div style="color:{DIM};text-align:center;padding:40px;">Analyse an IP address first.</div>', unsafe_allow_html=True)
    else:
        prefix = r["prefix"]; host_bits = r["host_bits"]
        nh_str = "".join(("." if i > 0 and i % 8 == 0 else "") + ("N" if i < prefix else "H") for i in range(32))

        rows = [
            ("IP Address", r["ip"]), ("IP Class", r["cls"]["class"]),
            ("Default Class Mask", r["cls"]["default_mask"]), ("Subnet Mask", r["mask"]),
            ("CIDR Notation", f"/{prefix}"), ("Wildcard Mask", r["wildcard"]),
            ("Network Address", r["network"]), ("Broadcast Address", r["broadcast"]),
            ("First Usable Host", r["first_usable"]), ("Last Usable Host", r["last_usable"]),
            ("Host ID", r["host_id"]),
            ("Total Hosts", f"{r['total_hosts']:,}"), ("Usable Hosts", f"{r['usable_hosts']:,}"),
            ("Network Bits (N)", f"{prefix}"), ("Host Bits (H)", f"{host_bits}"),
            ("NH Pattern", nh_str),
            ("Binary IP", to_binary_str(r["ip"])), ("Binary Mask", to_binary_str(r["mask"])),
            ("Binary Network", to_binary_str(r["network"])), ("Binary Broadcast", to_binary_str(r["broadcast"])),
        ]

        df = pd.DataFrame(rows, columns=["Property", "Value"])
        st.dataframe(df, use_container_width=True, hide_index=True, height=560)

        txt = "=" * 60 + "\n  SubnetLab — Subnet Analysis Export\n" + "=" * 60 + "\n\n"
        mx = max(len(k) for k, _ in rows)
        for k, v in rows: txt += f"  {k:<{mx}}  │  {v}\n"
        txt += "\n" + "=" * 60 + "\n"
        st.download_button("📥 EXPORT .TXT", txt, "subnet_analysis.txt", "text/plain")


# ═══════════════════════════════════════════
# TAB 5 — ROUTING TABLE
# ═══════════════════════════════════════════

with tab_rt:
    rc1, rc2, rc3, rc4 = st.columns([3, 1, 1, 1.5])
    with rc1:
        rt_input = st.text_input("Quick Add", placeholder="e.g. 10.0.0.0/8", label_visibility="collapsed", key="rt_input")
    with rc2:
        rt_add = st.button("➕ ADD", use_container_width=True, key="rt_add")
    with rc3:
        rt_clr = st.button("🗑 CLEAR", use_container_width=True, key="rt_clr")
    with rc4:
        st.markdown(f'<div style="color:{DIM};font-size:0.8rem;padding-top:8px;text-align:right;">{len(st.session_state.subnets)} subnet(s)</div>', unsafe_allow_html=True)

    if rt_add and rt_input:
        try:
            ip, prefix = parse_input(rt_input)
            net = calculate_network_id(ip, prefix); net_int = ip_to_int(net)
            exists = any(s["ni"] == net_int and s["p"] == prefix for s in st.session_state.subnets)
            if not exists:
                mask = cidr_to_mask(prefix); bcast = calculate_broadcast(net, prefix)
                bi = ip_to_int(bcast); hb = 32 - prefix; total = 2 ** hb
                if prefix == 32: usable, first, last = 1, net, net
                elif prefix == 31: usable, first, last = 2, net, bcast
                else: usable = total - 2; first = int_to_ip(net_int + 1); last = int_to_ip(bi - 1)
                st.session_state.subnets.append({
                    "net": net, "p": prefix, "mask": mask, "bcast": bcast,
                    "ni": net_int, "bi": bi, "first": first, "last": last,
                    "total": total, "usable": usable, "hb": hb, "cls": classify_ip(net),
                })
                st.rerun()
            else:
                st.toast("⚠ Already exists")
        except ValueError as e:
            st.error(f"✗ {e}")

    if rt_clr:
        st.session_state.subnets.clear(); st.rerun()

    ss = sorted(st.session_state.subnets, key=lambda s: (s["ni"], s["p"]))

    if ss:
        # Overlap detection
        ov = set()
        for i in range(len(ss)):
            for j in range(i+1, len(ss)):
                a, b = ss[i], ss[j]
                if a["ni"] <= b["bi"] and b["ni"] <= a["bi"]:
                    if not (a["ni"] >= b["ni"] and a["bi"] <= b["bi"]) and not (b["ni"] >= a["ni"] and b["bi"] <= a["bi"]):
                        ov.add(id(a)); ov.add(id(b))
        if ov: st.error(f"⚠ {len(ov)} overlapping subnets!")
        else: st.success("✓ No overlaps")

        rt_df = pd.DataFrame([{
            "Network": s["net"], "CIDR": f"/{s['p']}", "Mask": s["mask"],
            "Broadcast": s["bcast"], "Usable Range": f"{s['first']} – {s['last']}",
            "Usable": f"{s['usable']:,}"
        } for s in ss])
        st.dataframe(rt_df, use_container_width=True, hide_index=True)

        # Remove
        opts = [f"{s['net']}/{s['p']}" for s in ss]
        rc5, rc6 = st.columns([3, 1])
        with rc5:
            sel = st.selectbox("Remove", opts, label_visibility="collapsed", key="rt_rm_sel")
        with rc6:
            if st.button("🗑 Remove", key="rt_rm_btn", use_container_width=True):
                for i, s in enumerate(st.session_state.subnets):
                    if f"{s['net']}/{s['p']}" == sel:
                        st.session_state.subnets.pop(i); st.rerun()

        # Hierarchy tree
        st.markdown(f'<div class="sec-title" style="margin-top:8px;">SUBNET HIERARCHY TREE</div>', unsafe_allow_html=True)

        def build_hier(subs):
            nodes = [{"d": s, "ch": []} for s in subs]
            roots = []
            for nd in nodes:
                placed = False
                for root in roots:
                    if _place(root, nd): placed = True; break
                if not placed: roots.append(nd)
            return roots

        def _place(p, c):
            pd, cd = p["d"], c["d"]
            if pd["ni"] <= cd["ni"] and pd["bi"] >= cd["bi"] and pd["p"] < cd["p"]:
                for ch in p["ch"]:
                    if _place(ch, c): return True
                p["ch"].append(c); return True
            return False

        def show_tree(nd, depth=0):
            s = nd["d"]; icons = {"A": "🟢", "B": "🔵", "C": "🟠", "D": "🟣", "E": "🔴"}
            pad = "│   " * depth + ("├── " if depth > 0 else "")
            st.markdown(f'`{pad}`{icons.get(s["cls"]["class"],"⚪")} **{s["net"]}/{s["p"]}** — `{s["usable"]:,} hosts` · `{s["mask"]}`')
            for ch in nd["ch"]: show_tree(ch, depth + 1)

        for root in build_hier(ss): show_tree(root)
    else:
        st.markdown(f'<div style="color:{DIM};text-align:center;padding:30px;">Add subnets using Quick Add above or analyse an IP then click + TABLE</div>', unsafe_allow_html=True)
