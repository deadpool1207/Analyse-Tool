import customtkinter as ctk
import socket
import time
import json
import subprocess
import requests

# ============ CustomTkinter Setup ============
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ============ Funktionen ============

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as")
        data = response.json()
        if data["status"] == "success":
            return {
                "Country": data.get("country"),
                "Region": data.get("regionName"),
                "City": data.get("city"),
                "ISP": data.get("isp"),
                "ASN": data.get("as")
            }
        else:
            return None
    except:
        return None

def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Kein PTR-Record gefunden"

def ping_host(ip):
    try:
        is_windows = subprocess.run(["ping", "-n", "1", "127.0.0.1"], capture_output=True).returncode == 0
        cmd = ["ping", "-n", "4", ip] if is_windows else ["ping", "-c", "4", ip]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        output = result.stdout

        if "TTL=" not in output and "ttl=" not in output:
            return 100, -1

        loss = 0
        for line in output.splitlines():
            if "%" in line and ("Lost" in line or "loss" in line or "Verloren" in line):
                loss = int([s for s in line.split() if "%" in s][0].replace("%",""))
                break

        latency = -1
        for line in output.splitlines():
            if "Average" in line or "Mittelwert" in line:
                latency = int(''.join(filter(str.isdigit, line.split('=')[-1])))
                break

        return loss, latency
    except:
        return 100, -1

def check_port(ip, port):
    start = time.time()
    try:
        with socket.create_connection((ip, port), timeout=5):
            duration = round((time.time() - start) * 1000, 2)
            return True, duration
    except:
        return False, None

def run_traceroute(ip):
    try:
        is_windows = subprocess.run(["tracert", "127.0.0.1"], capture_output=True).returncode == 0
        cmd = ["tracert", ip] if is_windows else ["traceroute", ip]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="ignore")
        return result.stdout
    except:
        return "Traceroute nicht möglich."



# ============ Analyse-Funktion ============

def start_analysis():
    ips_raw = entry_ip.get()
    ports_raw = entry_port.get()

    ip_list = [ip.strip() for ip in ips_raw.split(",") if ip.strip()]
    try:
        port = int(ports_raw)
    except ValueError:
        log_box.insert("end", "❌ Bitte gib eine gültige Portnummer ein.\n")
        return

    all_results = []

    log_box.delete("1.0", "end")
    log_box.insert("end", f"🔎 Starte Analyse für {len(ip_list)} IP(s) auf Port {port}\n\n")

    for ip in ip_list:
        log_box.insert("end", f"=== Analyse für {ip} ===\n")
        results = {"IP": ip, "Port": port}

        # GeoIP
        log_box.insert("end", "🌍 Hole Standortdaten...\n")
        info = get_ip_info(ip)
        if info:
            log_box.insert("end", f"📌 Standort: {info['Country']}, {info['Region']}, {info['City']}\n")
            log_box.insert("end", f"🌐 ISP: {info['ISP']} | ASN: {info['ASN']}\n")
            results["GeoIP"] = info
        else:
            log_box.insert("end", "⚠️ Standortinformationen nicht verfügbar.\n")
            results["GeoIP"] = {}

        # Reverse DNS
        ptr = reverse_dns_lookup(ip)
        log_box.insert("end", f"🔗 Reverse DNS: {ptr}\n")
        results["ReverseDNS"] = ptr

        # Ping
        log_box.insert("end", "🟢 Führe Ping-Analyse durch...\n")
        loss, latency = ping_host(ip)
        log_box.insert("end", f"⇒ Paketverlust: {loss}%\n")
        log_box.insert("end", f"⇒ Latenz: {latency} ms\n")
        results["Ping"] = {"PacketLoss": f"{loss}%", "Latency": f"{latency} ms"}

        # Port-Check
        log_box.insert("end", f"🟠 Prüfe TCP-Port {port}...\n")
        reachable, duration = check_port(ip, port)
        if reachable:
            log_box.insert("end", f"✅ Port {port} erreichbar ({duration} ms)\n")
        else:
            log_box.insert("end", f"❌ Port {port} nicht erreichbar\n")
        results["PortCheck"] = {"Reachable": reachable, "ResponseTime": f"{duration} ms" if duration else "Timeout"}

        # Traceroute
        log_box.insert("end", f"🛰️ Starte Traceroute...\n")
        trace_result = run_traceroute(ip)
        log_box.insert("end", f"{trace_result}\n")
        results["Traceroute"] = trace_result

        log_box.insert("end", "\n")
        all_results.append(results)

    with open("ddos_log.json", "w") as f:
        json.dump(all_results, f, indent=4)
    log_box.insert("end", f"\n💾 Analyse in ddos_log.json gespeichert.\n")



# ============ GUI-Setup ============

app = ctk.CTk()
app.title("🌙 DDoS Analyse Tool (Dark Mode)")
app.geometry("700x600")

frame = ctk.CTkFrame(master=app)
frame.pack(padx=20, pady=20, fill="both", expand=True)

title_label = ctk.CTkLabel(master=frame, text="🌌 DDoS Analyse Tool v2", font=("Segoe UI", 22, "bold"))
title_label.pack(pady=(10, 20))

entry_ip = ctk.CTkEntry(master=frame, placeholder_text="Server IP(s) kommasepariert")
entry_ip.pack(padx=10, pady=10, fill="x")

entry_port = ctk.CTkEntry(master=frame, placeholder_text="Port")
entry_port.pack(padx=10, pady=10, fill="x")

start_button = ctk.CTkButton(master=frame, text="Starte Analyse", command=start_analysis)
start_button.pack(pady=15)

log_box = ctk.CTkTextbox(master=frame, height=300, corner_radius=10, font=("Consolas", 12), wrap="word")
log_box.pack(padx=10, pady=10, fill="both", expand=True)
log_box.configure(fg_color="black", text_color="#39FF14")

app.mainloop()
