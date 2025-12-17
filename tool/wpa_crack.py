from scapy.all import *
import hashlib
import hmac
import binascii
import struct

# ================= CRYPTO =================

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    # Đảm bảo SSID string y chang thực tế (bao gồm dấu cách)
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)

def prf_512(key: bytes, A: bytes, B: bytes) -> bytes:
    n_bytes = 64
    i = 0
    R = b''
    while len(R) < n_bytes:
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:n_bytes]

def calculate_mic(kck, eapol_payload):
    # EAPOL Header (4) + Offset (77) = 81
    # Chỉ zero đúng 16 bytes MIC
    eapol_zeroed = eapol_payload[:81] + (b'\x00' * 16) + eapol_payload[97:]
    mic = hmac.new(kck, eapol_zeroed, hashlib.sha1).digest()[:16]
    return mic

# ================= HELPER: CLEAN PACKET =================

def extract_clean_eapol(pkt):
    """
    Cắt bỏ Padding thừa (Ethernet padding) dựa trên EAPOL Length header.
    Nếu không cắt, HMAC sẽ tính sai vì tính cả byte rác.
    """
    try:
        raw_bytes = raw(pkt[EAPOL])
        # Byte 2-3 là Length (Big Endian)
        eapol_len = struct.unpack('>H', raw_bytes[2:4])[0]
        # EAPOL thực tế = Header(4) + Body(Len)
        real_len = 4 + eapol_len
        return raw_bytes[:real_len]
    except:
        return None

# ================= MAIN LOGIC =================

def crack_wpa_robust(pcap_file, ssid, bssid, password):
    bssid_clean = bssid.replace(':', '').lower()
    
    print(f"[*] Loading PCAP: {pcap_file}")
    packets = rdpcap(pcap_file)
    
    # 1. Thu thập TẤT CẢ Anonce tiềm năng (Từ Msg 1 và Msg 3)
    potential_anonces = set() # Dùng set để loại bỏ trùng lặp
    
    msg2_targets = []

    print("[*] Đang quét toàn bộ file để phân loại...")
    
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                src = pkt[Dot11].addr2.replace(':', '').lower()
                dst = pkt[Dot11].addr1.replace(':', '').lower()
                
                clean_eapol = extract_clean_eapol(pkt)
                if not clean_eapol: continue
                
                key_info = struct.unpack('>H', clean_eapol[5:7])[0]
                nonce = clean_eapol[17:49] # Lấy vị trí Nonce
                
                # A. Tìm Anonce (Gói từ Router -> Client bất kỳ)
                # Msg 1 (No MIC) hoặc Msg 3 (Has MIC) đều chứa Anonce
                if src == bssid_clean:
                    # Lưu lại Anonce này
                    potential_anonces.add(bytes(nonce))

                # B. Tìm Message 2 (Gói từ Client -> Router)
                # Phải có MIC (Bit 8 set)
                elif dst == bssid_clean and (key_info & 0x0100):
                     msg2_targets.append({
                        'client': src,
                        'snonce': nonce,
                        'mic_orig': clean_eapol[81:97],
                        'payload': clean_eapol,
                        'desc': f"Msg2 from {src}"
                    })

            except Exception as e:
                # print(e)
                continue
                
    if not msg2_targets:
        print("[-] Không tìm thấy gói Message 2 nào.")
        return
    
    if not potential_anonces:
        print("[-] Không tìm thấy bất kỳ Anonce nào từ Router.")
        return

    print(f"[+] Thu thập được {len(potential_anonces)} Anonce duy nhất.")
    print(f"[+] Tìm thấy {len(msg2_targets)} gói Message 2 cần crack.")
    
    # 2. Tính PMK
    print(f"[*] Calculating PMK for SSID: '{ssid}' | Pass: '{password}'")
    pmk = derive_pmk(password, ssid)
    
    # 3. CRACKING (Thử mọi tổ hợp Anonce + Msg 2)
    print("\n[*] BẮT ĐẦU CHẠY THỬ (BRUTE-FORCE ANONCE)...")
    
    for idx, target in enumerate(msg2_targets):
        print(f"\n--- Checking Target #{idx+1} ({target['desc']}) ---")
        print(f"    Snonce: {target['snonce'][:8].hex()}...")
        print(f"    MIC Gốc: {target['mic_orig'].hex()}")
        
        found = False
        # Lặp qua từng Anonce có trong kho
        for anonce in potential_anonces:
            # ---------------- TÍNH TOÁN ----------------
            ap_mac = bytes.fromhex(bssid_clean)
            sta_mac = bytes.fromhex(target['client'])
            
            B = (min(ap_mac, sta_mac) + max(ap_mac, sta_mac) +
                 min(anonce, target['snonce']) + max(anonce, target['snonce']))
            
            ptk = prf_512(pmk, b"Pairwise key expansion", B)
            kck = ptk[0:16]
            mic_calc = calculate_mic(kck, target['payload'])
            
            # ---------------- SO SÁNH ----------------
            if mic_calc == target['mic_orig']:
                print(f"\n>>> SUCCESS: MẬT KHẨU CHÍNH XÁC! <<<")
                print(f"    Khớp với Anonce: {anonce[:8].hex()}...")
                print(f"    MIC khớp: {mic_calc.hex()}")
                found = True
                break # Tìm ra rồi thì break loop Anonce
        
        if not found:
            print("    [-] Thử tất cả Anonce đều không khớp.")

# ================= RUN =================
if __name__ == "__main__":
    # FILE, SSID, BSSID, PASS CỦA BẠN
    # Nhớ kiểm tra kỹ SSID có dấu cách hay không
    crack_wpa_robust("dump-01.cap", "Galaxy A04s ", "fe:20:e0:41:59:3b", "21012004")