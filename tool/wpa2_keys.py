import hashlib
import hmac
import binascii

# PBKDF2-HMAC-SHA1 → PMK
def derive_pmk(passphrase: str, ssid: str) -> bytes:
    """
    PMK = PBKDF2(HMAC-SHA1, passphrase, ssid, 4096, 32 bytes)
    """
    pmk = hashlib.pbkdf2_hmac(
        'sha1',
        passphrase.encode('utf-8'),
        ssid.encode('utf-8'),
        4096,
        32
    )
    return pmk

# PRF-512 → PTK
def prf_512(key: bytes, A: bytes, B: bytes) -> bytes:
    """
    PRF-512 as defined in IEEE 802.11i
    """
    result = b''
    i = 0
    while len(result) < 64:
        hmacsha1 = hmac.new(
            key,
            A + b'\x00' + B + bytes([i]),
            hashlib.sha1
        )
        result += hmacsha1.digest()
        i += 1
    return result[:64]

#Cut mic field from EAPOL frame and set it to zero
def zero_mic(eapol: bytes) -> bytes:
    # EAPOL Header (4) + EAPOL Body Offset to MIC (77) = 81
    MIC_OFFSET = 81 
    MIC_LEN = 16

    return (
        eapol[:MIC_OFFSET] +
        b'\x00' * MIC_LEN +
        eapol[MIC_OFFSET + MIC_LEN:]
    )

# Build B value
def build_B(ap_mac, sta_mac, anonce, snonce):
    return (
        min(ap_mac, sta_mac) +
        max(ap_mac, sta_mac) +
        min(anonce, snonce) +
        max(anonce, snonce)
    )

#Calculate PTK, KCK, KEK, TK, and MIC from given inputs
def calcu_MIC(passphrase, ssid, ap_mac, sta_mac, anonce, snonce, eapol_frame_ori):
    eapol_frame = zero_mic(eapol_frame_ori)

    pmk = derive_pmk(passphrase, ssid)

    A = b"Pairwise key expansion"
    B = build_B(ap_mac, sta_mac, anonce, snonce)
    ptk = prf_512(pmk, A, B)

    kck = ptk[0:16]
    kek = ptk[16:32]
    tk  = ptk[32:48]

    mic = hmac.new(
        kck,
        eapol_frame,
        hashlib.sha1
    ).digest()[0:16]

    return {
        "PMK": pmk,
        "PTK": ptk,
        "KCK": kck,
        "KEK": kek,
        "TK": tk,
        "MIC": mic
    }

# DEMO
if __name__ == "__main__":

    # ===== INPUT SAMPLE =====
    passphrase = "21012004"
    ssid = "Galaxy A04s "

    ap_mac  = bytes.fromhex("fe20e041593b")
    sta_mac = bytes.fromhex("ce1fca58aae1")

    anonce = bytes.fromhex(
        "6fac2ef8864875ddef2b0663570c91849ccc6319321015b9c3fedc6a3d9ef945" 
        )

    snonce = bytes.fromhex(     
        "58f69e6555daa8a3f92bac0b683df15c69ed083fa96c5b45284f521bea6defa7"
        )

    eapol_frame_ori = bytes.fromhex(
        "0103007502010a0000000000000000000158f69e6555daa8a3f92bac0b683df15c69ed083fa96c5b45284f521bea6defa7000000000000000000000000000000000000000000000000000000000000000064749d3397bb569af6fe7b3c8ac058e3001630140100000fac040100000fac040100000fac020000"
        )

    result = calcu_MIC(
        passphrase,
        ssid,
        ap_mac,
        sta_mac,
        anonce,
        snonce,
        eapol_frame_ori
    )

print("MIC: {}".format(binascii.hexlify(result["MIC"]).decode()))