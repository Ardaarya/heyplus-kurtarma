#!/usr/bin/env python3
"""
HeyPlus W2100 BLE Binding Script v4
Completa o binding sem servidor.

Antes de rodar: bluetoothctl remove 98:80:BB:03:3B:49

Fluxo:
  1. Register Session (token exchange) - Service 0xFE95
  2. Login Session (ativa canal RC4) - Service 0xFE95
  3. BindAckStart (CMD 30 via RC4) - Service 0xB167
  4. BindResult (CMD 31 via RC4) - Service 0xB167
"""

import asyncio
import hashlib
import struct
import time
import random
import sys

from bleak import BleakClient, BleakScanner

# === Device Config ===
DEVICE_MAC = "98:80:BB:03:3B:49"
DEVICE_MAC_CRYPTO = "49:3B:03:BB:80:98"  # reversed for crypto
DEVICE_PID = 911

# === BLE UUIDs ===
CHAR_MI_EVENT = "00000010-0000-1000-8000-00805f9b34fb"  # 0x0010
CHAR_MI_TOKEN = "00000001-0000-1000-8000-00805f9b34fb"  # 0x0001
CHAR_RYEEX_RC4 = "0000aa00-0000-1000-8000-00805f9b34fb"  # 0xAA00

# === Protocol Constants ===
RYEEX_REGISTER_SESSION_START = -561657199
RYEEX_REGISTER_SESSION_END   = -95114349
RYEEX_LOGIN_SESSION_START    = -851198975
RYEEX_LOGIN_ENCRYPT_DATA     = -1816155126
RYEEX_LOGIN_ACK              = 916084938

# === Crypto ===
def int_to_bytes_le(val):
    return struct.pack('<i', val)

def mac_to_bytes(mac_str):
    return bytes([int(x, 16) for x in mac_str.split(':')])

def pid_to_bytes(pid):
    return bytes([pid & 0xFF, (pid >> 8) & 0xFF])

def mix_a(mac_str, pid):
    mac = mac_to_bytes(mac_str)
    p = pid_to_bytes(pid)
    return bytes([mac[0], mac[2], mac[5], p[0], p[0], mac[4], mac[5], mac[1]])

def mix_b(mac_str, pid):
    mac = mac_to_bytes(mac_str)
    p = pid_to_bytes(pid)
    return bytes([mac[0], mac[2], mac[5], p[1], mac[4], mac[0], mac[5], p[0]])

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)

def gen_token():
    seed = f"token.{int(time.time()*1000)}.{random.random()}"
    md5 = hashlib.md5(seed.encode()).digest()
    m = len(md5) // 2
    return md5[m-6:m+6]

# === Protobuf manual encoding ===
def encode_varint(value):
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts) if parts else b'\x00'

def encode_field_varint(field_number, value):
    tag = (field_number << 3) | 0
    return encode_varint(tag) + encode_varint(value)

def encode_field_bytes(field_number, data):
    tag = (field_number << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data

def encode_field_string(field_number, s):
    return encode_field_bytes(field_number, s.encode('utf-8'))

def decode_varint(data, pos):
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return value, pos

def parse_protobuf(data):
    """Parse protobuf basico, retorna dict de field_number -> value."""
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            value, pos = decode_varint(data, pos)
            fields[field_number] = value
        elif wire_type == 2:  # length-delimited
            length, pos = decode_varint(data, pos)
            fields[field_number] = data[pos:pos+length]
            pos += length
        else:
            break
    return fields

# === RBP Protocol ===
CMD_DEV_BIND_ACK_START = 30
CMD_DEV_BIND_RESULT = 31

def build_rbp_request(cmd, payload=None, session_id=None):
    """Constroi um RbpMsg request completo."""
    if session_id is None:
        session_id = random.randint(1, 127)  # small to fit in 1 varint byte

    # RbpMsg_Req
    req = encode_field_varint(1, 1)  # total = 1
    # sn = 0, omit (default)
    if payload:
        req += encode_field_bytes(3, payload)  # val

    # RbpMsg
    msg = encode_field_varint(1, 1)          # protocol_ver = 1
    msg += encode_field_varint(2, cmd)        # cmd
    msg += encode_field_varint(3, session_id) # session_id
    msg += encode_field_bytes(4, req)         # req (embedded message)

    return msg, session_id

def build_bind_result_payload(error_code=0, uid="local"):
    """Constroi o payload BindResult protobuf."""
    data = encode_field_varint(1, error_code)
    if uid:
        data += encode_field_string(2, uid)
    return data


# === Notification handler ===
class NotifyCollector:
    def __init__(self):
        self.event = asyncio.Event()
        self.data = None

    def handler(self, sender, data):
        self.data = data
        self.event.set()

    async def wait(self, timeout=5.0):
        self.event.clear()
        self.data = None
        try:
            await asyncio.wait_for(self.event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        return self.data

    def reset(self):
        self.event.clear()
        self.data = None


async def main():
    print("=" * 60)
    print("  HeyPlus W2100 - Binding sem servidor v4")
    print("=" * 60)
    print(f"  MAC: {DEVICE_MAC}")
    print(f"  MAC (crypto): {DEVICE_MAC_CRYPTO}")
    print(f"  PID: {DEVICE_PID}")

    # Pre-compute keys
    ka = mix_a(DEVICE_MAC_CRYPTO, DEVICE_PID)
    kb = mix_b(DEVICE_MAC_CRYPTO, DEVICE_PID)
    token = gen_token()
    print(f"  Token: {token.hex()}")
    print(f"  mixA:  {ka.hex()}")
    print(f"  mixB:  {kb.hex()}")

    # === Scan ===
    print(f"\n[1] Procurando {DEVICE_MAC}...")
    device = await BleakScanner.find_device_by_address(DEVICE_MAC, timeout=10.0)
    if not device:
        print("  ERRO: Nao encontrado")
        return
    print(f"  Encontrado: {device.name}")

    # === Connect ===
    print(f"\n[2] Conectando...")

    disconnected_event = asyncio.Event()
    def on_disconnect(client):
        print(f"  !!! DESCONECTADO pelo relogio !!!")
        disconnected_event.set()

    SERVICE_MI = "0000fe95-0000-1000-8000-00805f9b34fb"
    SERVICE_RYEEX = "0000b167-0000-1000-8000-00805f9b34fb"
    client = BleakClient(
        device,
        disconnected_callback=on_disconnect,
        timeout=15.0,
    )
    try:
        await client.connect()
    except Exception as e:
        print(f"  ERRO: {e}")
        return
    print(f"  Conectado! MTU: {client.mtu_size}")

    mi_notify = NotifyCollector()
    rc4_notify = NotifyCollector()

    try:
        # ============================================
        # PHASE 1: Register Session (Token Exchange)
        # ============================================
        print(f"\n{'='*60}")
        print(f"  FASE 1: Token Exchange")
        print(f"{'='*60}")

        print(f"\n[3] Ativando notify em 0x0001...")
        try:
            await client.start_notify(CHAR_MI_TOKEN, mi_notify.handler,
                                      bluez={"use_start_notify": True})
            print(f"  OK (StartNotify)")
        except Exception as e:
            print(f"  StartNotify falhou: {e}")
            print(f"  Tentando escrever CCCD direto...")
            # Fallback: write 0x0100 to CCCD descriptor manually
            char = client.services.get_characteristic(CHAR_MI_TOKEN)
            if char is None:
                print(f"  ERRO: characteristic 0x0001 nao encontrada!")
                return
            for desc in char.descriptors:
                if "2902" in desc.uuid:
                    await client.write_gatt_descriptor(desc.handle, b'\x01\x00')
                    # Register callback manually via bleak internals
                    client._backend._notification_callbacks[
                        char.obj[0] if hasattr(char, 'obj') else char.handle
                    ] = lambda s, d: mi_notify.handler(s, d)
                    print(f"  OK (CCCD direto)")
                    break
            else:
                print(f"  ERRO: CCCD descriptor nao encontrado!")
                return

        print(f"\n[4] SESSION_START -> 0x0010...")
        ss = int_to_bytes_le(RYEEX_REGISTER_SESSION_START)
        await client.write_gatt_char(CHAR_MI_EVENT, ss, response=True)
        print(f"  Enviado: {ss.hex()}")

        print(f"\n[5] Token encriptado -> 0x0001...")
        enc_token = rc4(ka, token)
        mi_notify.reset()
        await client.write_gatt_char(CHAR_MI_TOKEN, enc_token, response=True)
        print(f"  Enviado: {enc_token.hex()}")

        print(f"  Aguardando resposta...")
        resp = await mi_notify.wait(timeout=5.0)
        if resp is None:
            print(f"  TIMEOUT! Relogio nao respondeu ao token")
            return
        print(f"  Recebido: {resp.hex()}")

        # Verify token
        dec = rc4(kb, rc4(ka, resp))
        if dec != token:
            print(f"  ERRO: Token nao bateu!")
            print(f"  Esperado:   {token.hex()}")
            print(f"  Decriptado: {dec.hex()}")
            return
        print(f"  TOKEN VALIDADO!")

        print(f"\n[6] SESSION_END ACK -> 0x0001...")
        se = int_to_bytes_le(RYEEX_REGISTER_SESSION_END)
        ack = rc4(token, se)
        await client.write_gatt_char(CHAR_MI_TOKEN, ack, response=True)
        print(f"  Enviado: {ack.hex()}")

        await asyncio.sleep(0.5)

        # ============================================
        # PHASE 2: Login Session
        # ============================================
        print(f"\n{'='*60}")
        print(f"  FASE 2: Login Session")
        print(f"{'='*60}")

        print(f"\n[7] LOGIN_SESSION_START -> 0x0010...")
        ls = int_to_bytes_le(RYEEX_LOGIN_SESSION_START)
        mi_notify.reset()
        await client.write_gatt_char(CHAR_MI_EVENT, ls, response=True)
        print(f"  Enviado: {ls.hex()}")

        print(f"  Aguardando login challenge...")
        login_resp = await mi_notify.wait(timeout=5.0)
        if login_resp is None:
            print(f"  TIMEOUT! Relogio nao enviou challenge de login")
            return
        print(f"  Recebido: {login_resp.hex()} ({len(login_resp)} bytes)")

        # Compute login response
        encrypted = rc4(token, login_resp)
        modified_token = bytearray(token)
        for i in range(min(4, len(encrypted))):
            modified_token[i] ^= encrypted[i]
        modified_token = bytes(modified_token)
        print(f"  Modified token: {modified_token.hex()}")

        login_encrypt_data = int_to_bytes_le(RYEEX_LOGIN_ENCRYPT_DATA)
        login_answer = rc4(modified_token, login_encrypt_data)

        print(f"\n[8] Login answer -> 0x0001...")
        mi_notify.reset()
        await client.write_gatt_char(CHAR_MI_TOKEN, login_answer, response=True)
        print(f"  Enviado: {login_answer.hex()}")

        print(f"  Aguardando verificacao...")
        login_verify = await mi_notify.wait(timeout=5.0)
        if login_verify is None:
            print(f"  TIMEOUT! Relogio nao verificou login")
            return
        print(f"  Recebido: {login_verify.hex()}")

        # Verify login
        login_dec = rc4(modified_token, login_verify)
        expected_ack = int_to_bytes_le(RYEEX_LOGIN_ACK)
        if login_dec == expected_ack:
            print(f"  LOGIN OK!")
        else:
            print(f"  LOGIN FALHOU!")
            print(f"  Esperado:   {expected_ack.hex()}")
            print(f"  Decriptado: {login_dec.hex()}")
            print(f"  Continuando mesmo assim...")

        await asyncio.sleep(0.5)

        # ============================================
        # PHASE 3: BindAckStart (CMD 30 via RC4)
        # ============================================
        print(f"\n{'='*60}")
        print(f"  FASE 3: BindAckStart (CMD 30)")
        print(f"{'='*60}")

        print(f"\n[9] Ativando notify em 0xAA00...")
        await client.start_notify(CHAR_RYEEX_RC4, rc4_notify.handler,
                                  bluez={"use_start_notify": True})
        print(f"  OK")

        print(f"\n[10] BindAckStart -> 0xAA00 (RC4)...")
        rbp_msg, sid = build_rbp_request(CMD_DEV_BIND_ACK_START)
        print(f"  RbpMsg: {rbp_msg.hex()} (sessionId={sid})")
        enc_msg = rc4(token, rbp_msg)
        print(f"  Encrypted: {enc_msg.hex()}")

        rc4_notify.reset()
        await client.write_gatt_char(CHAR_RYEEX_RC4, enc_msg, response=True)
        print(f"  Enviado!")

        print(f"  Aguardando BindAckResult (relogio pode pedir confirmacao)...")
        print(f"  >>> Olhe o relogio! Se aparecer botao, CONFIRME! <<<")
        bind_ack_resp = await rc4_notify.wait(timeout=20.0)
        if bind_ack_resp is None:
            print(f"  TIMEOUT! Relogio nao respondeu ao BindAckStart")
            print(f"  Possibilidades:")
            print(f"    - Login nao foi aceito (RC4 channel inativo)")
            print(f"    - Token expirou")
            print(f"    - Comando nao reconhecido")
            # Tenta enviar BindResult mesmo assim
        else:
            print(f"  Recebido: {bind_ack_resp.hex()}")
            dec_resp = rc4(token, bind_ack_resp)
            print(f"  Decriptado: {dec_resp.hex()}")
            fields = parse_protobuf(dec_resp)
            print(f"  Parsed: {fields}")

            # Check response
            if 5 in fields:  # RbpMsg.res (field 5)
                res_fields = parse_protobuf(fields[5])
                print(f"  Response fields: {res_fields}")
                if 3 in res_fields:  # RbpMsg_Res.val (field 3)
                    ack_fields = parse_protobuf(res_fields[3])
                    code = ack_fields.get(1, -1)  # BindAckResult.code
                    print(f"  BindAckResult code: {code}")
                    if code == 1:
                        print(f"  Usuario cancelou no relogio!")
                        return
                    elif code != 0:
                        print(f"  Codigo inesperado: {code}")

        await asyncio.sleep(0.5)

        # ============================================
        # PHASE 4: BindResult (CMD 31 via RC4)
        # ============================================
        print(f"\n{'='*60}")
        print(f"  FASE 4: BindResult (CMD 31)")
        print(f"{'='*60}")

        uid = "local"
        bind_payload = build_bind_result_payload(error_code=0, uid=uid)
        print(f"\n[11] BindResult(error=0, uid='{uid}') -> 0xAA00 (RC4)...")
        rbp_msg2, sid2 = build_rbp_request(CMD_DEV_BIND_RESULT, payload=bind_payload)
        print(f"  RbpMsg: {rbp_msg2.hex()} (sessionId={sid2})")
        enc_msg2 = rc4(token, rbp_msg2)
        print(f"  Encrypted: {enc_msg2.hex()}")

        rc4_notify.reset()
        await client.write_gatt_char(CHAR_RYEEX_RC4, enc_msg2, response=True)
        print(f"  Enviado!")

        print(f"  Aguardando resposta...")
        bind_resp = await rc4_notify.wait(timeout=10.0)
        if bind_resp is not None:
            print(f"  Recebido: {bind_resp.hex()}")
            dec_resp2 = rc4(token, bind_resp)
            print(f"  Decriptado: {dec_resp2.hex()}")
            fields2 = parse_protobuf(dec_resp2)
            print(f"  Parsed: {fields2}")
        else:
            print(f"  Sem resposta (pode ser normal)")

        # ============================================
        # Result
        # ============================================
        print(f"\n{'='*60}")
        print(f"  VERIFICACAO")
        print(f"{'='*60}")
        print(f"\n  Olhe o relogio!")
        print(f"  - Saiu do QR code?")
        print(f"  - Mostra alguma tela diferente?")

        # Keep connection alive for a bit
        await asyncio.sleep(5)

    except Exception as e:
        print(f"\nERRO: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            await client.disconnect()
        except:
            pass
        print(f"\nDesconectado.")


if __name__ == "__main__":
    asyncio.run(main())
