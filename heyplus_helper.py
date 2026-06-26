#!/usr/bin/env python3
"""
HeyPlus W2100 - Helper para binding manual via nRF Connect

Esse script calcula os bytes que você precisa escrever
nas characteristics do relógio usando o nRF Connect no celular.

Uso: python3 heyplus_helper.py
"""

import hashlib
import struct
import time
import random

DEVICE_MAC = "49:3B:03:BB:80:98"
DEVICE_PID = 911

RYEEX_REGISTER_SESSION_START = -561657199
RYEEX_REGISTER_SESSION_END   = -95114349

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
    m = len(md5)//2
    return md5[m-6:m+6]

def format_hex(data):
    """Formata bytes pro formato do nRF Connect: hex sem separador"""
    return data.hex().upper()

# --- Protobuf manual encoding ---

def encode_varint(value):
    """Encode um inteiro como protobuf varint."""
    if value < 0:
        # Protobuf signed int32 usa 10 bytes em complemento de 2
        value = value & 0xFFFFFFFFFFFFFFFF
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts) if parts else b'\x00'

def encode_field_varint(field_number, value):
    """Encode field tag + varint value."""
    tag = (field_number << 3) | 0  # wire type 0 = varint
    return encode_varint(tag) + encode_varint(value)

def encode_field_bytes(field_number, data):
    """Encode field tag + length-delimited bytes."""
    tag = (field_number << 3) | 2  # wire type 2 = length-delimited
    return encode_varint(tag) + encode_varint(len(data)) + data

def encode_field_string(field_number, s):
    """Encode field tag + string."""
    return encode_field_bytes(field_number, s.encode('utf-8'))

def build_bind_result(error_code, uid):
    """
    Constroi o protobuf BindResult.

    message BindResult {
        required int32 error = 1;
        optional string uid = 2;
    }
    """
    data = encode_field_varint(1, error_code)
    if uid:
        data += encode_field_string(2, uid)
    return data

def build_rbp_msg_req(total, sn, val=None):
    """
    Constroi o protobuf RbpMsg_Req.

    message RbpMsg_Req {
        optional int32 total = 1;
        optional int32 sn = 2;
        optional bytes val = 3;
    }
    """
    data = encode_field_varint(1, total)
    if sn > 0:
        data += encode_field_varint(2, sn)
    if val:
        data += encode_field_bytes(3, val)
    return data

def build_rbp_msg(protocol_ver, cmd, session_id, req_bytes):
    """
    Constroi o protobuf RbpMsg.

    message RbpMsg {
        optional int32 protocol_ver = 1;
        optional CMD cmd = 2;  // enum, serializado como varint
        optional int32 session_id = 3;
        oneof message {
            RbpMsg_Req req = 4;
            RbpMsg_Res res = 5;
            RbpMsg_Ind ind = 6;
        }
    }
    """
    data = encode_field_varint(1, protocol_ver)
    data += encode_field_varint(2, cmd)  # enum = varint
    data += encode_field_varint(3, session_id)
    data += encode_field_bytes(4, req_bytes)  # req = embedded message
    return data

def build_bind_result_packet(token, error_code=0, uid="local"):
    """
    Constroi o pacote completo de BindResult pronto pra enviar via RC4.

    Retorna os bytes encriptados pra escrever na characteristic 0xAA00.
    """
    # 1. BindResult protobuf
    bind_result = build_bind_result(error_code, uid)

    # 2. RbpMsg_Req com o BindResult como payload
    req = build_rbp_msg_req(total=1, sn=0, val=bind_result)

    # 3. RbpMsg envelope
    session_id = random.randint(1, 0x7FFFFFFF)
    CMD_DEV_BIND_RESULT = 31
    rbp_msg = build_rbp_msg(
        protocol_ver=1,
        cmd=CMD_DEV_BIND_RESULT,
        session_id=session_id,
        req_bytes=req
    )

    print(f"\n  [Debug] BindResult protobuf: {bind_result.hex()}")
    print(f"  [Debug] RbpMsg_Req: {req.hex()}")
    print(f"  [Debug] RbpMsg completo: {rbp_msg.hex()}")
    print(f"  [Debug] RbpMsg tamanho: {len(rbp_msg)} bytes")
    print(f"  [Debug] sessionId: {session_id}")

    # 4. RC4 encrypt com o token do binding
    encrypted = rc4(token, rbp_msg)

    return encrypted, session_id


def main():
    print("=" * 60)
    print("  HeyPlus W2100 - Binding via nRF Connect")
    print("=" * 60)

    token = gen_token()
    ka = mix_a(DEVICE_MAC, DEVICE_PID)
    kb = mix_b(DEVICE_MAC, DEVICE_PID)

    print(f"\nToken gerado: {token.hex()}")
    print(f"mixA: {ka.hex()}")
    print(f"mixB: {kb.hex()}")

    ss = int_to_bytes_le(RYEEX_REGISTER_SESSION_START)
    enc_token = rc4(ka, token)

    print()
    print("=" * 60)
    print("  FASE 1: Token Exchange (Servico 0xFE95)")
    print("=" * 60)

    print(f"""
PASSO 1: Conectar
  - Abra nRF Connect no celular
  - Scan -> encontre "hey+ Watch" -> CONNECT

PASSO 2: Ativar notificacao
  - Ache o servico "Unknown Service" com UUID 0xFE95
  - Dentro dele, ache a characteristic 0x0001 (tem Notify + Write)
  - Toque no icone de SINO pra ativar Notify

PASSO 3: Escrever SESSION_START
  - No MESMO servico 0xFE95, ache a characteristic 0x0010
  - Toque na SETA PRA CIMA pra escrever
  - Selecione tipo "ByteArray"
  - Digite: {format_hex(ss)}
  - Toque Send

PASSO 4: Escrever Token
  - Volte pra characteristic 0x0001
  - Toque na SETA PRA CIMA pra escrever
  - Selecione tipo "ByteArray"
  - Digite: {format_hex(enc_token)}
  - Toque Send

PASSO 5: Ler resposta
  - A characteristic 0x0001 deve ter recebido uma NOTIFICACAO
  - Copie o valor hex da notificacao recebida
  - Cole aqui no terminal:""")

    resp_hex = input("\n  Valor da notificacao (hex): ").strip()

    # Limpar input
    resp_hex = resp_hex.replace(" ", "").replace("-", "").replace("0x", "").replace("(", "").replace(")", "")
    try:
        resp_bytes = bytes.fromhex(resp_hex)
    except ValueError:
        print(f"  ERRO: '{resp_hex}' nao eh hex valido")
        return

    print(f"  Recebido: {resp_bytes.hex()} ({len(resp_bytes)} bytes)")

    # Validar - tenta normal
    dec = rc4(kb, rc4(ka, resp_bytes))
    ok = (dec == token)
    print(f"  Decriptado: {dec.hex()}")
    print(f"  Esperado:   {token.hex()}")

    if ok:
        print("  TOKEN VALIDADO!")
    else:
        # Tenta MAC reverso
        rev = ":".join(DEVICE_MAC.split(":")[::-1])
        ka2, kb2 = mix_a(rev, DEVICE_PID), mix_b(rev, DEVICE_PID)
        dec2 = rc4(kb2, rc4(ka2, resp_bytes))
        if dec2 == token:
            print("  TOKEN VALIDADO (MAC reverso)!")
        else:
            print("  Token NAO bateu.")
            print("  Continuando mesmo assim...")

    # Calcular ACK
    se = int_to_bytes_le(RYEEX_REGISTER_SESSION_END)
    ack = rc4(token, se)

    print(f"""
PASSO 6: Escrever ACK (SESSION_END)
  - Na characteristic 0x0001 (mesma de antes)
  - Toque na SETA PRA CIMA pra escrever
  - Selecione tipo "ByteArray"
  - Digite: {format_hex(ack)}
  - Toque Send
""")

    input("Aperte Enter depois de enviar o ACK...")

    print()
    print("=" * 60)
    print("  FASE 2: BindResult (Servico 0xB167)")
    print("=" * 60)

    # Perguntar UID
    uid = input("\n  UID do usuario (Enter pra 'local'): ").strip()
    if not uid:
        uid = "local"

    # Construir pacote BindResult
    bind_packet, session_id = build_bind_result_packet(token, error_code=0, uid=uid)

    print(f"""
PASSO 7: Ativar notificacao no servico Ryeex
  - Ache o servico "Unknown Service" com UUID 0xB167
  - Dentro dele, ache a characteristic 0xAA00 (tem Notify + Write)
  - Toque no icone de SINO pra ativar Notify

PASSO 8: Escrever BindResult (encriptado)
  - Na characteristic 0xAA00
  - Toque na SETA PRA CIMA pra escrever
  - Selecione tipo "ByteArray"
  - Digite: {format_hex(bind_packet)}
  - Toque Send

  Tamanho: {len(bind_packet)} bytes
  (Se maior que o MTU, o nRF Connect deve fragmentar automaticamente)
""")

    input("Aperte Enter depois de enviar o BindResult...")

    print("\nVerifique:")
    print("  1. O relogio saiu da tela de QR code?")
    print("  2. Houve alguma notificacao na characteristic 0xAA00?")
    print()
    print("Se houver notificacao, copie o valor hex:")
    resp2_hex = input("  Resposta (hex, ou Enter pra pular): ").strip()

    if resp2_hex:
        resp2_hex = resp2_hex.replace(" ", "").replace("-", "").replace("0x", "")
        try:
            resp2_bytes = bytes.fromhex(resp2_hex)
            # Decriptar a resposta com RC4(token)
            dec2 = rc4(token, resp2_bytes)
            print(f"  Resposta decriptada (hex): {dec2.hex()}")
            print(f"  Resposta decriptada (raw): {dec2}")

            # Tentar parsear como RbpMsg protobuf
            print("\n  Tentando parsear como RbpMsg protobuf...")
            parse_rbp_response(dec2)
        except ValueError:
            print(f"  ERRO: hex invalido")

    print()
    resp = input("O relogio saiu do QR code? (s/n): ").strip().lower()
    if resp == 's':
        print("\n  SUCESSO! O binding funcionou!")
        print("  Agora o relogio deve estar funcional.")
    else:
        print("\n  O relogio ainda ta no QR code.")
        print("  Possibilidades:")
        print("  - O token expirou (desconecta e refaz do passo 1)")
        print("  - O formato do pacote ta errado")
        print("  - Precisa de mais algum passo")
        print()
        print("  Copie qualquer log/resposta e compartilhe na conversa.")


def parse_rbp_response(data):
    """Tenta parsear bytes como um RbpMsg protobuf (parsing basico)."""
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        # Read tag
        tag_byte = data[pos]
        field_number = tag_byte >> 3
        wire_type = tag_byte & 0x07
        pos += 1

        if wire_type == 0:  # varint
            value = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                value |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            print(f"    field {field_number} (varint) = {value}")
        elif wire_type == 2:  # length-delimited
            length = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                pos += 1
                length |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
            payload = data[pos:pos+length]
            pos += length
            print(f"    field {field_number} (bytes, len={length}) = {payload.hex()}")
            # Tenta parsear recursivamente
            if field_number in (4, 5, 6):
                print(f"    -> parseando sub-message (field {field_number}):")
                parse_rbp_response(payload)
        else:
            print(f"    field {field_number} (wire_type={wire_type}) - nao suportado")
            break


if __name__ == "__main__":
    main()
