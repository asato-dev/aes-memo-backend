"""
aes.py - AES-256-CBC 暗号化モジュール

外部ライブラリを使わず、Python 標準ライブラリのみで AES-256-CBC 暗号化・復号を実装したモジュール。
暗号理論（有限体演算・鍵スケジュール・CBCモード）の理解を目的として作成。

仕様:
    - 鍵長:         256 bit (32 バイト)
    - ブロックサイズ: 128 bit (16 バイト)
    - 動作モード:    CBC (Cipher Block Chaining)
    - パディング:    PKCS#7
    - IV:           os.urandom(16) で暗号化ごとにランダム生成し、暗号文先頭に付加
"""

import os
import base64


# ================================================================
# AES 定数テーブル
# ================================================================

# S-Box: SubBytes 変換で使う非線形置換テーブル（256 エントリ）
# GF(2^8) 上の乗法逆元にアフィン変換を施して生成される。
# 差分解読・線形解読への耐性（非線形性）を提供する。
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# 逆 S-Box: 復号時の InvSubBytes で使う S-Box の逆写像テーブル
INV_SBOX = [
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]

# ラウンド定数: 鍵スケジュールで使用する定数列
# GF(2^8) 上で 2^(i-1) を計算した値（i = 1〜10）
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


# ================================================================
# GF(2^8) 有限体演算
# ================================================================

def xtime(b: int) -> int:
    """
    GF(2^8) 上で b に 2 を掛ける演算。

    1 ビット左シフト後、元の最上位ビットが 1 だった場合は
    既約多項式 x^8 + x^4 + x^3 + x + 1（= 0x11B）に相当する
    0x1B で XOR して剰余を取り、8 ビットに収める。

    Args:
        b: 入力バイト（0〜255）
    Returns:
        GF(2^8) 上での 2*b
    """
    return ((b << 1) ^ 0x1B) & 0xFF if b & 0x80 else (b << 1) & 0xFF


# ================================================================
# AES ラウンド変換（暗号化方向）
# ================================================================

def sub_bytes(state: list) -> list:
    """
    SubBytes 変換: 各バイトを S-Box で非線形置換する。

    AES の安全性の核となるステップ。S-Box の非線形性により、
    差分解読・線形解読への耐性を与える。

    Args:
        state: 16 バイトのブロック状態
    Returns:
        置換後の 16 バイトリスト
    """
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: list) -> list:
    """InvSubBytes 変換: SubBytes の逆変換（復号用）。"""
    return [INV_SBOX[b] for b in state]


def rot_left(row: list, n: int) -> list:
    """
    リストを左方向に n 要素だけ循環シフトする。

    例: rot_left([1,2,3,4], 1) → [2,3,4,1]
    """
    return row[n:] + row[:n]


def shift_rows(state: list) -> list:
    """
    ShiftRows 変換: 状態を 4×4 行列と見なし、各行を左循環シフトする。

    行ごとのシフト量:
        行 0（バイト  0〜 3）: シフトなし
        行 1（バイト  4〜 7）: 1 バイト左シフト
        行 2（バイト  8〜11）: 2 バイト左シフト
        行 3（バイト 12〜15）: 3 バイト左シフト

    効果: 異なる列のバイトを混合し、列単位の攻撃を困難にする（拡散）。
    """
    return (state[0:4]
            + rot_left(state[4:8],  1)
            + rot_left(state[8:12], 2)
            + rot_left(state[12:16], 3))


def inv_shift_rows(state: list) -> list:
    """InvShiftRows 変換: ShiftRows の逆変換（復号用）。各行を右循環シフトする。"""
    return (state[0:4]
            + rot_left(state[4:8],  3)
            + rot_left(state[8:12], 2)
            + rot_left(state[12:16], 1))


def mix_col(col: list) -> list:
    """
    MixColumns の 1 列分の演算。

    GF(2^8) 上の行列乗算を実施する:
        | 2 3 1 1 |   | b0 |
        | 1 2 3 1 | × | b1 |
        | 1 1 2 3 |   | b2 |
        | 3 1 1 2 |   | b3 |

    3*b = xtime(b) ^ b としてビット演算で表現する。
    効果: 1 バイトの変化が列全体に波及する（拡散・雪崩効果）。
    """
    b0, b1, b2, b3 = col
    return [
        xtime(b0) ^ (xtime(b1) ^ b1) ^ b2             ^ b3,
        b0         ^ xtime(b1)        ^ (xtime(b2)^b2) ^ b3,
        b0         ^ b1               ^ xtime(b2)       ^ (xtime(b3)^b3),
        (xtime(b0)^b0) ^ b1           ^ b2              ^ xtime(b3),
    ]


def mix_columns(state: list) -> list:
    """MixColumns 変換: 状態の全 4 列に mix_col を適用する。"""
    res = [0] * 16
    for c in range(4):
        col = mix_col([state[c], state[4+c], state[8+c], state[12+c]])
        res[c], res[4+c], res[8+c], res[12+c] = col
    return res


def inv_mix_col(col: list) -> list:
    """
    InvMixColumns の 1 列分の演算（復号用）。

    MixColumns の逆行列（GF(2^8) 上）を乗算する:
        | 14 11 13  9 |
        |  9 14 11 13 |
        | 13  9 14 11 |
        | 11 13  9 14 |

    各係数は xtime の入れ子でビット演算として表現する。
    例: 14*b = 8*b ^ 4*b ^ 2*b
    """
    b0, b1, b2, b3 = col
    x2  = lambda b: xtime(b)
    x4  = lambda b: xtime(xtime(b))
    x8  = lambda b: xtime(xtime(xtime(b)))
    x14 = lambda b: x8(b) ^ x4(b) ^ x2(b)  # 0x0e = 14
    x11 = lambda b: x8(b) ^ x2(b) ^ b       # 0x0b = 11
    x13 = lambda b: x8(b) ^ x4(b) ^ b       # 0x0d = 13
    x9  = lambda b: x8(b) ^ b                # 0x09 =  9
    return [
        x14(b0) ^ x11(b1) ^ x13(b2) ^ x9(b3),
        x9(b0)  ^ x14(b1) ^ x11(b2) ^ x13(b3),
        x13(b0) ^ x9(b1)  ^ x14(b2) ^ x11(b3),
        x11(b0) ^ x13(b1) ^ x9(b2)  ^ x14(b3),
    ]


def inv_mix_columns(state: list) -> list:
    """InvMixColumns 変換: 全 4 列に inv_mix_col を適用する（復号用）。"""
    res = [0] * 16
    for c in range(4):
        col = inv_mix_col([state[c], state[4+c], state[8+c], state[12+c]])
        res[c], res[4+c], res[8+c], res[12+c] = col
    return res


def add_round_key(state: list, round_key: list) -> list:
    """
    AddRoundKey 変換: 状態とラウンド鍵を XOR する。

    XOR は可逆演算なので、暗号化・復号で同じ関数を使える。
    鍵情報を状態に混入する唯一のステップ。
    """
    return [b ^ round_key[i] for i, b in enumerate(state)]


# ================================================================
# 鍵スケジュール（Key Expansion）
# ================================================================

def key_expansion(key: bytes) -> list:
    """
    元の鍵からラウンド鍵列を生成する（Rijndael 鍵スケジュール）。

    AES-256 (Nk=8) では 14 ラウンドのため、15 個のラウンド鍵を生成。
    各ラウンド鍵は 16 バイト（4 ワード）。

    アルゴリズム:
        - 最初の Nk ワードは元の鍵をそのまま使用
        - 以降: 前ワードと Nk 個前のワードを XOR して生成
        - Nk の倍数番目: RotWord → SubWord → RCON XOR を追加適用
        - AES-256 では Nk の倍数+4 番目にも SubWord を適用

    Args:
        key: 32 バイトの秘密鍵
    Returns:
        ラウンド鍵のリスト（各要素は 16 バイトのリスト）
    """
    nk = len(key) // 4  # ワード単位の鍵長（AES-256: 8）
    nr = nk + 6         # ラウンド数（AES-256: 14）

    w = [list(key[i*4 : i*4+4]) for i in range(nk)]

    for i in range(nk, 4 * (nr + 1)):
        tmp = w[i - 1][:]

        if i % nk == 0:
            tmp = sub_bytes(rot_left(tmp, 1))
            tmp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            tmp = sub_bytes(tmp)

        w.append([w[i - nk][j] ^ tmp[j] for j in range(4)])

    return [
        sum([w[r*4 + c] for c in range(4)], [])
        for r in range(nr + 1)
    ]


# ================================================================
# AES ブロック暗号化 / 復号
# ================================================================

def aes_encrypt_block(block: list, round_keys: list) -> list:
    """
    16 バイトの単一ブロックを AES で暗号化する。

    ラウンド構成（AES-256: 14 ラウンド）:
        初期ラウンド:    AddRoundKey
        ラウンド 1〜13: SubBytes → ShiftRows → MixColumns → AddRoundKey
        最終ラウンド:   SubBytes → ShiftRows → AddRoundKey（MixColumns なし）

    Args:
        block:      16 バイトの平文ブロック
        round_keys: key_expansion() で生成したラウンド鍵リスト
    Returns:
        16 バイトの暗号文ブロック
    """
    nr = len(round_keys) - 1
    state = add_round_key(list(block), round_keys[0])

    for r in range(1, nr + 1):
        state = sub_bytes(state)
        state = shift_rows(state)
        if r < nr:
            state = mix_columns(state)  # 最終ラウンドはスキップ
        state = add_round_key(state, round_keys[r])

    return state


def aes_decrypt_block(block: list, round_keys: list) -> list:
    """
    16 バイトの単一ブロックを AES で復号する。

    暗号化の逆順で各逆変換を適用する:
        初期:            AddRoundKey（最終ラウンド鍵）
        ラウンド nr-1〜1: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
        最終:            InvShiftRows → InvSubBytes → AddRoundKey（InvMixColumns なし）

    Args:
        block:      16 バイトの暗号文ブロック
        round_keys: key_expansion() で生成したラウンド鍵リスト
    Returns:
        16 バイトの平文ブロック
    """
    nr = len(round_keys) - 1
    state = add_round_key(list(block), round_keys[nr])

    for r in range(nr - 1, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        if r > 0:
            state = inv_mix_columns(state)  # ラウンド 0 はスキップ

    return state


# ================================================================
# PKCS#7 パディング
# ================================================================

def pkcs7_pad(data: bytes) -> bytes:
    """
    PKCS#7 パディングを付加する。

    16 バイト境界に揃えるよう末尾にパディングを追加する。
    パディングバイトの値 = 追加するバイト数（例: 3 バイト必要なら 0x03 を 3 個）。
    データがすでにブロック境界に揃っている場合も、必ず 1 ブロック分追加する。
    """
    pad = 16 - (len(data) % 16)
    return data + bytes([pad] * pad)


def pkcs7_unpad(data: bytes) -> bytes:
    """PKCS#7 パディングを除去する。末尾バイトの値がパディング長を示す。"""
    return data[:-data[-1]]


# ================================================================
# 公開 API: AES-256-CBC による文字列の暗号化・復号
# ================================================================

def aes_encrypt(plaintext: str, key: bytes) -> str:
    """
    文字列を AES-256-CBC で暗号化し、Base64 エンコードして返す。

    CBC モード:
        各ブロックを暗号化する前に、直前の暗号文ブロックと XOR する。
        同じ平文ブロックでも異なる暗号文が生成され、パターン解析への耐性が向上する。

        平文1 → XOR(IV)      → AES 暗号化 → 暗号文1
        平文2 → XOR(暗号文1) → AES 暗号化 → 暗号文2

    IV:
        os.urandom(16) で暗号化ごとにランダム生成し、復号に必要なため暗号文先頭に付加する。
        出力フォーマット: Base64( IV(16 バイト) + 暗号文 )

    Args:
        plaintext: 暗号化する平文文字列（UTF-8）
        key:       32 バイトの秘密鍵
    Returns:
        Base64 エンコードされた文字列（先頭 16 バイトが IV）
    """
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext.encode())

    iv = list(os.urandom(16))  # 暗号化ごとにランダムな IV を生成
    prev = iv
    out = []

    for i in range(0, len(padded), 16):
        block = [b ^ prev[j] for j, b in enumerate(padded[i:i+16])]
        enc = aes_encrypt_block(block, round_keys)
        out += enc
        prev = enc

    # IV を先頭に付加して返す（復号時に IV を取り出すために必要）
    return base64.b64encode(bytes(iv + out)).decode()


def aes_decrypt(ciphertext: str, key: bytes) -> str:
    """
    Base64 エンコードされた暗号文を AES-256-CBC で復号し、平文を返す。

    入力フォーマット: Base64( IV(16 バイト) + 暗号文 )
    先頭 16 バイトを IV として取り出し、残りを復号する。

    暗号文1 → AES 復号 → XOR(IV)      → 平文1
    暗号文2 → AES 復号 → XOR(暗号文1) → 平文2

    Args:
        ciphertext: Base64 エンコードされた暗号文字列
        key:        32 バイトの秘密鍵（暗号化時と同一）
    Returns:
        復号された平文文字列（UTF-8）
    """
    round_keys = key_expansion(key)
    data = list(base64.b64decode(ciphertext))

    iv   = data[:16]   # 先頭 16 バイトが IV
    data = data[16:]   # 残りが暗号文本体
    prev = iv
    out  = []

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        dec = aes_decrypt_block(block, round_keys)
        out += [b ^ prev[j] for j, b in enumerate(dec)]
        prev = block

    return pkcs7_unpad(bytes(out)).decode()
