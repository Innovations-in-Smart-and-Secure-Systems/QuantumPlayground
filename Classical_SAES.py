import sys

class ClassicalSAES:
    """
    Simplified AES (S-AES) implementation in Python.

    - Block size: 16 bits (2 characters).
    - Key size: 16 bits (2 characters).
    - Encryption and decryption use substitution, permutation, key expansion,
      and mixing steps similar to full AES.

    Note:
    Although the code is functional with smaller block/key sizes (< 16 bits),
    encryption becomes much more predictable and insecure, making it unsuitable
    for real cryptographic use. Therefore, the reference implementation is 
    designed for exactly 16 bits.
    """

    GF_MUL_PRECOMPUTED_TERM = 0x3  # Polynomial for GF(2^4)

    # S-Boxes
    Sbox = [
        0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7
    ]

    InvSbox = [
        0xA, 0x5, 0x9, 0xB,
        0x1, 0x7, 0x8, 0xF,
        0x6, 0x0, 0x2, 0x3,
        0xC, 0x4, 0xD, 0xE
    ]

    # Round constants
    RCON = [0, 0x80, 0x30]

    def __init__(self, key: int):
        """Initialize with a 16-bit key."""
        self.roundkeys = [0, 0, 0]
        self.encryptState = [[0, 0], [0, 0]]
        self.decryptState = [[0, 0], [0, 0]]
        self.expand_key(key)

    # ---------- Key Expansion ----------
    def expand_key(self, originalKey: int):
        """Generates the three round keys from the original 16-bit key."""
        w = [0] * 6
        self.roundkeys[0] = originalKey
        w[0] = (self.roundkeys[0] >> 8) & 0xFF
        w[1] = self.roundkeys[0] & 0xFF

        w[2] = w[0] ^ self.RCON[1] ^ self.sub_nibble(self.rot_nibble(w[1]))
        w[3] = w[1] ^ w[2]
        self.roundkeys[1] = (w[2] << 8) | w[3]

        w[4] = w[2] ^ self.RCON[2] ^ self.sub_nibble(self.rot_nibble(w[3]))
        w[5] = w[3] ^ w[4]
        self.roundkeys[2] = (w[4] << 8) | w[5]

    # ---------- Utility ----------
    @staticmethod
    def add_round_key(data, roundKey):
        return data ^ roundKey

    @staticmethod
    def rot_nibble(value):
        return ((value << 4) | ((value >> 4) & 0xF)) & 0xFF

    def sub_nibble(self, value):
        """Substitute nibbles using the S-Box."""
        N0 = value & 0xF
        N1 = (value >> 4) & 0xF
        N0 = self.Sbox[N0]
        N1 = self.Sbox[N1]
        return (N1 << 4) | N0

    @staticmethod
    def update_state_matrix(State, data):
        """Load 16-bit data into 2x2 state matrix."""
        mask = 0xF
        State[0][0] = (data >> 12) & mask
        State[1][0] = (data >> 8) & mask
        State[0][1] = (data >> 4) & mask
        State[1][1] = data & mask

    @staticmethod
    def state_to_data(State):
        """Convert state matrix to 16-bit word."""
        return (State[0][0] << 12) | (State[1][0] << 8) | (State[0][1] << 4) | State[1][1]

    @staticmethod
    def normalize_bits(bitstring: str, name: str) -> int:
        """
        Normalize input bitstring.
        - If < 16 bits: pad with leading zeros and warn about predictability.
        - If > 16 bits: truncate to last 16 bits and warn.
        """
        if any(c not in "01" for c in bitstring):
            raise ValueError(f"{name} must contain only '0' or '1'.")

        if len(bitstring) < 16:
            print(f"⚠️ Warning: {name} has less than 16 bits ({len(bitstring)} bits). "
                  "Encryption may be predictable/insecure.")
            bitstring = bitstring.zfill(16)
        elif len(bitstring) > 16:
            print(f"⚠️ Warning: {name} has more than 16 bits. "
                  "It will be truncated to the last 16 bits.")
            bitstring = bitstring[-16:]

        return int(bitstring, 2)
    
    @staticmethod
    def int_to_bitstring(value: int, length: int = 16) -> str:
        """Convert integer to fixed-length bitstring."""
        return format(value, f'0{length}b')


    # ---------- Encryption steps ----------
    def substitute_nibbles(self):
        for i in range(2):
            for j in range(2):
                self.encryptState[i][j] = self.Sbox[self.encryptState[i][j]]

    def shift_row(self):
        self.encryptState[1][0], self.encryptState[1][1] = self.encryptState[1][1], self.encryptState[1][0]

    def mix_columns(self):
        old = [[self.encryptState[i][j] for j in range(2)] for i in range(2)]
        for i in range(2):
            for j in range(2):
                self.encryptState[i][j] = old[i][j] ^ self.gf_multiply(old[(i + 1) % 2][j], 4)

    # ---------- Decryption steps ----------
    def inverse_substitute_nibbles(self):
        for i in range(2):
            for j in range(2):
                self.decryptState[i][j] = self.InvSbox[self.decryptState[i][j]]

    def inverse_shift_row(self):
        self.decryptState[1][0], self.decryptState[1][1] = self.decryptState[1][1], self.decryptState[1][0]

    def inverse_mix_columns(self):
        old = [[self.decryptState[i][j] for j in range(2)] for i in range(2)]
        for i in range(2):
            for j in range(2):
                self.decryptState[i][j] = self.gf_multiply(old[i][j], 9) ^ self.gf_multiply(old[(i + 1) % 2][j], 2)

    # ---------- Finite Field Arithmetic ----------
    def gf_multiply(self, data, mulValue):
        """Finite field multiplication in GF(2^4)."""
        result = data
        if mulValue == 2:
            if (result >> 3) & 1:
                result = ((result << 1) & 0x0F) ^ self.GF_MUL_PRECOMPUTED_TERM
            else:
                result = (result << 1) & 0x0F
        elif mulValue == 4:
            for _ in range(2):
                if (result >> 3) & 1:
                    result = ((result << 1) & 0x0F) ^ self.GF_MUL_PRECOMPUTED_TERM
                else:
                    result = (result << 1) & 0x0F
        elif mulValue == 9:
            temp = result
            for _ in range(3):
                if (result >> 3) & 1:
                    result = ((result << 1) & 0x0F) ^ self.GF_MUL_PRECOMPUTED_TERM
                else:
                    result = (result << 1) & 0x0F
            result ^= temp
        return result

    # ---------- Main Encryption/Decryption ----------
    def encrypt(self, plaintext: int) -> int:
        """Encrypt a 16-bit plaintext block."""
        addRoundOutput = self.add_round_key(plaintext, self.roundkeys[0])

        self.update_state_matrix(self.encryptState, addRoundOutput)
        self.substitute_nibbles()
        self.shift_row()
        self.mix_columns()
        mixOut = self.state_to_data(self.encryptState)
        addRoundOutput = self.add_round_key(mixOut, self.roundkeys[1])

        self.update_state_matrix(self.encryptState, addRoundOutput)
        self.substitute_nibbles()
        self.shift_row()
        shiftOut = self.state_to_data(self.encryptState)
        ciphertext = self.add_round_key(shiftOut, self.roundkeys[2])
        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        """Decrypt a 16-bit ciphertext block."""
        addRoundOutput = self.add_round_key(ciphertext, self.roundkeys[2])

        self.update_state_matrix(self.decryptState, addRoundOutput)
        self.inverse_shift_row()
        self.inverse_substitute_nibbles()
        invOut = self.state_to_data(self.decryptState)
        addRoundOutput = self.add_round_key(invOut, self.roundkeys[1])

        self.update_state_matrix(self.decryptState, addRoundOutput)
        self.inverse_mix_columns()
        self.inverse_shift_row()
        self.inverse_substitute_nibbles()
        invOut = self.state_to_data(self.decryptState)
        plaintext = self.add_round_key(invOut, self.roundkeys[0])
        return plaintext



def interactive_mode():
    # Key input
    key_bits = input("Enter the key (<=16 bits, e.g., 1011 or 0100101011110101): ").strip()
    key = ClassicalSAES.normalize_bits(key_bits, "Key")

    # Create S-AES instance
    saes = ClassicalSAES(key)

    # Text input
    text_bits = input("Enter the text to encrypt (<=16 bits): ").strip()
    plaintext = ClassicalSAES.normalize_bits(text_bits, "Plaintext")

    # Encryption
    ciphertext = saes.encrypt(plaintext)
    print("\n--- RESULTS ---")
    print("Plaintext (bits):", ClassicalSAES.int_to_bitstring(plaintext))
    print("Key        (bits):", ClassicalSAES.int_to_bitstring(key))
    print("Ciphertext (bits):", ClassicalSAES.int_to_bitstring(ciphertext))

    # Decryption
    decrypted = saes.decrypt(ciphertext)
    print("Decrypted  (bits):", ClassicalSAES.int_to_bitstring(decrypted))


def fixed_demo_mode():
    """
    Fixed demo: plaintext and key are hard-coded here.
    Change key_bits_fixed and text_bits_fixed if you want other fixed values.
    """
    # Example fixed values (16 bits each)
    key_bits_fixed = "0100101011110101"
    text_bits_fixed = "1101011100101000"

    print("Running fixed demo with hard-coded key and plaintext.")
    print(f"Fixed key  (bits): {key_bits_fixed}")
    print(f"Fixed plain(bits): {text_bits_fixed}")

    # Normalize (will not warn because they are exactly 16 bits)
    key = ClassicalSAES.normalize_bits(key_bits_fixed, "Key")
    plaintext = ClassicalSAES.normalize_bits(text_bits_fixed, "Plaintext")

    # Create instance and run
    saes = ClassicalSAES(key)
    ciphertext = saes.encrypt(plaintext)
    decrypted = saes.decrypt(ciphertext)

    print("\n--- FIXED DEMO RESULTS ---")
    print("Plaintext  (bits):", ClassicalSAES.int_to_bitstring(plaintext))
    print("Key        (bits):", ClassicalSAES.int_to_bitstring(key))
    print("Ciphertext (bits):", ClassicalSAES.int_to_bitstring(ciphertext))
    print("Decrypted  (bits):", ClassicalSAES.int_to_bitstring(decrypted))


if __name__ == "__main__":
    # If script called with --fixed, run fixed demo; otherwise run interactive.
    if "--fixed" in sys.argv:
        fixed_demo_mode()
    else:
        # If running in an environment where stdin is not interactive (e.g., some notebooks),
        # still try interactive_mode — it will raise if input() isn't available.
        try:
            interactive_mode()
        except (EOFError, KeyboardInterrupt):
            # Fallback to fixed demo if no interactive input is possible
            print("\nNo interactive input detected — falling back to fixed demo.")
            fixed_demo_mode()


# ----------------- MODES -----------------
def fixed_demo_mode():
    key_bits_fixed = "0100101011110101"
    text_bits_fixed = "1101011100101000"

    print("=== Values hard-coded ===")
    key = ClassicalSAES.normalize_bits(key_bits_fixed, "Key")
    plaintext = ClassicalSAES.normalize_bits(text_bits_fixed, "Plaintext")

    saes = ClassicalSAES(key)
    ciphertext = saes.encrypt(plaintext)
    decrypted = saes.decrypt(ciphertext)

    print("Plaintext  (bits):", ClassicalSAES.int_to_bitstring(plaintext))
    print("Key        (bits):", ClassicalSAES.int_to_bitstring(key))
    print("Ciphertext (bits):", ClassicalSAES.int_to_bitstring(ciphertext))
    print("Decrypted  (bits):", ClassicalSAES.int_to_bitstring(decrypted))


def interactive_mode():
    print("=== Interactive mode ===")
    key_bits = input("Enter the key (<=16 bits): ").strip()
    text_bits = input("Enter the text (<=16 bits): ").strip()

    key = ClassicalSAES.normalize_bits(key_bits, "Key")
    plaintext = ClassicalSAES.normalize_bits(text_bits, "Plaintext")

    saes = ClassicalSAES(key)
    ciphertext = saes.encrypt(plaintext)
    decrypted = saes.decrypt(ciphertext)

    print("Plaintext  (bits):", ClassicalSAES.int_to_bitstring(plaintext))
    print("Key        (bits):", ClassicalSAES.int_to_bitstring(key))
    print("Ciphertext (bits):", ClassicalSAES.int_to_bitstring(ciphertext))
    print("Decrypted  (bits):", ClassicalSAES.int_to_bitstring(decrypted))


if __name__ == "__main__":
    # By default it uses fixed values
    if "--interactive" in sys.argv:
        interactive_mode()
    else:
        fixed_demo_mode()