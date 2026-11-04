import time
import json
import csv
from math import pi, sqrt, floor
from collections import Counter
from qat.lang.AQASM import Program, QRoutine, Z, H, X, CNOT
from qat.qpus import LinAlg

# Import the ClassicalSAES class
from Classical_SAES import ClassicalSAES

# -----------------------------------------
# Selecting bits from an external csv file
# -----------------------------------------
# Specify the desired number of bits here
desired_bits = 8  # Change this to 8,10,12,14 or 16 as needed

print(f"\n=== Running for {desired_bits} bits ===")
# Read from CSV file and find the row matching desired_bits
found = False
try:
    with open('data.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        header = next(reader)
        for row in reader:
            if row and int(row[0].strip()) == desired_bits:
                key_bits = row[1].strip()
                plaintext_bits = row[2].strip()
                found = True
                break
    if found:
        print(f"Loaded key and plaintext for {desired_bits} bits from data.csv")
    else:
        raise FileNotFoundError("No matching bits found")
except FileNotFoundError:
    print("data.csv not found or no matching bits, using manual values")
    key_bits = "01001010"
    plaintext_bits = "11010110"

# -----------------------------------
# Cipher selection (SAES vs XOR toy)
# -----------------------------------
USE_SAES = True  # now we always use the class
key = int(key_bits, 2)
plaintext = int(plaintext_bits, 2)
n_key = desired_bits  # Use the specified number of bits
if USE_SAES:
    # Normalize key and plaintext (assuming normalize_bits handles padding to 16 bits for SAES)
    key = ClassicalSAES.normalize_bits(key_bits, "Key")
    plaintext = ClassicalSAES.normalize_bits(plaintext_bits, "Plaintext")
    saes = ClassicalSAES(key)

    # Define encryption/decryption using the class
    Encrypt = lambda pt, k: saes.encrypt(pt)
    Decrypt = lambda ct, k: saes.decrypt(ct)
else:
    # Fallback XOR toy cipher
    def XOR_Encryption(pt, k, n_bits):
        mask = (1 << n_bits) - 1
        return (pt ^ k) & mask

    def XOR_Decryption(ct, k, n_bits):
        mask = (1 << n_bits) - 1
        return (ct ^ k) & mask

    Encrypt = lambda pt, k: XOR_Encryption(pt, k, n_key)
    Decrypt = lambda ct, k: XOR_Decryption(ct, k, n_key)

# -----------------------------------
# Helper for formatting binary strings
# -----------------------------------
def fmt(x): return format(x, f'0{n_key}b')

# Test single-block encryption
ciphertext = Encrypt(plaintext, key)
print("=== Single block example ===")
print(f"Key:        {fmt(key)}")
print(f"Plaintext:  {fmt(plaintext)}  (hex {plaintext:X})")
print(f"Ciphertext: {fmt(ciphertext)}  (hex {ciphertext:X})")

# -----------------------------------
# Timing start (circuit build)
# -----------------------------------
t0 = time.perf_counter()

# Quantum registers
prog = Program()
key_q = prog.qalloc(n_key)
flag_q = prog.qalloc(1)

max_anc = max(0, n_key - 2)
anc_q = prog.qalloc(max_anc)

# Prepare flag in |-> for phase kickback
prog.apply(X, flag_q[0])
prog.apply(H, flag_q[0])

# Put key register into uniform superposition
for q in key_q:
    prog.apply(H, q)

solution_bits = format(key, f'0{n_key}b')

# --------------------------------------
# Helper function for MCX as QRoutine with abstract wires
# --------------------------------------
def mcx_routine(n_controls):
    rout = QRoutine()
    if n_controls == 0:
        target = rout.new_wires(1)
        rout.apply(X, target)
    elif n_controls == 1:
        control = rout.new_wires(1)
        target = rout.new_wires(1)
        rout.apply(CNOT, control, target)
    elif n_controls == 2:
        c1 = rout.new_wires(1)
        c2 = rout.new_wires(1)
        target = rout.new_wires(1)
        rout.apply(X.ctrl(2), c1, c2, target)
    else:
        controls = rout.new_wires(n_controls)
        target = rout.new_wires(1)
        ancillas = rout.new_wires(n_controls - 2)
        # Forward
        rout.apply(X.ctrl(2), controls[0], controls[1], ancillas[0])
        for i in range(2, n_controls - 1):
            rout.apply(X.ctrl(2), controls[i], ancillas[i - 2], ancillas[i - 1])
        rout.apply(X.ctrl(2), controls[n_controls - 1], ancillas[n_controls - 3], target)
        # Reverse
        for i in range(n_controls - 2, 1, -1):
            rout.apply(X.ctrl(2), controls[i], ancillas[i - 2], ancillas[i - 1])
        rout.apply(X.ctrl(2), controls[0], controls[1], ancillas[0])
    return rout

# -----------------------------------
# Grover oracle
# -----------------------------------
def oracle_routine(n_key, solution_bits):
    rout = QRoutine()
    key_wires = rout.new_wires(n_key)
    flag = rout.new_wires(1)
    anc_needed = max(0, n_key - 2)
    if anc_needed > 0:
        anc_wires = rout.new_wires(anc_needed)
    with rout.compute():
        # Flip where solution bit is '0'
        for i, b in enumerate(solution_bits):
            if b == "0":
                rout.apply(X, key_wires[i])
    # Apply decomposed MCX
    mcx = mcx_routine(n_key)
    if anc_needed > 0:
        rout.apply(mcx, *key_wires, flag, *anc_wires)
    else:
        rout.apply(mcx, *key_wires, flag)
    rout.uncompute()
    return rout

# -----------------------------------
# Grover diffuser
# -----------------------------------
def diffuser_routine(n_key):
    rout = QRoutine()
    wires = rout.new_wires(n_key)
    n_controls = n_key - 1
    anc_needed = max(0, n_controls - 2)
    if anc_needed > 0:
        anc_wires = rout.new_wires(anc_needed)
    with rout.compute():
        for w in wires:
            rout.apply(H, w)
            rout.apply(X, w)
    # MCZ = H + MCX + H on target (last wire)
    target = wires[-1]
    controls = wires[:-1]
    rout.apply(H, target)
    mcx = mcx_routine(n_controls)
    if anc_needed > 0:
        rout.apply(mcx, *controls, target, *anc_wires)
    else:
        rout.apply(mcx, *controls, target)
    rout.apply(H, target)
    rout.uncompute()
    return rout

# -------------------------
# Compute number of Grover iterations
# -------------------------
N = 2**n_key
M = 1  # Single solution
r = floor((pi/4) * sqrt(N / M))
print("Grover iterations (computed):", r)

oracle = oracle_routine(n_key, solution_bits)
diffuser = diffuser_routine(n_key)

# -------------------------
# Run Grover iterations
# -------------------------
anc_oracle_count = max(0, n_key - 2)
anc_diffuser_count = max(0, n_key - 3)
for _ in range(r):
    prog.apply(oracle, list(key_q) + [flag_q[0]] + list(anc_q[:anc_oracle_count]))
    prog.apply(diffuser, list(key_q) + list(anc_q[:anc_diffuser_count]))

# Unprepare flag
prog.apply(H, flag_q[0])
prog.apply(X, flag_q[0])

# Create the circuit
circ = prog.to_circ()

t1 = time.perf_counter()

# -----------------------------------
# Simulation timing
# -----------------------------------
qpu = LinAlg()
shots = 1024
t2 = time.perf_counter()
job = circ.to_job(qubits=key_q, nbshots=shots)
result = qpu.submit(job)
t3 = time.perf_counter()

# -----------------------------------
# Process results
# -----------------------------------
counts = Counter()
for sample in result:
    bitstring = "".join(str(int(b)) for b in sample.state)  # List of bits
    counts[bitstring] += int(sample.probability * shots)

most_likely = max(counts, key=counts.get)
most_likely_int = int(most_likely, 2)
success = (most_likely_int == key)

print("Top measurement counts:", counts.most_common(10))
print("Most likely key measured:", format(most_likely_int, f'0{n_key}b'))
print("Matches actual key:", most_likely_int == key)

# ---------------------------------
# Functions to get some statistics
# ---------------------------------
def get_circuit_depth(circ):
    """
    Compute an approximate circuit depth for a QLM circuit.
    """
    nbqbits = circ.statistics()['nbqbits']
    layers = [0] * nbqbits

    for gate in circ.iterate_simple():
        _, _, targets = gate
        for q_target in targets:
            layers[q_target] += 1

    return max(layers)

def get_gates_type(circuit):
    """
    Count gates by type.
    """
    gates = {}
    for op in circuit.iterate_simple():
        gate_name = op[0]
        gates[gate_name] = gates.get(gate_name, 0) + 1
    return gates

# -----------------------------------
# Circuit stats
# -----------------------------------
print("=== Circuit information ===")
print("Number of qubits:", circ.nbqbits)
print("Number of classical bits:", n_key)
print("Circuit depth:", get_circuit_depth(circ))
print("Number of operations:", len(circ.ops))
print(get_gates_type(circ))
print("===========================")

# -----------------------------------
# Timing breakdown
# -----------------------------------
build_time = t1 - t0
emulation_time = t3 - t2
total_time = build_time + emulation_time

print(f"Build time: {build_time:.4f} s")
print(f"Emulation time: {emulation_time:.4f} s")
print(f"Total time: {total_time:.4f} s")


# -----------------------------------
# Save results to CSV
# -----------------------------------
csv_file = "emulation_record_qaptiva.csv"
ops_counts_str = json.dumps(get_gates_type(circ))

fieldnames = [
    "key", "key_length_bits", "num_qubits", "circuit_depth", "num_operations", "ops_counts",
    "build_time_s", "emulation_time_s", "total_time_s",
    "num_shots", "success"
]

row = {
    "key": fmt(key),
    "key_length_bits": n_key,
    "num_qubits": circ.nbqbits,
    "circuit_depth": get_circuit_depth(circ),
    "num_operations": len(circ.ops),
    "ops_counts": ops_counts_str,
    "build_time_s": build_time,
    "emulation_time_s": emulation_time,
    "total_time_s": total_time,
    "num_shots": shots,
    "success": success,
}

try:
    with open(csv_file, "x", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)
except FileExistsError:
    with open(csv_file, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writerow(row)

print(f"Results saved to {csv_file}")