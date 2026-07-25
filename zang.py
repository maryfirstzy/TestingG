import os
import re
from fractions import Fraction

# SECP256k1 Curve Order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- 1. PURE PYTHON LLL ENGINE ---

def dot_product(v1, v2):
    return sum(x * y for x, y in zip(v1, v2))

def create_rational_vector(v):
    return [Fraction(x, 1) for x in v]

def lll_reduction(basis, delta=0.75):
    """
    Pure Python execution of the Lenstra-Lenstra-Lovasz (LLL) 
    lattice basis reduction algorithm using precise Fraction math.
    """
    n = len(basis)
    m = len(basis[0])
    
    b = [create_rational_vector(row) for row in basis]
    mu = [[Fraction(0, 1)] * n for _ in range(n)]
    b_star = [[Fraction(0, 1)] * m for _ in range(n)]

    def update_gram_schmidt(start_idx=0):
        for i in range(start_idx, n):
            b_star[i] = list(b[i])
            for j in range(i):
                dot_star = dot_product(b_star[j], b_star[j])
                if dot_star == 0:
                    mu[i][j] = Fraction(0, 1)
                else:
                    mu[i][j] = Fraction(dot_product(b[i], b_star[j]), dot_star)
                for k in range(m):
                    b_star[i][k] -= mu[i][j] * b_star[j][k]

    update_gram_schmidt(0)
    k = 1
    
    while k < n:
        for j in reversed(range(k)):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round(mu[k][j])
                for i in range(m):
                    b[k][i] -= q * b[j][i]
                update_gram_schmidt(j)
        
        lhs = dot_product(b_star[k], b_star[k])
        rhs = (Fraction(delta) - mu[k][k-1]**2) * dot_product(b_star[k-1], b_star[k-1])
        
        if lhs >= rhs:
            k += 1
        else:
            b[k], b[k-1] = b[k-1], b[k]
            update_gram_schmidt(k-1)
            k = max(k - 1, 1)

    return [[int(x) for x in row] for row in b]


# --- 2. HNP AUTOMATED SOLVER ---

def solve_unknown_multiplier_pure_lll(r1, s1, z1, r2, s2, z2):
    """
    Formulates a 3D HNP lattice matrix and runs the pure-Python LLL 
    algorithm to automatically extract the multiplier and private key.
    """
    inv_s1 = pow(s1, N - 2, N)
    inv_s2 = pow(s2, N - 2, N)
    
    t1 = (inv_s1 * r1) % N
    u1 = (inv_s1 * z1) % N
    t2 = (inv_s2 * r2) % N
    u2 = (inv_s2 * z2) % N
    
    # Upper search space bound for the linear scaling factor
    B = 2**64 
    
    lattice_matrix = [
        [N, 0, 0],
        [t2, -t1, B],
        [u2, -u1, 0]
    ]
    
    reduced_matrix = lll_reduction(lattice_matrix, delta=0.75)
    
    for row in reduced_matrix:
        potential_a = abs(row[2] // B)
        
        if potential_a == 0:
            continue
            
        numerator = (potential_a * s2 * z1 - s1 * z2) % N
        denominator = (s1 * r2 - potential_a * s2 * r1) % N
        
        if denominator == 0:
            continue
            
        potential_d = (numerator * pow(denominator, N - 2, N)) % N
        
        if potential_d > 0:
            k1_check = (inv_s1 * (z1 + r1 * potential_d)) % N
            k2_check = (inv_s2 * (z2 + r2 * potential_d)) % N
            
            if k2_check == (potential_a * k1_check) % N:
                print("\n=======================================================")
                print(" [CRITICAL] UNKNOWN MULTIPLIER CRACKED VIA NATIVE LLL")
                print("=======================================================")
                print(f" Recovered Multiplier Factor (a): {potential_a}")
                print(f" Recovered Private Key (Hex):     {hex(potential_d)[2:].zfill(64)}")
                print("=======================================================\n")
                return True
                
    return False


# --- 3. FILE SYSTEM MANAGEMENT ---

def run_file_scanner(filename="BOOG.txt"):
    """
    Validates, parses, and processes target entries from READ.txt
    """
    if not os.path.exists(filename):
        print(f"[-] Input file '{filename}' not found.")
        print(f"[*] Instantiating a clean '{filename}' with an active Linear Nonce challenge vector...")
        
        # Writes an active linear test vector (a=5) into the file for instant testing
        test_vector = """-------------------------------
 -> Scanning address: Address: 1LinearSimulationTestingAddress
 -> Scanning address: R: 1826b5d63f081ed73ce02b0c1630faeef709c0ba025732ef1372afcb41d5e6bf
 -> Scanning address: S: cd23a5e173df82aa301eec956bca70fe15bb2b45cd6ea309bcde31fa1a2c34ff
 -> Scanning address: Z: 3f1a26bc8edc5021aae259cb21edcf1544aae72df486eb4025eafe6cd21bcde3
----------------------------------------
 -> Scanning address: Address: 1LinearSimulationTestingAddress
 -> Scanning address: R: 74ae63bc51ed42aae00e1236fbce72d415ffec72da51ec43de89fa12cb14b531
 -> Scanning address: S: 9a23fe41caed50bc11ea2bdf23dc58fe72ba56cd2a1ee8c201befe4ca237df12
 -> Scanning address: Z: 7a1e2fbc410ed8ea23be12cbfe14ed583aae01efcbde45aa1a2e3fcbe14b8a21
-------------------------------"""
        with open(filename, "w") as f:
            f.write(test_vector)
        print(f"[+] '{filename}' initialized successfully. Re-running execution pipeline.\n")

    print(f"[*] Reading and parsing target matrix profiles from {filename}...")
    with open(filename, "r") as f:
        content = f.read()

    r_vals = [int(x, 16) for x in re.findall(r'R:\s*([a-fA-F0-9]+)', content)]
    s_vals = [int(x, 16) for x in re.findall(r'S:\s*([a-fA-F0-9]+)', content)]
    z_vals = [int(x, 16) for x in re.findall(r'Z:\s*([a-fA-F0-9]+)', content)]

    total_signatures = len(r_vals)
    print(f"[*] Extracted {total_signatures} cryptographic signature parameter lines.")

    if total_signatures < 2:
        print("[-] Error: The file must contain at least 2 complete signature sets to run pairwise lattice analysis.")
        return

    success = False
    # Execute a pairwise comparison cross-sweep through all parsed structures
    for i in range(total_signatures):
        for j in range(i + 1, total_signatures):
            print(f"[*] Analyzing signature link pair: Set [{i}] against Set [{j}]...")
            if solve_unknown_multiplier_pure_lll(r_vals[i], s_vals[i], z_vals[i], r_vals[j], s_vals[j], z_vals[j]):
                success = True
                
    if not success:
        print("[-] Scanning complete. No low-bound hidden multiplier anomalies resolved in this log batch.")

if __name__ == "__main__":
    run_file_scanner("BOOG.txt")
