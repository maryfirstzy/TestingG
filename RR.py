import re
from ecdsa.curves import SECP256k1

# SECP256k1 Curve Order - Added () to properly call the method and get the integer
N = SECP256k1.generator.order()

# Your precise log data
raw_log = """
-------------------------------
 -> Scanning address: Address: 1LFSRp9dhPNV8RSULb5KbzuTB6uMUa4Bd1
 -> Scanning address: R: 7e0077d060a735ac7d21f7203f8ab4c2f2d4706a1af8f97e243a1ea3ab3d50ff
 -> Scanning address: S: bd0b470fbdf216cb13f9df43034606e402ac10bef138bbf871166802656c725d
 -> Scanning address: Z: da3354c9859adb5547a2f0e72d5a86dc77d609aa2a66bea1e7374333787864e3
 -> Scanning address: ----------------------------------------
 -> Scanning address: Address: 1LFSRp9dhPNV8RSULb5KbzuTB6uMUa4Bd1
 -> Scanning address: R: 7e0077d060a735ac7d21f7203f8ab4c2f2d4706a1af8f97e243a1ea3ab3d50ff
 -> Scanning address: S: d05a25134c236a8943d8985275e211c0f45c518c6f98831628a10da77f1f4e09
 -> Scanning address: Z: f6221fa926352085759b2f15c7caacb54c83931e9bdb75b1bab55a5512b198fd
"""

def parse_and_solve(log_text):
    # Extract hex strings and convert them cleanly to base-16 integers
    r_vals = [int(x, 16) for x in re.findall(r'R:\s*([a-fA-F0-9]+)', log_text)]
    s_vals = [int(x, 16) for x in re.findall(r'S:\s*([a-fA-F0-9]+)', log_text)]
    z_vals = [int(x, 16) for x in re.findall(r'Z:\s*([a-fA-F0-9]+)', log_text)]
    
    if len(r_vals) < 2 or len(s_vals) < 2 or len(z_vals) < 2:
        print("Error: Could not parse at least two full transaction profiles from the log.")
        return

    # Assign distinct variables for the pair calculation
    r1, r2 = r_vals[0], r_vals[1]
    s1, s2 = s_vals[0], s_vals[1]
    z1, z2 = z_vals[0], z_vals[1]

    if r1 != r2:
        print("The R values do not match. This is not a classic nonce reuse anomaly.")
        return

    print("[+] Confirmed Classic Nonce Reuse Attack Matrix (R1 == R2).")
    
    # Mathematical calculation: k = (z1 - z2) / (s1 - s2) mod N
    delta_z = (z1 - z2) % N
    delta_s = (s1 - s2) % N
    
    try:
        # Modular inverse using Fermat's Little Theorem since N is prime
        inv_delta_s = pow(delta_s, N - 2, N)
        k = (delta_z * inv_delta_s) % N
        print(f"[+] Recovered Secret Nonce (k): {hex(k)}")
        
        # Mathematical calculation: d = (s1 * k - z1) / r mod N
        inv_r = pow(r1, N - 2, N)
        private_key = (((s1 * k) - z1) * inv_r) % N
        
        print(f"\n[CRITICAL] Private Key Recovered (Hex):")
        print(f"{hex(private_key)[2:].zfill(64)}")
        
    except ZeroDivisionError:
        print("Execution failed: Modular calculation encountered a division by zero.")

if __name__ == "__main__":
    parse_and_solve(raw_log)
