import time
import z3

def benchmark_smt():
    print("[+] Running SMT Solver Stress Benchmark (Z3 Bit-Vector Theory)...")
    
    # 1. Baseline Simple Add Expression: x + y == 0x12345678
    x = z3.BitVec('x', 64)
    y = z3.BitVec('y', 64)
    
    s1 = z3.Solver()
    s1.set("timeout", 10000)
    t0 = time.time()
    s1.add((x + y) == 0x12345678)
    res1 = s1.check()
    t1 = time.time()
    print(f"  [Baseline Simple Op] Z3 Check Result: {res1}, Time: {t1 - t0:.4f}s")
    
    # 2. Non-linear BPP + Bivariate MBA Expression:
    # P(x) = 0x9e3779b97f4a7c15 * x + 0x12345678 * x^2
    # P_inv(y) + (x ^ y) * y^2 == 0x12345678
    s2 = z3.Solver()
    s2.set("timeout", 30000)
    
    a1 = 0x9e3779b97f4a7c15
    c  = 0x12345678
    
    P_x = a1 * x + (2 * c) * (x * x)
    y_expr = P_x
    
    # Bivariate cross term
    biv_term = (x ^ y) * (y * y)
    
    s2.add((y_expr + biv_term) == 0x87654321)
    
    t0 = time.time()
    res2 = s2.check()
    t1 = time.time()
    print(f"  [BPP + Bivariate Non-linear MBA] Z3 Check Result: {res2}, Time: {t1 - t0:.4f}s")
    print(f"[+] SMT Complexity Explosion Ratio: > {((t1 - t0) / max(0.0001, (t1 - t0))):.1f}x")

if __name__ == '__main__':
    benchmark_smt()
