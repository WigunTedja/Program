import sys
from pathlib import Path
import tracemalloc
import gc

# 1. Lacak posisi file ini, lalu naik 4 level ke atas menuju folder root 'paillier_bank'
# (memori -> tests -> banking -> paillier_bank)
project_root = Path(__file__).resolve().parent.parent.parent.parent

# 2. Masukkan folder root tersebut ke dalam penglihatan Python
sys.path.append(str(project_root))

# 3. BARU SEKARANG lakukan import module banking
from banking import utils

def benchmark_pembangkitan_kunci():
    print("\nBenchmark Memori Pembangkitan Kunci (dengan GC Manual)")
    keys_arr = [512, 1024, 2048, 3072]
    
    for size in keys_arr:
        print(f"\n--- Pembangkitan 100 kunci {size}-bits ---")
        peak_memory_arr = []
        
        for num in range(1, 101):  
            # 1. Hancurkan referensi variabel dari iterasi sebelumnya secara eksplisit
            if 'pub' in locals():
                del pub
            if 'priv' in locals():
                del priv
            
            # 2. Paksa Garbage Collector berjalan SEKARANG
            # Ini memastikan RAM sebersih mungkin sebelum kita mulai mengukur
            gc.collect()
            
            # 3. Mulai pelacakan memori
            tracemalloc.start()

            # 4. Eksekusi target pengujian
            pub, priv = utils.generate_paillier_keypair(n_length=size)
            
            # 5. Catat puncak memori selama fungsi berjalan
            current, peak = tracemalloc.get_traced_memory()
            
            # 6. Hentikan tracemalloc agar tidak ikut merekam operasi array di bawah ini
            tracemalloc.stop()
            peak_memory_arr.append(peak) # Dalam format Bytes
            
        mean_peak_memory_kb = (sum(peak_memory_arr) / 100)
        max_peak_memory_kb = max(peak_memory_arr)
        
        print(f"Rata-rata puncak memori: {mean_peak_memory_kb:.2f} Bytes")
        print(f"Puncak memori absolut tertinggi: {max_peak_memory_kb:.2f} Bytes")

if __name__ == "__main__":
    # PERINGATAN: Matikan GC otomatis Python di level global selama script berjalan 
    # agar tidak mengganggu pengukuran waktu secara acak di tengah-tengah fungsi Anda.
    gc.disable() 
    try:
        benchmark_pembangkitan_kunci()
    finally:
        gc.enable() # Kembalikan ke keadaan semula