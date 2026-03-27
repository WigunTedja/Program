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

def benchmark_penambahan():
    print("\nBenchmark  Memori Penambahan Homomorfik (dengan GC Manual)")
    data_arr = [1000,4679,17279,17298,20977,23077,23156,26835,26635,26736,30415,25115,25224,28903,21403,21487,21502,19035,22714,22014,22091,22106,19639,23318,20418,1100,21336,25036,25050,45286,34286,34395,54631,37031,37176,67530,45130,45290,42090,62326,49181,38881,39069,39084,31803,28903,49139,27853,26853,26992,1000,8502,8526,16326,23828,23907,21507,29009,29122,22222,29724,29847,22447,29949,30059,30074,27659,22959,21824,21497,17958,29211,26651,26749,26764,800,6353,11906,17459,23012,28565,27280,25380,25432,25447,23354,28907,27622,23522,23613,23627,21535,27088,25803,22503,22587,22602,20509,26062,24777]
    keys_arr = [512, 1024, 2048, 3072]
    for size in keys_arr:
        print(f"\n--- Penambahan Homomorfik 100 data dengan kunci {size}-bits ---")
        peak_memory_arr = []
        
        pub, priv = utils.generate_paillier_keypair(n_length=size)
        saldo = pub.encrypt(0).ciphertext()
        cipher_arr = []
        for plain in data_arr:
            cipher_arr.append(pub.encrypt(plain))
        for data in cipher_arr:  
            # 1. Hancurkan referensi variabel dari iterasi sebelumnya secara eksplisit
            if 'addition' in locals():
                del addition
            
            # 2. Paksa Garbage Collector berjalan SEKARANG
            # Ini memastikan RAM sebersih mungkin sebelum kita mulai mengukur
            gc.collect()
            
            # 3. Mulai pelacakan memori
            tracemalloc.start()
            # 4. Eksekusi target pengujian
            addition = utils.paillier_addition(saldo, data.ciphertext(), pub.n)
            # 5. Catat puncak memori selama fungsi berjalan
            current, peak = tracemalloc.get_traced_memory()
            
            # 6. Hentikan tracemalloc agar tidak ikut merekam operasi array di bawah ini
            tracemalloc.stop()
            peak_memory_arr.append(peak) # Dalam format Bytes
            saldo = addition
            
        mean_peak_memory = (sum(peak_memory_arr) / 100)
        max_peak_memory = max(peak_memory_arr)
        print(f"Rata-rata puncak memori: {mean_peak_memory:.2f} Bytes")
        print(f"Puncak memori absolut tertinggi: {max_peak_memory:.2f} Bytes")

if __name__ == "__main__":
    # PERINGATAN: Matikan GC otomatis Python di level global selama script berjalan 
    # agar tidak mengganggu pengukuran waktu secara acak di tengah-tengah fungsi Anda.
    gc.disable() 
    try:
        benchmark_penambahan()
    finally:
        gc.enable() # Kembalikan ke keadaan semula