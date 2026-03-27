from django.test import SimpleTestCase
import time
from banking.utils import PublicKey, PrivateKey
from banking import utils

class TestPembangkitanKunci(SimpleTestCase):
    def test_waktu_pembangkitan_kunci(self):
        print("\nUji Waktu Pembangkitan Kunci")
        keys_arr = [512, 1024, 2048, 3072]
        for size in keys_arr:
            print(f"pembangkitan 100 kunci {size}-bits")
            time_arr = []
            total_time = 0
            for num in range(1, 101):  
                start_time = time.perf_counter()
                PublicKey, PrivateKey = utils.generate_paillier_keypair(n_length=size)
                finish_time = time.perf_counter() - start_time
                time_arr.append(finish_time)
            total_time= sum(time_arr)
            mean_waktu = total_time/100
            print(f"Total Waktu: {total_time}")
            print(f"Rata-rata waktu pembangkitan kunci {size}-bit: {mean_waktu} detik")
