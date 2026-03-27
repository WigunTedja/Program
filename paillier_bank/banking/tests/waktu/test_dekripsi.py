from django.test import SimpleTestCase
import time
from banking.utils import PublicKey, PrivateKey
from banking import utils

class TestKebenaran(SimpleTestCase):
    def test_waktu_dekripsi(self):
        print("\nUji Waktu Dekripsi")
        data_arr = [1000,4679,17279,17298,20977,23077,23156,26835,26635,26736,30415,25115,25224,28903,21403,21487,21502,19035,22714,22014,22091,22106,19639,23318,20418,1100,21336,25036,25050,45286,34286,34395,54631,37031,37176,67530,45130,45290,42090,62326,49181,38881,39069,39084,31803,28903,49139,27853,26853,26992,1000,8502,8526,16326,23828,23907,21507,29009,29122,22222,29724,29847,22447,29949,30059,30074,27659,22959,21824,21497,17958,29211,26651,26749,26764,800,6353,11906,17459,23012,28565,27280,25380,25432,25447,23354,28907,27622,23522,23613,23627,21535,27088,25803,22503,22587,22602,20509,26062,24777]
        keys_arr = [512, 1024, 2048, 3072]
        for size in keys_arr:
            print(f"Dekripsi 100 data dengan kunci {size}-bits")
            enc_data_arr = []
            self.PublicKey, self.PrivateKey = utils.generate_paillier_keypair(n_length=size)
            time_arr = []
            total_time = 0
            for val in data_arr:
                enc_data_arr.append(self.PublicKey.encrypt(val))

            for val in enc_data_arr:  
                start_time = time.perf_counter()
                decry_data = self.PrivateKey.decrypt(val)
                finish_time = time.perf_counter() - start_time
                time_arr.append(finish_time)
            total_time = sum(time_arr)
            mean_waktu = total_time/100
            print(f"Total Waktu: {total_time}")
            print(f"Rata-rata waktu dekripsi dengan kunci {size}-bit: {mean_waktu} detik")