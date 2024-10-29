# for/unexpected

Từ minidump có thể tìm được C2 mà attacker đang sử dụng là SolaraExecutor.exe, sử dụng detect it easy có thể thấy được đây là sample c2 đã được tác giả custom lại, [mã nguồn gốc](https://github.com/ricardojoserf/SharpCovertTube).

Dựa vào mã nguồn gốc có thể thấy được flow của C2
![image](https://github.com/user-attachments/assets/2ae94ee2-f8a3-4f87-a2b9-a3d32c8e827f)

Dựa vào [youtube api](https://github.com/hoanga2dtk68/isitdtu2024/blob/main/playlistItems.json) mà kẻ tấn công sử dụng để thu thập được các ảnh qr để giải mã command của kẻ tấn công.

Sử dụng dnspy để đọc mã nguồn của mã độc, tìm được key và iv để giải mã lấy được part2
![image](https://github.com/user-attachments/assets/5d5ce8b4-6c87-4cc4-a24a-b1cf02e1efd8)

Part 1 nằm trong source code



```c#
using System;
namespace SharpCovertTube
{
    // Token: 0x0200000A RID: 10
    internal class Configuration
    {
        // Token: 0x0400001F RID: 31
        public const string playlist_id = "PL8rua6xfypCAiqEdvoKs006WPvBMQF9-G";

        // Token: 0x04000020 RID: 32
        public const string api_key = "AIzaSyDTtHVcvOlZM46Ik9pH5tJbjE1vI74JJO0";

        // Token: 0x04000021 RID: 33
        public const string payload_aes_key = "c4530e2eeb9ea61d57910fe9ec86f47e25359840bf430c3ce78e4c363c5d24ef";

        // Token: 0x04000022 RID: 34
        public const string payload_aes_iv = "6c44f45102fdd739cbc6b572ed8698db";

        // Token: 0x04000023 RID: 35
        public const int seconds_delay = 120;

        // Token: 0x04000024 RID: 36
        public const bool debug_console = true;

        // Token: 0x04000025 RID: 37
        public const bool log_to_file = false;

        // Token: 0x04000026 RID: 38
        public const string log_file = "c:\\temp\\.sharpcoverttube.log";

        // Token: 0x04000027 RID: 39
        public const bool dns_exfiltration = true;

        // Token: 0x04000028 RID: 40
        public const string dns_hostname = ".wallpaperzn.store";

        // Token: 0x04000029 RID: 41
        public const string part1_flag = "SVNJVERUVXszdkVyeTdoIW45Xw==";
    }
}
```
part 3 yêu cầu phải decrypt phần response từ client trả về qua hàm dns exfil
Ban đầu, mình tìm cách attack rsa hoặc khôi phục từ pcap nhưng không khả thi

```
        public static byte[] RSAEncrypt(byte[] data)
        {
            string text = "PFJTQUtleVZhbHVlPjxNb2R1bHVzPmNZTm4ybnlZeVltTWhvcnZLelVzYzA4eG9uQzhGVEZibVIyRXVaRzN3aHdpYjBLTWhJZDUzdHErVkZYaVFHTUlydE9kMlFRbXZXZG1WNll6RnFaMExUUXgzLzNLREo0ZVE5MnZvQTJuWFZxVy9LVWFTU1ZFV3diTzVuZU9GOHIzeTUzS0JvZE83WGpmblVxU3c4SHB6cE1mTG5EVUFJdDlhOHR2TTZvYzh6RXBXb2Jtb1J6cEJXTUNzU2w1dkNTNmxTUlB4alg1eXRpSmRFZWFvMmVxa0NMQWVOSEl3TWJ0aC9BNHVOWWpFVk95dDdMVzBKMFBjNWVTQi9RU2FWYTBGT2t3V0RBZ2M1MjIwbU9rWWxLMmZSZDN5OTRsN3dRSDNwMFVGeE1UeVMycVRRL1YvbG5NQS9rWEtTeDJDWHF2Nmp3cHJwVjFiY2toSUwxS3k4YldDZUtqS2t1Mk4rWWdma3pXV3JLTU8reFZ4ejg4YWVJMjRwZzIwdHVJNUt2cmpmcEt4NzNhM3pOSDZFem9TOHpodUxQMU5yanZ2Y0hxZ2xaOHBLMXhtMHQrWTJwNUVsUHVwd2xCblR5Wkw3c3FnSTB6bnRDU0d5K2Z6WE96WDBad1N1ejNweEVTVVdJNytVVlJKL2hKbEZBekFwVVZSc1BiMVhjOEcyZjRsazZ5TExRUUJjZFRoZXpZM0U0L1Z0Z09HWE1QSWxFWklvOEZEWUJqZHdFb2JReit4aXRYbnN4ZnNRckFsTjhsWDhsanJVTTRLcENwWjNzUmxoYkw3WW05ZzM0U01EeGRCclFGbGhFWXFLWCtmc3hBNm8xQmVrWjVqYjV6ZEZSVnMvRHZXZXB3VnhqSndhQW9oanJDUTU1LzlrcXF1TXhSWHRIdWovcjl0ancxTEJjPTwvTW9kdWx1cz48RXhwb25lbnQ+QVFBQjwvRXhwb25lbnQ+PC9SU0FLZXlWYWx1ZT4=";
            text = HelperFunctions.Base64Decode(text);
            byte[] array = new byte[0];
            using (RSACng rsacng = new RSACng())
            {
                rsacng.ImportParameters(HelperFunctions.GetRSAParametersFromXml(text));
                array = rsacng.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            }
            return array;
        }
```

Sau đó mình thử sử dụng aeskeyfind đã tìm được aes để giải mã thực hiện lấy dữ liệu dns ra và decrypt với iv 16 bytes cuối cùng của cipher

![image](https://github.com/user-attachments/assets/f80f4daa-64f8-4ef3-aaa2-9b1fad94848a)

flag: ISITDTU{3vEry7h!n9_c0uLd_B3_u5ed_4s_c2-chAnNe|~}
