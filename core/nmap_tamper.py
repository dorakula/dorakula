"""
Dorakula Nmap Tamper Scripts
Modul untuk menghasilkan argumen Nmap berdasarkan tingkat keahlian (Normal, Advanced, Expert).
Didesain untuk keamanan, efektivitas, dan integrasi langsung dengan NmapEngine.
"""

from typing import List, Optional


class NmapTamper:
    """
    Kelas pembangkit argumen Nmap untuk teknik evasi dan optimasi scanning.
    """

    def __init__(self, level: str = "normal"):
        """
        Inisialisasi Tamper Script.
        
        Args:
            level (str): Tingkat keahlian ('normal', 'advanced', 'expert').
        """
        self.level = level.lower()
        if self.level not in ["normal", "advanced", "expert"]:
            raise ValueError(f"Level tidak valid: {self.level}. Pilih: normal, advanced, expert")

    def get_arguments(self) -> List[str]:
        """
        Mendapatkan daftar argumen Nmap berdasarkan level yang dipilih.
        
        Returns:
            List[str]: Daftar argumen command line Nmap.
        """
        if self.level == "normal":
            return self._get_normal_args()
        elif self.level == "advanced":
            return self._get_advanced_args()
        elif self.level == "expert":
            return self._get_expert_args()
        return []

    def _get_normal_args(self) -> List[str]:
        """
        Level Normal: Fokus pada kecepatan dan stabilitas.
        Cocok untuk audit rutin dan jaringan internal yang dipercaya.
        """
        args = [
            "-Pn",  # Asumsi host aktif (skip ping) untuk kecepatan
            "--open",  # Hanya tampilkan port terbuka
            "-T4",  # Timing template agresif tapi aman
            "--max-retries", "2",  # Batasi retry agar cepat
            "--host-timeout", "15m"  # Timeout per host
        ]
        return args

    def _get_advanced_args(self) -> List[str]:
        """
        Level Advanced: Menambahkan teknik evasi firewall dasar dan deteksi lebih dalam.
        Cocok untuk jaringan dengan firewall standar.
        """
        args = self._get_normal_args()
        
        # Hapus timing normal, ganti dengan yang lebih spesifik
        # Remove -T4 dari list normal jika ada, kita timpa dengan konfigurasi manual atau biarkan T4
        # Kita tambahkan teknik evasi
        
        args.extend([
            "-f",  # Fragmentasi paket (24 byte)
            "--data-length", "32",  # Tambah data random ke paket
            "--scan-delay", "10ms",  # Delay kecil untuk menghindari threshold IDS
            "--max-parallelism", "50",  # Paralelisme moderat
            "--script", "default,safe"  # Jalankan script NSE default dan safe
        ])
        return args

    def _get_expert_args(self) -> List[str]:
        """
        Level Expert: Teknik evasi canggih, full port scan, dan script agresif.
        HANYA gunakan pada lingkungan terkontrol atau dengan izin tertulis eksplisit.
        """
        args = [
            "-Pn",  # No Ping
            "-T4",  # Aggressive timing
            "-f",  # Fragmentasi
            "-f",  # Fragmentasi ganda (total 36 byte biasanya)
            "--mtu", "24",  # Set MTU manual untuk fragmentasi spesifik
            "--data-length", "64",  # Payload lebih besar
            "--scan-delay", "5ms",
            "--max-parallelism", "100",
            "--badsum",  # Kirim checksum TCP salah untuk tes respons firewall
            "--spoof-mac", "0",  # Spoof MAC address acak
            "--source-port", "53",  # Gunakan port sumber 53 (DNS) untuk menyamar
            "--script", "default,vuln,exploit",  # Script agresif (Hati-hati!)
            "--traceroute"  # Lacak rute
        ]
        return args

    def add_custom_options(self, custom_args: List[str]) -> List[str]:
        """
        Menambahkan opsi kustom ke argumen yang dihasilkan.
        Berguna jika pengguna ingin menimpa beberapa setting.
        
        Args:
            custom_args (List[str]): Daftar argumen tambahan.
            
        Returns:
            List[str]: Gabungan argumen tamper dan kustom.
        """
        base_args = self.get_arguments()
        
        # Logika sederhana: append saja, Nmap akan menggunakan nilai terakhir jika duplikat
        # Atau bisa ditambahkan logika konflik jika diperlukan di masa depan
        return base_args + custom_args

    def get_description(self) -> str:
        """Mengembalikan deskripsi teks untuk level saat ini."""
        descriptions = {
            "normal": "Mode Normal: Cepat, stabil, minim noise. Cocok untuk inventory jaringan.",
            "advanced": "Mode Advanced: Evasi firewall dasar, deteksi service mendalam. Cocok untuk audit keamanan eksternal.",
            "expert": "Mode Expert: Evasi IDS/IPS canggih, script vuln/exploit. BERISIKO TINGGI. Hanya untuk penetrasi test berizin."
        }
        return descriptions.get(self.level, "Deskripsi tidak tersedia.")

# Contoh penggunaan langsung jika dijalankan sebagai script standalone
if __name__ == "__main__":
    import json
    
    print("=== Dorakula Nmap Tamper Generator ===")
    
    for lvl in ["normal", "advanced", "expert"]:
        tamper = NmapTamper(level=lvl)
        args = tamper.get_arguments()
        print(f"\n[{lvl.upper()}]")
        print(f"Deskripsi: {tamper.get_description()}")
        print(f"Argumen: {' '.join(args)}")
        print(f"JSON: {json.dumps(args)}")
