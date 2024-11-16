package spring.security.practice.webtoken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service // Menandai kelas ini sebagai komponen Spring yang dikelola, sehingga dapat di-`@Autowired` di tempat lain.
public class JwtService {

    // Kunci rahasia yang digunakan untuk membuat dan memverifikasi token JWT.
    private static final String SECRET = "296D602EBC0A9F45A62D99B5D2BAB3636219DF1EE8671459F6CEF228FAE90BE804E9894D9089F2EC61EC1846A54A5165B74B35362BA33D173598B52BB06334EC";

    // Durasi validitas token JWT dalam milidetik (30 menit).
    private static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);

    /**
     * Menghasilkan token JWT untuk pengguna berdasarkan detail pengguna.
     *
     * @param userDetails Detail pengguna (username dan otoritas/hak akses).
     * @return Token JWT yang telah dibuat.
     */
    public String generateToken(UserDetails userDetails) {
        // Membuat klaim tambahan untuk disertakan di dalam token.
        Map<String, String> claims = new HashMap<>();
        claims.put("name", "dani"); // Contoh klaim statis (bisa diubah sesuai kebutuhan).

        // Membuat token JWT.
        return Jwts.builder()
                .claims(claims) // Menambahkan klaim ke dalam payload token.
                .subject(userDetails.getUsername()) // Menetapkan username sebagai subjek token.
                .issuedAt(Date.from(Instant.now())) // Menetapkan waktu pembuatan token.
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY))) // Menetapkan waktu kadaluarsa token.
                .signWith(generateKey()) // Menandatangani token menggunakan kunci rahasia.
                .compact(); // Menggabungkan semua bagian token menjadi string JWT.
    }

    /**
     * Menghasilkan kunci rahasia berbasis HMAC-SHA dengan mendekodekan kunci yang dienkode dalam format Base64.
     *
     * @return Objek `SecretKey` untuk tanda tangan JWT.
     */
    private SecretKey generateKey() {
        // Mendekodekan kunci rahasia dari format Base64.
        byte[] decodedKey = Base64.getDecoder().decode(SECRET);
        // Membuat kunci HMAC-SHA berdasarkan byte yang telah didekode.
        return Keys.hmacShaKeyFor(decodedKey);
    }

    /**
     * Mengekstrak username (subjek) dari token JWT.
     *
     * @param jwt Token JWT.
     * @return Username pengguna yang ada dalam token.
     */
    public String extractUsername(String jwt) {
        // Mendapatkan klaim dari token dan mengambil subjeknya.
        Claims claims = getClaims(jwt);
        return claims.getSubject();
    }

    /**
     * Mendapatkan klaim (payload) dari token JWT.
     *
     * @param jwt Token JWT.
     * @return Objek `Claims` yang berisi data dari token.
     */
    private Claims getClaims(String jwt) {
        return Jwts.parser() // Membuat parser JWT.
                .verifyWith(generateKey()) // Menentukan kunci rahasia untuk verifikasi.
                .build() // Menyelesaikan konfigurasi parser.
                .parseSignedClaims(jwt) // Mem-parsing token JWT dan mendapatkan klaim yang ditandatangani.
                .getPayload(); // Mengembalikan payload (klaim) token.
    }

    /**
     * Memeriksa apakah token JWT masih valid berdasarkan waktu kadaluarsa.
     *
     * @param jwt Token JWT.
     * @return `true` jika token masih valid; `false` jika sudah kadaluarsa.
     */
    public boolean isTokenValid(String jwt) {
        // Mendapatkan klaim dari token.
        Claims claims = getClaims(jwt);
        // Membandingkan waktu kadaluarsa dengan waktu saat ini.
        return claims.getExpiration().after(Date.from(Instant.now()));
    }
}

