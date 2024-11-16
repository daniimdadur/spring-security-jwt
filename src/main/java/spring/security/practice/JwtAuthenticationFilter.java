package spring.security.practice;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import spring.security.practice.model.MyUserDetailService;
import spring.security.practice.webtoken.JwtService;

import java.io.IOException;

@Configuration // Menandai kelas ini sebagai konfigurasi Spring yang akan dijalankan saat aplikasi mulai.
public class JwtAuthenticationFilter extends OncePerRequestFilter { //Filter ini hanya dipanggil satu kali untuk setiap request
    @Autowired
    private JwtService jwtService; // Digunakan untuk memproses dan memvalidasi token JWT.

    @Autowired
    private MyUserDetailService myUserDetailService; // Digunakan untuk mengambil detail pengguna berdasarkan username.

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Mendapatkan header "Authorization" dari request.
        String authHeader = request.getHeader("Authorization");

        // Jika header tidak ada atau tidak diawali dengan "Bearer ", maka filter langsung dilanjutkan tanpa otentikasi.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return; // Menghentikan eksekusi kode di bawah jika syarat tidak terpenuhi.
        }

        // Mengambil token JWT dengan menghapus prefix "Bearer ".
        String jwt = authHeader.substring(7);

        // Mengekstrak username dari token JWT.
        String username = this.jwtService.extractUsername(jwt);

        // Jika username berhasil diekstrak dan pengguna belum diautentikasi sebelumnya:
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Memuat detail pengguna berdasarkan username.
            UserDetails userDetails = this.myUserDetailService.loadUserByUsername(username);

            // Jika detail pengguna ada dan token JWT valid:
            if (userDetails != null && this.jwtService.isTokenValid(jwt)) {
                // Membuat objek otentikasi dengan detail pengguna dan otoritasnya.
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        username, // Username pengguna.
                        userDetails.getPassword(), // Password pengguna (dalam skenario ini mungkin tidak digunakan secara eksplisit).
                        userDetails.getAuthorities() // Hak akses/otoritas pengguna.
                );

                // Menambahkan detail request ke dalam objek otentikasi.
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Menyimpan otentikasi ke dalam konteks keamanan Spring.
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // Melanjutkan proses filter berikutnya.
        filterChain.doFilter(request, response);
    }
}

