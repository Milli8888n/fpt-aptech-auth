# Cổng tài khoản học viên FPT Aptech
> **Hệ thống xác thực & Quản lý định danh cấp doanh nghiệp với Spring Security, Spring Session JDBC & Spring Data JPA**

Dự án triển khai hoàn chỉnh **Mục 11: Bài tập ứng dụng - Cổng tài khoản học viên FPT Aptech** từ tài liệu *"Tutorial: Đăng ký và đăng nhập với Spring Security 7 + Spring Boot 4.1 + Spring Data JPA"*.

---

## 1. Khởi động nhanh bằng một lệnh (Single Command)

### Bước 1: Khởi động cơ sở dữ liệu & Mail server (Docker Compose)
```bash
docker compose up -d
```
* **MySQL 8.4:** Port `3307:3306` (Database: `auth`, User: `auth`, Password: `auth_pw`)
* **Mailpit (Webmail test):** Truy cập Web UI tại [http://localhost:8025](http://localhost:8025) để xem email xác thực và email đặt lại mật khẩu (SMTP chạy tại cổng `1025`).

### Bước 2: Chạy ứng dụng bằng một lệnh duy nhất
```bash
./mvnw spring-boot:run
```
Ứng dụng sẽ tự động khởi động và chạy tại: **[http://localhost:8080](http://localhost:8080)**

---

## 2. Tài khoản Quản trị khởi tạo sẵn (Initial Seed Account)

Hệ thống được seed sẵn 1 tài khoản Quản trị viên (`ROLE_ADMIN`) trong database để quản trị ngay từ đầu:
* **Email:** `admin@fpt.edu.vn`
* **Username:** `admin`
* **Mật khẩu khởi tạo:** `Admin@Aptech2026!`
* **Trạng thái:** `ACTIVE` (Hệ thống yêu cầu thiết lập 2FA ngay khi đăng nhập)

---

## 3. Ma trận Nghiệm thu 11 Tiêu chí (F1 – F11)

| Tiêu chí | Chức năng | Trạng thái | Chi tiết kỹ thuật đã triển khai |
| :---: | :--- | :---: | :--- |
| **F1** | Đăng ký bằng email | ✅ Đạt | Form đăng ký tạo user `PENDING`. Sinh link xác thực gửi qua SMTP Mailpit. |
| **F2** | Xác minh email | ✅ Đạt | Token 24h dùng 1 lần, lưu băm SHA-256. Gửi lại tối đa 3 lần/giờ. Kích hoạt xong tự động đăng nhập. |
| **F3** | Quên mật khẩu | ✅ Đạt | Token 30 phút dùng 1 lần. Phản hồi mờ (Blind response) không tiết lộ email tồn tại. Đổi xong hủy mọi session cũ. |
| **F4** | Chính sách mật khẩu | ✅ Đạt | $\ge 12$ ký tự, không chứa username/email, cấm top 10.000 mật khẩu phổ biến (`common-passwords-10k.txt`), cấm trùng 5 mật khẩu gần nhất (`password_history`). |
| **F5** | Khóa tạm thời | ✅ Đạt | Nhập sai 5 lần trong 15 phút -> khóa 15 phút (`LOCKED`). Băm giả lập giữ thời gian phản hồi giữa user tồn tại và không tồn tại chênh lệch $\Delta \le 50\text{ ms}$ (chống Timing Attack). |
| **F6** | Xác thực 2 bước (2FA) | ✅ Đạt | Chuẩn RFC 6238 TOTP qua `dev.samstevens.totp`, sinh QR Code Data URI, 10 mã khôi phục 1 lần. Secret mã hóa AES-GCM 256-bit. Bắt buộc 2FA với `LECTURER` và `ADMIN`. |
| **F7** | Ghi nhớ đăng nhập | ✅ Đạt | Remember-me lưu DB (`persistent_logins`) hiệu lực 14 ngày. Tự thu hồi khi đổi mật khẩu. |
| **F8** | Quản lý phiên | ✅ Đạt | `Spring Session JDBC`, tối đa 2 phiên đồng thời; phiên thứ 3 đá phiên cũ nhất. Trang `/sessions` hiển thị IP, User-Agent, thời gian và cho phép hủy phiên từ xa. |
| **F9** | Đổi mật khẩu | ✅ Đạt | Bắt buộc nhập mật khẩu hiện tại. Đổi xong giữ nguyên phiên hiện tại, hủy toàn bộ các phiên khác. |
| **F10** | Quản trị tài khoản | ✅ Đạt | Danh sách phân trang, lọc vai trò/trạng thái, tìm email, khóa/mở khóa, gán vai trò, buộc đăng xuất. Chốt chặn bảo vệ: Không thể xóa Admin cuối cùng và Admin không thể tự hạ quyền. |
| **F11** | Nhật ký kiểm toán | ✅ Đạt | Ghi nhận tự động vào bảng `audit_logs`: Đăng nhập, đăng xuất, khóa, đổi pass, đổi quyền, 2FA kèm IP, User-Agent, thời điểm; Admin có trang tra cứu và lọc nhật ký. |

---

## 4. Chạy Bộ Kiểm thử Tự động (Automated Test Suite)

Toàn bộ test suite chạy hoàn toàn tự động trên in-memory H2 database (chế độ MySQL) và không yêu cầu Docker đang mở:
```bash
./mvnw test
```

### Các lớp kiểm thử chính:
1. `PasswordPolicyTest`: Kiểm thử tiêu chí F4 (độ dài, loại trừ username/email, từ điển 10k mật khẩu, lịch sử 5 mật khẩu).
2. `TotpServiceTest`: Kiểm thử tiêu chí F6 (mã hóa AES-GCM, sinh QR Code Data URI, kiểm tra mã OTP chuẩn RFC 6238, 10 mã khôi phục).
3. `AccountLockoutTest`: Kiểm thử tiêu chí F5 (khóa tạm 15m sau 5 lần sai pass, đo lường chống tấn công phân tích thời gian delta $\le 50\text{ ms}$).
4. `SessionManagementTest`: Kiểm thử tiêu chí F8 (giới hạn tối đa 2 phiên đồng thời, tự động đá phiên cũ, hủy phiên từ xa).
5. `AdminRulesTest`: Kiểm thử tiêu chí F10 (chốt chặn cấm xóa Admin cuối cùng và cấm Admin tự hạ quyền của mình).
6. `AuthFlowComprehensiveTest`: Kiểm thử luồng E2E đăng ký, kích hoạt token email, bảo vệ CSRF và phân quyền vai trò.

---

## 5. Tài liệu Kiến trúc & Mô hình Mối đe dọa

* **Mô hình Mối đe dọa (Threat Model):** [docs/THREAT-MODEL.md](file:///c:/Users/Million/ApifirstSpring/fpt-aptech-auth/docs/THREAT-MODEL.md) (Phân tích chi tiết theo STRIDE & OWASP Top 10).
* **Đặc tả kỹ thuật:** [docs/Dac_ta_ky_thuat_Cong_tai_khoan_FPT_Aptech.md](file:///c:/Users/Million/ApifirstSpring/fpt-aptech-auth/docs/Dac_ta_ky_thuat_Cong_tai_khoan_FPT_Aptech.md).
* **Kế hoạch triển khai:** [docs/Ke_hoach_trien_khai_Cong_tai_khoan_FPT_Aptech.md](file:///c:/Users/Million/ApifirstSpring/fpt-aptech-auth/docs/Ke_hoach_trien_khai_Cong_tai_khoan_FPT_Aptech.md).
