# Threat Model for json_search()

Dựa trên framework **STRIDE** (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) cho chức năng `json_search()` trong môi trường giám sát hạ tầng mạng.

---

## 1. Actors & Roles
Hàm `json_search()` phục vụ nhiều đối tượng người dùng với quyền hạn và mục đích khác nhau:
- **Admin**:
  - *Mục đích*: Quản trị toàn diện hệ thống mạng, cấu hình thiết bị, quản lý khóa bảo mật, xử lý sự cố cấp độ cao nhất.
  - *Quyền hạn*: Toàn quyền truy xuất tất cả các trường dữ liệu, bao gồm các tài sản tối mật (`apiKey`, `managementIpAddress`, `issueSummary`, và toàn bộ cấu hình mạng).
- **Operator**:
  - *Mục đích*: Giám sát trạng thái hoạt động của mạng, vận hành kỹ thuật, xử lý các sự cố kết nối của thiết bị hạ tầng.
  - *Quyền hạn*: Được phép tra cứu thông tin sự cố (`issueSummary`) và địa chỉ quản trị thiết bị (`managementIpAddress`) để kết nối khắc phục, nhưng **không** được phép xem các thông tin xác thực/bí mật (`apiKey`).
- **Viewer**:
  - *Mục đích*: Theo dõi tổng quan tình trạng hệ thống, xem báo cáo trạng thái giám sát ở mức độ người dùng/khách hàng.
  - *Quyền hạn*: Chỉ được phép xem các thông tin cảnh báo chung (`issueSummary`), **tuyệt đối không** được xem địa chỉ IP quản trị nội bộ (`managementIpAddress`) hoặc thông tin xác thực bí mật (`apiKey`).

---

## 2. Sensitive Assets
Trong dữ liệu mẫu (`test_data.py`) các asset nhạy cảm có thể xuất hiện trong dữ liệu trả về bao gồm:

+ `apiKey`:
   - *Trong dữ liệu*: Chuỗi SNMP Community string `SNMP-COMMUNITY-STRING-7f3a9c`.
   - Nếu bị lộ, kẻ tấn công có thể truy vấn hoặc can thiệp trái phép vào thiết bị mạng qua giao thức SNMP, chiếm quyền điều khiển hạ tầng.

+ `managementIpAddress`:
   - *Trong dữ liệu*: Địa chỉ IP quản trị thiết bị mạng nội bộ `10.10.20.21`.
   - Nếu bị lộ, attacker có thể định vị chính xác vị trí interface quản trị của switch lõi/switch biên.

+ `issueSummary`:
   - *Trong dữ liệu*: Tóm tắt sự cố (`"Network Device 10.10.20.82 Is Unreachable From Controller"`).
   - Cung cấp thông tin về tình trạng sẵn sàng của hệ thống mạng cho mục đích giám sát vận hành.

---

## 3. Trust Boundary
- **Nếu hàm không kiểm tra role trước khi trả kết quả thì**:
  - Hàm `json_search(key, input_object)` sẽ chỉ thực hiện thuật toán tìm kiếm đệ quy mà không kiểm tra role của người gọi hàm, dẫn đến việc bất kỳ lời gọi hàm nào từ phía ngoài (kể cả từ actor có quyền hạn thấp như `Viewer` hoặc lời gọi không định danh) cũng truy cập trực tiếp vào vùng dữ liệu nhạy cảm được bảo vệ (ví dụ như lộ apikey).

---

## 4. Phân tích mối đe dọa

| Mối đe dọa (STRIDE) | Khả năng xảy ra | Mô tả chi tiết | Hậu quả / Tác động |
| :--- | :--- | :--- | :--- |
| **Information Disclosure** *(Trọng tâm)* | **Cao** | Người dùng có vai trò `Viewer` hoặc `Operator` gọi hàm `json_search("apiKey", data)`. Do hàm thiếu kiểm tra quyền, dữ liệu chuỗi xác thực SNMP bị trả về nguyên vẹn. | Tiết lộ bí mật xác thực, vi phạm tính bảo mật (Confidentiality). |
| **Elevation of Privilege** *(Trọng tâm)* | **Cao** | Caller không truyền `role` (`role=None`) hoặc truyền vai trò không hợp lệ nhưng hệ thống vẫn thực thi tìm kiếm và trả về toàn bộ dữ liệu, cho phép đối tượng không xác thực có quyền năng như `Admin`. | Nâng quyền trái phép, vi phạm nguyên tắc đặc quyền tối thiểu (Least Privilege). |
| **Spoofing** | Trung bình | Caller tự khai báo `role="admin"` giả mạo trong tham số gọi hàm mà không có cơ chế xác thực phiên (Session/Token Verification). | Vượt qua hàng rào kiểm soát quyền. |
| **Tampering** | Thấp | Sửa đổi trái phép nội dung bảng chính sách phân quyền `policy.py` hoặc dữ liệu trong quá trình tìm kiếm. | Sai lệch kết quả hoặc cấp quyền sai. |
| **Denial of Service** | Thấp | Đối tượng cố tình truyền cấu trúc JSON bị vòng lặp tham chiếu (circular reference) hoặc lồng quá sâu gây tràn ngăn xếp đệ quy (RecursionError). | Treo hoặc dừng đột ngột ứng dụng giám sát. |
