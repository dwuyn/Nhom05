# Security Requirements for json_search()

Dựa trên kết quả phân tích Threat Model theo mô hình STRIDE, các yêu cầu an toàn phần mềm (Security Requirements - SR) cho hàm `json_search()` được phát biểu cụ thể như sau:

---

## 1. Yêu cầu Kiểm soát Truy cập theo Vai trò (Role-Based Access Control - RBAC)
- **SR-01 (RBAC Enforcement)**:
  - Hàm `json_search(key, input_object, role=None)` bắt buộc phải đối chiếu vai trò của người gọi (`role`) với chính sách kiểm soát truy cập được định nghĩa trong `policy.py` trước khi trả về bất kỳ kết quả nào.
  - Hệ thống chỉ trả về giá trị của trường `key` nếu và chỉ nếu `role` hiện tại nằm trong danh sách các vai trò được phép truy cập trường đó trong `POLICY[key]`.

- **SR-02 (Default Deny & Principle of Least Privilege)**:
  - Nếu `role` không được cung cấp (`role=None`), `role` là chuỗi rỗng `""`, hoặc không khớp với bất kỳ vai trò hợp lệ nào trong chính sách (`admin`, `operator`, `viewer`), hàm `json_search()` phải từ chối truy cập mặc định và trả về một danh sách rỗng `[]`.
  - Nếu `key` được tìm kiếm không tồn tại trong danh mục kiểm soát của `POLICY` hoặc không tồn tại trong dữ liệu, hàm phải trả về danh sách rỗng `[]`.

---

## 2. Yêu cầu Bảo mật cụ thể cho từng Loại Tài sản (Data Confidentiality)

- **SR-03 (Bảo vệ thông tin xác thực tối mật - `apiKey`)**:
  - Dữ liệu `apiKey` (chuỗi xác thực SNMP / Secret Token) **chỉ duy nhất** vai trò `admin` được phép đọc.
  - Các vai trò `operator`, `viewer`, hoặc các yêu cầu không xác thực (`role=None`) khi tra cứu `apiKey` phải nhận về kết quả rỗng `[]`.

- **SR-04 (Bảo vệ thông tin hạ tầng nội bộ - `managementIpAddress`)**:
  - Dữ liệu `managementIpAddress` (địa chỉ IP quản trị mạng nội bộ) **chỉ cho phép** các vai trò `admin` và `operator` truy cập phục vụ mục đích cấu hình và xử lý sự cố.
  - Vai trò `viewer` hoặc yêu cầu không xác thực (`role=None`) khi tra cứu `managementIpAddress` phải nhận về kết quả rỗng `[]`.

- **SR-05 (Kiểm soát dữ liệu cảnh báo vận hành - `issueSummary`)**:
  - Dữ liệu `issueSummary` (mô tả và tóm tắt sự cố mạng) được phép truy xuất bởi các vai trò `admin`, `operator`, và `viewer` để phục vụ giám sát chung.
  - Các yêu cầu không hợp lệ hoặc không có vai trò (`role=None`) vẫn không được phép truy xuất dữ liệu này (Default Deny).

---

## 3. Căn cứ cho Security Test Suite (Verification & Testability)
Các Security Requirements trên là căn cứ trực tiếp để xây dựng tối thiểu 3 Security Test Cases trong `test_json_search.py`:
1. `test_apiKey_restricted_to_admin_only()`: Kiểm tra `viewer` và `operator` không thể đọc `apiKey` (kết quả trả về `[]`), trong khi `admin` đọc được kết quả hợp lệ.
2. `test_managementIpAddress_blocked_for_viewer()`: Kiểm tra `viewer` không thể đọc `managementIpAddress` (kết quả trả về `[]`), trong khi `operator` và `admin` đọc được.
3. `test_default_deny_when_role_is_none_or_invalid()`: Kiểm tra khi `role=None` hoặc `role="guest"` (vai trò không hợp lệ), hàm đều trả về `[]` cho mọi key được bảo vệ.
