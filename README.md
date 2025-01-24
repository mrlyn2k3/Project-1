# **Project ethical hacking**
# **Topic: tấn công mạng**
## **1. Thông tin về project**
Xây dụng mô hình và kịch bản tấn công hệ thống mạng sử dụng mô hình C2 havoc. Mô tả các kỹ thuật tấn công theo MITRE ATT@CK.
- Xây dựng mô hình chung cho hệ thống và xây dựng hoàn chỉnh các thành phần trong mạng như AD, Web, Client...
- Xây dựng mô hình C2, phân tích cụ thể các thành phần sử dụng trong C2.
- Xây dựng các kịch bản tấn công và phân tích các kỹ thuật sử dụng trong đó.

Hệ thống lab được build bằng VMware workstation pro.

## **2. Phân tích quá trình tấn công**
### **2.1 Kịch bản tấn công**
AD: `phongbat.com`

WEb: 'home.phongbat.com'

Hệ thống nội bộ gồm 4 máy:
- `RootDC (Active Directory)`: Window Server 2019
- `User1 (WS1)`: Window 10
- `User2 (WS2)`: Window 10
- `Web (Web01)`: Ubuntu, đóng vai trò là WebServer giao tiếp với External Network

- Máy Attacker sử dụng `Kali Linux` dùng để xâm nhập vào hệ thống nội bộ ở trên.

Giới thiệu về `Havoc Framework`: một framework mã nguồn mở cho phép cài đặt và vận hành C2 server một cách dễ dàng, tích hợp nhiều tính năng giúp cho việc quản lí, duy trì trong hệ thống mạng đã khai thác, được sử dụng như một giải pháp thay thế cho `Cobalt Strike` và `Brute Ratel` (post-exploitation C2 framework). C2 framework cung cấp cho các threat actor khả năng thả beacon trên các mạng bị xâm chiếm để vận chuyển các payload độc hại. Trong những năm qua, `Cobalt Strike` và `Brute Ratel` đã trở thành công cụ phổ biến để các threat actor cung cấp payload độc hại cho những nạn nhân được nhắm tới. Điều này đã khiến các nhà phát triển và tổ chức C2 sử dụng `Cobalt Strike` và `Brute Ratel` phải cảnh giác hơn với phần mềm độc hại tiềm ẩn bên trong repository của họ. Với `Havoc`, các threat actor được cung cấp một lựa chọn mới trong việc nhắm mục tiêu và khai thác hệ thống mạng.

Về hệ thống C2 Server, gồm 3 thành phần chính:
- `Havoc Server`: Máy chủ cốt lõi của framework, dùng để khởi động listener, tương tác với các agent và xử lí các command do client yêu cầu.
- `Havoc Client`: Giao diện chính của framework, giúp cho các thành viên redteam liên lạc, tương tác với các máy bị xâm chiếm.
- `Havoc Agent`: payload được khởi chạy bởi máy tính mục tiêu, nhận lệnh và thực thi lệnh do server yêu cầu.

Attacker có thể xâm nhập vào hệ thống thông qua 2 cách tiếp cận: exploit từ Web01 đi vào, tải và thực thi file agent, sau đó gửi malware phishing cho WS01, từ đó máy WS01 này sẽ tải agent và thực thi để thêm vào C2 Server, duy trì sự hiện diện trong hệ thống.

### **2.2 Phân tích cụ thể**
