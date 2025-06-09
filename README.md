# KaliPurple-AIOps
![Finaly drawio](https://github.com/user-attachments/assets/7778082d-180c-4254-bf79-33ec75ece92f)
Hệ thống được xây dựng nhằm mô phỏng một môi trường giám sát và phản ứng an ninh mạng sử dụng Kali Purple làm nền tảng chính. Kiến trúc hệ thống chia thành ba tầng xử lý chính: thu thập log, phân tích bằng AI, và cảnh báo – phân tích sự kiện (alerting & analysis). Ngoài ra, để mô phỏng tấn công thực tế, hệ thống còn bao gồm một máy victim Ubuntu bị tấn công bởi một máy Attacker.
### Tầng 1 – Thu thập log (Log Collection Layer):
Một máy ảo Kali Purple (Zeek) được triển khai công cụ giám sát mạng Zeek, thực hiện phân tích lưu lượng mạng giữa các máy trong hệ thống (bao gồm cả attacker và victim). Zeek phân tích các gói tin và tạo ra các log chi tiết như conn.log, dns.log, http.log,... Các log này được gửi về máy Kali ELK thông qua Filebeat hoặc trực tiếp bằng Logstash sau đó lưu trữ trong Elasticsearch và hiển thị qua Kibana.
    
### Tầng 2 – Phân tích AI (AI Pre-analysis Layer):
	
Máy Kali ELK đóng vai trò thu nhận log từ Zeek. Sau khi log được xử lý ban đầu, một đoạn script Python sẽ trích xuất log cần thiết và gửi đến API của Meta AI Meta: Llama 3.3 8B Instruct để phân tích sơ bộ hành vi. Meta AI giúp đánh giá nhanh các chỉ số nghi ngờ. Kết quả sau đó được gửi tiếp đến AWS S3 Bucket, sau đó Lambda sẽ trigger S3 và gửi log tới AWS Bedrock AI – mô hình AI chuyên dụng cho bảo mật – để đánh giá mức độ nghiêm trọng, liên kết với tactic/technique theo MITRE ATT&CK, và phân loại sự kiện (event classification).
### Tầng 3 – Cảnh báo và phân tích sâu (Alerting & Deep Analysis Layer):
Một máy ảo Kali Purple khác, được cài đặt TheHive (nền tảng điều phối phân tích sự kiện) và Cortex (công cụ hỗ trợ phân tích tự động). Máy này tiếp nhận kết quả phân tích từ Bedrock AI và tạo ra alert tương ứng trong TheHive. Các alert sau đó được xử lý bằng các analyzer và responder trong Cortex nhằm hỗ trợ SOC analyst thực hiện phản ứng sự kiện hoặc điều tra sâu.

Link Demo Video: 
https://www.youtube.com/watch?v=6hFkN78U3NE
