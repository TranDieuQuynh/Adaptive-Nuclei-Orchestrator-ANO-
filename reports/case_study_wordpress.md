## Case Study 1: WordPress Adaptive Chain

Mục tiêu: 
Đánh giá khả năng điều phối động của hệ thống ASMO trong việc:
- Tự động nhận diện công nghệ (Technology Detection)
- Sinh tri thức (Facts)
- Kích hoạt template phù hợp ở các bước tiếp theo

## Môi trường thử nghiệm

- Target: http://127.0.0.1:8080
- Nền tảng: WordPress (Docker)
- Công cụ: Nuclei v3.7.1
- Template subset: ~15 WordPress templates

## Luồng thực thi của ASMO

### Iteration 1:

Template được chọn:
- wordpress-detect
- wordpress-passive-detection

Facts sinh ra:

- tech: wordpress
- version: 6.9.4
- theme: twentytwentyfive

---

### Iteration 2:

Dựa trên Facts mới, hệ thống kích hoạt:

- wordpress-db-exposure (score: 0.7225)

So với detect templates (score: 0.6550), template này có độ ưu tiên cao hơn.

---

### Nhận xét:

Hệ thống đã:
- Không sử dụng workflow tĩnh
- Tự động chuyển từ detection → exploitation phase

## Attack Graph (trích xuất)

url
→ wordpress-detect
→ tech:wordpress
→ version:6.9.4
→ wordpress-passive-detection
→ theme:twentytwentyfive
→ wordpress-db-exposure

## Phân tích

Kết quả cho thấy:

- ASMO sử dụng cơ chế matching động giữa Facts và Signatures
- Việc xuất hiện Fact "tech:wordpress" đã kích hoạt các template chuyên biệt
- Hệ thống ưu tiên template có liên quan cao hơn thông qua scoring

Điều này chứng minh:
ASMO không phụ thuộc vào workflow cố định mà xây dựng chuỗi kiểm thử theo thời gian thực.

## Kết luận

ASMO đã thể hiện khả năng:
- Tự động khám phá bề mặt tấn công
- Điều phối template theo ngữ cảnh
- Xây dựng chuỗi kiểm thử thích ứng (Adaptive Chain)

Đây là ưu điểm vượt trội so với workflow tĩnh của Nuclei.

