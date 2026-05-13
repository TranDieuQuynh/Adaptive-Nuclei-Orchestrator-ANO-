# ASMO Demo Guide

## 1. Mục tiêu demo
Mục tiêu của chế độ demo là chạy ASMO end-to-end một cách ổn định trên target WordPress local, ngay cả khi Nuclei không trả JSONL result thật ở vòng đầu. Demo vẫn giữ được logic cốt lõi của hệ thống: URL seed, semantic matching, controlled fallback, Blackboard update, và expansion sang các template WordPress ở vòng sau.

## 2. Lệnh chạy normal mode
```powershell
d:/KLTN/.venv/Scripts/python.exe main.py --target http://127.0.0.1:8080 --beam-width 3 --max-iterations 3
```

## 3. Lệnh chạy demo mode
```powershell
d:/KLTN/.venv/Scripts/python.exe main.py --target http://127.0.0.1:8080 --beam-width 3 --max-iterations 3 --demo-mode
```

## 4. Giải thích `--demo-mode`
- Chỉ dùng khi local target không trả JSONL result thật từ Nuclei.
- Chỉ fallback cho trusted fingerprint templates:
  - `wordpress-detect`
  - `wordpress-passive-detection`
  - `wordpress-readme-file`
- Không ảnh hưởng normal mode.
- Khi tắt `--demo-mode`, behavior giữ nguyên: không có match thật thì không sinh fact bừa.

## 5. Flow demo
Luồng demo mong đợi là:

```text
url -> wordpress-detect
wordpress-detect -> tech:wordpress
tech:wordpress -> plugin/theme/exposure templates
```

Ở vòng 1, ASMO chỉ cho các template recon/detect WordPress từ URL đi qua. Khi Nuclei không trả JSONL result thật, runner có thể sinh controlled fallback để tạo `tech:wordpress`. Khi Blackboard có `tech:wordpress`, vòng 2 mở ra nhóm template phụ thuộc WordPress như plugin, theme, readme, exposure, và các template liên quan khác.

## 6. Ví dụ expected log
```text
[CANDIDATE]
[MATCH]
[DEMO-FALLBACK]
[FACT]
[EXEC]
```

Ví dụ thực tế sẽ gần như sau:
```text
[CANDIDATE]url:http://127.0.0.1:8080 -> wordpress-detect
[MATCH] semantic match wordpress-detect score=...
[EXEC] wordpress-detect policy=allowed score=...
[DEMO-FALLBACK] wordpress-detect produced tech:wordpress because demo-mode enabled
[FACT] tech=wordpress confidence=0.60
```

## 7. Final Blackboard expected
Trong demo mode, final Blackboard nên có tối thiểu:
- `protocol:http`
- `url:http://127.0.0.1:8080`
- `template_match:wordpress-detect`
- `tech:wordpress`

Nếu target trả thêm dữ liệu, Blackboard có thể có thêm `template_match:wordpress-passive-detection`, `template_match:wordpress-readme-file`, `theme:<value>`, `plugin:<value>`, hoặc `exposure:<value>`.

## 8. Attack Graph expected
Graph mong đợi có các edge chính sau:
- `fact:url -> template:wordpress-detect`
- `template:wordpress-detect -> fact:tech:wordpress`
- `fact:tech:wordpress -> template:wordpress-plugin-detect`
- `fact:tech:wordpress -> template:wordpress-theme-detect`
- `fact:tech:wordpress -> template:wordpress-readme-file`
- `fact:tech:wordpress -> template:wordpress-wp-env-exposure`

## 9. Giới hạn hiện tại
- Demo fallback chỉ là controlled fallback cho local demo, không phải xác thực thật từ target.
- Nếu target không phải WordPress, demo mode vẫn có thể làm chuỗi chạy tiếp, nên chỉ dùng với local WordPress demo đã biết trước.
- Nếu một template không thuộc nhóm trusted fingerprint ở trên, demo mode không tự sinh fact thay thế.
- Kết quả theme/plugin/version/exposure vẫn phụ thuộc vào output thực tế hoặc dữ liệu fallback hợp lệ.

## 10. Future work
- Chạy trên target WordPress thật để kiểm tra end-to-end không cần fallback.
- Thêm signature extractor để suy luận fact tốt hơn từ JSONL output.
- Thử adaptive beam width để ưu tiên template hữu ích theo từng iteration.
- Mở rộng policy cho full exploit/bruteforce gating thay vì chỉ demo-safe chain.
