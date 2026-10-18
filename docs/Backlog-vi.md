# Backlog

### [Thấp] TlsRecordReassembler dùng List<byte> thêm từng byte

- Vị trí: `src/TqkLibrary.TlsFingerCopy/TlsRecordReassembler.cs` (Add/GetRange).
- Vấn đề: chép từng byte và GetRange trên đường nóng của proxy; có giới hạn 64KB nên không sai, chỉ tốn.
- Nên làm: đổi sang ArrayBufferWriter/byte[] tăng dần.
- Ghi: 2026-10-19.

### [Thấp] ClientHelloParser có các hàm static DecodeX(info, ...)

- Vị trí: `src/TqkLibrary.TlsFingerCopy/ClientHelloParser.cs` (các hàm Decode*).
- Vấn đề: cùng tham số `info` truyền qua nhiều hàm static, trái quy ước OOP của project.
- Nên làm: tách lớp phiên parse giữ `info` làm field.
- Ghi: 2026-10-19.

### [Thấp] Fork BC: BindersSize cũ sau HelloRetryRequest khi PSK bị bớt

- Vị trí: `libs/bc-csharp/crypto/src/tls/TlsClientProtocol.cs` (Send13ClientHelloRetry ~1716-1722, ApplyBoringSslPadding ~1998, SendClientHelloMessage ~2052).
- Vấn đề: lỗi có sẵn từ upstream; sau HRR mà PSK bị bớt thì BindersSize vẫn là của ClientHello đầu, làm sai binders và độ dài padding. TlsFingerCopy hiện không resume (không gửi PSK) nên chưa chạm.
- Nên làm: cập nhật bindersSize hoặc dựng lại ClientHello khi retry; cân nhắc gửi upstream.
- Ghi: 2026-10-19.

### [Thấp] Chưa có test so padding với ClientHello Chrome thật

- Vị trí: `libs/bc-csharp/crypto/src/tls/TlsClientProtocol.cs` (ApplyBoringSslPadding).
- Vấn đề: công thức padding BoringSSL mới kiểm bằng suy luận, chưa có golden test với bản capture Chrome có độ dài đã biết.
- Nên làm: record một ClientHello Chrome thật bằng RecorderApp, thêm test so độ dài và vị trí padding.
- Ghi: 2026-10-19.

### [Vừa] Fingerprint HTTP/2 vẫn là của .NET

- Vị trí: `src/TqkLibrary.TlsFingerCopy.Http/FingerprintHttpMessageHandler.cs` (h2 do SocketsHttpHandler dựng).
- Vấn đề: SETTINGS, WINDOW_UPDATE, thứ tự pseudo-header/header là của .NET; hệ thống so cả JA4 lẫn fingerprint h2 (Akamai) vẫn nhận ra. Recorder cũng chưa ghi được phần này (cần MITM).
- Nên làm: MITM ở Recorder để ghi h2 fingerprint + tự viết lớp HTTP/2 framing.
- Ghi: 2026-10-19.

### [Thấp] Chọn phiên bản HTTP phải đoán trước ALPN

- Vị trí: `src/TqkLibrary.TlsFingerCopy.Http/FingerprintHttpMessageHandler.cs` (MaxAlpnRetries, AlpnProtocolCache).
- Vấn đề: lần đầu gặp host lệch ALPN tốn một lần bắt tay bỏ đi; bản sửa retry 2 lần khi nhiều request song song chưa có test chứng minh.
- Nên làm: cân nhắc bắt tay trước rồi định tuyến sang handler 1.1/2 cố định và tái dùng chính kết nối đó.
- Ghi: 2026-10-19.

### [Thấp] Độ dài payload GREASE ECH cố định theo bản ghi

- Vị trí: `src/TqkLibrary.TlsFingerCopy.Http/ClientHelloPlan.cs` (RandomizeGreaseEch).
- Vấn đề: BoringSSL có thể chọn độ dài payload GREASE ECH ngẫu nhiên mỗi kết nối (chưa kiểm source); bản này giữ độ dài như bản ghi.
- Nên làm: đối chiếu source BoringSSL, nếu đúng thì random độ dài theo cùng tập giá trị.
- Ghi: 2026-10-19.

### [Thấp] Chunk còn trong hàng đợi không trả về ArrayPool khi Dispose/lỗi

- Vị trí: `src/TqkLibrary.TlsFingerCopy.Http/FingerprintTlsStream.cs` (DrainOutputAsync, Dispose).
- Vấn đề: rò khỏi pool (GC vẫn thu), không sai dữ liệu.
- Nên làm: dọn hàng đợi trong finally của Dispose.
- Ghi: 2026-10-19.
