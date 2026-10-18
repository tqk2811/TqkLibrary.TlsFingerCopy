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
