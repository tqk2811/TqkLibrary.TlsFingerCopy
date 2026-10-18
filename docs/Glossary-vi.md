# Thuật ngữ

## ClientHello

Message đầu tiên client gửi khi bắt tay TLS, chưa mã hoá. Chứa danh sách cipher suite, các extension và thứ tự của chúng. Đây là thứ server dùng để nhận dạng client là trình duyệt hay thư viện nào.

## TLS fingerprint

Tập đặc điểm của ClientHello (cipher, extension, thứ tự, groups, sig algs, ALPN…) đủ để phân biệt loại client. File fingerprint của thư viện lưu tập này dạng JSON.

## JA3

Chuỗi fingerprint cũ (Salesforce): version, cipher, extension, groups, point formats nối bằng dấu phẩy rồi lấy MD5. Bị Chrome làm vô dụng khi Chrome xáo thứ tự extension.

## JA4

Chuỗi fingerprint mới (FoxIO) dạng `a_b_c`: phần `a` tóm version/SNI/số lượng/ALPN, `b` là hash cipher đã sắp xếp, `c` là hash extension đã sắp xếp + sig algs. Không đổi khi thứ tự extension bị xáo.

## GREASE

Giá trị rác có dạng `0x?A?A` mà Chrome chèn vào cipher, extension, groups, versions để ép server chịu được giá trị lạ. Mỗi kết nối sinh giá trị mới.

## ALPN

Extension trong ClientHello để client và server thống nhất giao thức tầng trên (`h2` hay `http/1.1`).

## ALPS

Extension `application_settings` của Chrome (17513/17613): gửi kèm cấu hình HTTP/2 ngay trong bắt tay. Client phải gửi thêm message EncryptedExtensions khi server chấp nhận.

## SNI

Extension `server_name`: tên miền client muốn kết nối. Nhìn thấy được khi chưa mã hoá, Recorder dùng nó để đặt tên file.

## ECH

Encrypted Client Hello: mã hoá phần ClientHello bên trong. Chrome gửi bản "GREASE ECH" (payload ngẫu nhiên) dù server không hỗ trợ.

## Padding (BoringSSL)

Extension `padding` (21): BoringSSL độn ClientHello dài 256–511 byte lên đủ 512 byte để tránh lỗi của một số middlebox.

## HelloRetryRequest

Server trả lời ClientHello bằng yêu cầu gửi lại với key share khác; client phải gửi ClientHello thứ hai.

## h2c prior knowledge

Dùng HTTP/2 trên kết nối không TLS mà không cần nâng cấp từ HTTP/1.1. Thư viện dùng cách này để `SocketsHttpHandler` chạy HTTP/2 trên stream TLS do mình tự bắt tay.

## Half-close

Một đầu TCP báo "không gửi nữa" (FIN) nhưng vẫn nhận tiếp. Proxy phải chuyển tiếp đúng tín hiệu này, nếu không hai đầu treo tới timeout.
