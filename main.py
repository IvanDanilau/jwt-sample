import base64
import datetime
import hashlib
import hmac
import json

# обычно для подписи jwt используются более надежные секреты, например RSA ключи.
# Но для объяснения принципов работы JWT это не имеет значения
SECRET = "mysecret"


def base64_encoded(source: bytes) -> str:
    # '=' в конце, или padding связан с особенностями  работы base64,
    # и служит для обеспечения кратности данных, подлежащих кодировке.
    # Для jwt принято использовать кодировку base64 без padding
    return base64.urlsafe_b64encode(source).rstrip(b'=').decode()


def base64_decoded(encoded_str: str) -> str:
    padding_needed = 4 - (len(encoded_str) % 4)
    if padding_needed:
        encoded_str += "=" * padding_needed
    return base64.urlsafe_b64decode(encoded_str).decode()


# Заголовок в JSON формате, закодированный в base64.
def get_header() -> str:
    header = json.dumps({"alg": "HS256",
                         "typ": "JWT"})
    print(f"Header info: {header}")
    encoded_header = base64_encoded(header.encode())
    print(f"Encoded header: {encoded_header}")
    return encoded_header


# Полезная нагрузка в JSON формате, закодированная в base64.
def get_payload() -> str:
    payload = json.dumps({
        # данные могут быть любыми
        "sub": "user1234",
        "exp": int(datetime.datetime(2100, 1, 1).timestamp())
    })
    print(f"Payload info: {payload}")
    encoded_header = base64_encoded(payload.encode())
    print(f"Encoded payload: {encoded_header}")
    return encoded_header


# Получаем подпись с помощью HMAC функции, которая использует секрет и данные, содержащиеся в header и payload
def get_signature(unsigned_jwt: str, secret: str) -> str:
    signature = hmac.new(secret.encode(), unsigned_jwt.encode(), hashlib.sha256).digest()
    encoded_signature = base64_encoded(signature)
    print(f"Signature: {encoded_signature}")
    return encoded_signature


if __name__ == '__main__':
    header = get_header()
    payload = get_payload()
    unsigned_jwt = header + "." + payload
    # Получили JWT, он еще не подписан, но это уже jwt токен.
    print("Unsigned jwt: " + unsigned_jwt)
    signature = get_signature(unsigned_jwt, SECRET)
    signed_jwt = unsigned_jwt + "." + signature
    # Можно скопировать значение токена и проверить его на сайте https://jwt.io/, указав правильный секрет
    print("Signed jwt: " + signed_jwt)
    # Демонстрация того, что любой может прочитать данные из токена, без необходимости знать секрет
    without_signature = signed_jwt[:signed_jwt.rfind(".")]
    print(f"I still can see the data: {base64_decoded(without_signature)}")
    # Демострация того, что для верификации подписи необходимо знание секрета
    new_signature = get_signature(unsigned_jwt, "invalid secret")
    print(f"Try to get signature: {signature}")
    print(f"Signature are equal: {signature == new_signature}")
    print(f"Final jwt: {signed_jwt}")
