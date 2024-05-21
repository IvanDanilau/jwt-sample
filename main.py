import base64
import datetime
import hashlib
import hmac
import json

# обычно для подписи JWT используются более надежные секреты, например RSA ключи.
# Но для объяснения принципов работы JWT это не имеет значения
SECRET = "mysecret"


# функция кодирования строки (в нашем случае это части JWT) в base64 кодировку
def base64_encoded(source: bytes) -> str:
    # '=' в конце, или padding связан с особенностями  работы base64,
    # и служит для обеспечения кратности данных, подлежащих кодировке.
    # Для JWT принято использовать кодировку base64 без padding
    return base64.urlsafe_b64encode(source).rstrip(b'=').decode()


def base64_decoded(encoded_str: str) -> str:
    padding_needed = 4 - (len(encoded_str) % 4)
    if padding_needed:
        encoded_str += "=" * padding_needed
    return base64.urlsafe_b64decode(encoded_str).decode()


# Заголовок в JSON формате, закодированный в base64.
def get_base64_encoded_header() -> str:
    header = json.dumps({"alg": "HS256", "typ": "JWT"})  # пример заголовка
    print(f"Header info: {header}")
    encoded_header = base64_encoded(header.encode())  # Кодируем в base64
    print(f"Encoded header: {encoded_header}")
    return encoded_header


# Полезная нагрузка в JSON формате, закодированная в base64.
def get_base64_encoded_payload() -> str:
    payload = json.dumps({  # пример полезной нагрузки, данные могут быть любыми
        "sub": "user1234",
        "exp": int(datetime.datetime(2100, 1, 1).timestamp())
    })
    print(f"Payload info: {payload}")
    encoded_payload = base64_encoded(payload.encode())  # Кодируем в base64
    print(f"Encoded payload: {encoded_payload}")
    return encoded_payload


# Получаем подпись с помощью HMAC функции, которая использует секрет и данные, содержащиеся в header и payload
def get_signature(base64_encoded_header: str, base64_encoded_payload: str, secret: str) -> str:
    # Получили JWT, он еще не подписан, но это уже JWT токен.
    unsigned_jwt = base64_encoded_header + "." + base64_encoded_payload
    # применение hmc для вычисления подписи
    signature = hmac.new(secret.encode(), unsigned_jwt.encode(), hashlib.sha256).digest()
    encoded_signature = base64_encoded(signature)  # Кодируем в base64
    print(f"Signature: {encoded_signature}")
    return encoded_signature


if __name__ == '__main__':
    base64_encoded_header = get_base64_encoded_header()
    base64_encoded_payload = get_base64_encoded_payload()
    base64_encoded_signature = get_signature(base64_encoded_header, base64_encoded_payload, SECRET)
    # Подписываем токен, путем присоединения закодированных частей через точку
    signed_jwt = base64_encoded_header + "." + base64_encoded_payload + "." + base64_encoded_signature
    # Можно скопировать значение токена и проверить его подпись на сайте https://jwt.io/, указав правильный секрет
    print("Signed JWT: " + signed_jwt)
    # Демонстрация того, что любой может прочитать данные из токена, без необходимости знать секрет
    without_signature = signed_jwt[:signed_jwt.rfind(".")]  # обрезаем подпись
    print(f"I still can see the data: {base64_decoded(without_signature)}")
    # Демонстрация того, что для верификации подписи необходимо знание секрета
    new_signature = get_signature(base64_encoded_header, base64_encoded_payload, "invalid secret")
    print(f"Signatures are equal: {base64_encoded_signature == new_signature}")
    print(f"Final JWT: {signed_jwt}")
