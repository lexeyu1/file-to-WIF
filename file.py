import os
import hashlib
from ecdsa import SigningKey, SECP256k1
import base58

# Хэширование файла через SHA-256
def file_to_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.digest()

# Конвертация приватного ключа в WIF
def private_key_to_wif(private_key_bytes, compressed=True):
    payload = b'\x80' + private_key_bytes
    if compressed:
        payload += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

# Получение публичного ключа из приватного
def get_public_key(private_key_bytes):
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    return vk.to_string("compressed")

# Генерация Bitcoin-адреса
def public_key_to_address(public_key_bytes):
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    payload = b'\x00' + public_key_hash  # Префикс mainnet
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode('utf-8')
    return address

# Сохранение результата в файл
def save_to_file(data):
    with open("bitcoin_wallets.txt", "a", encoding="utf-8") as f:
        f.write(f"🔐 Приватный ключ (HEX): {data['private_key_hex']}\n")
        f.write(f"🔑 Приватный ключ (WIF): {data['wif']}\n")
        f.write(f"🧾 Публичный ключ: {data['public_key']}\n")
        f.write(f"₿ Bitcoin-адрес: {data['address']}\n")
        f.write("-" * 60 + "\n")

# Генерация ключей из файла
def generate_keys_from_file(file_path):
    private_key_bytes = file_to_sha256(file_path)
    private_key_int = int.from_bytes(private_key_bytes, 'big')

    if not (1 <= private_key_int < SECP256k1.order):
        raise ValueError("Сгенерированный ключ вне допустимого диапазона secp256k1")

    valid_private_key_bytes = private_key_int.to_bytes(32, 'big')

    wif_key = private_key_to_wif(valid_private_key_bytes)
    public_key = get_public_key(valid_private_key_bytes)
    bitcoin_address = public_key_to_address(public_key)

    return {
        'private_key_hex': valid_private_key_bytes.hex(),
        'wif': wif_key,
        'public_key': public_key.hex(),
        'address': bitcoin_address
    }

# Генерация ключей для всех файлов в папке CODE
def generate_keys_from_folder(folder_name="CODE"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(script_dir, folder_name)

    if not os.path.exists(folder_path):
        print(f"❌ Папка '{folder_name}' не найдена по пути: {folder_path}")
        return

    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    if not files:
        print(f"❌ В папке '{folder_name}' нет файлов для обработки.")
        return

    for filename in files:
        file_path = os.path.join(folder_path, filename)
        print(f"\n🔄 Обработка файла: {filename}")
        try:
            keys = generate_keys_from_file(file_path)
            print("🔐 Приватный ключ (HEX):", keys['private_key_hex'])
            print("🔑 Приватный ключ (WIF):", keys['wif'])
            print("🧾 Публичный ключ:", keys['public_key'])
            print("₿ Bitcoin-адрес:", keys['address'])
            save_to_file(keys)
            print("✅ Данные сохранены в bitcoin_wallets.txt")
        except Exception as e:
            print("❌ Ошибка:", str(e))

if __name__ == "__main__":
    mode = input("Выберите режим:\n1 - Один файл\n2 - Все файлы из папки CODE\nВведите 1 или 2: ").strip()

    if mode == '1':
        file_path = input("Введите путь к файлу: ")
        try:
            keys = generate_keys_from_file(file_path)
            print("\n🔐 Приватный ключ (HEX):", keys['private_key_hex'])
            print("\n🔑 Приватный ключ (WIF):", keys['wif'])
            print("\n🧾 Публичный ключ:", keys['public_key'])
            print("\n₿ Bitcoin-адрес:", keys['address'])
            save_to_file(keys)
            print("\n✅ Данные сохранены в bitcoin_wallets.txt")
        except Exception as e:
            print("❌ Ошибка:", str(e))

    elif mode == '2':
        generate_keys_from_folder()

    else:
        print("❌ Неверный ввод. Пожалуйста, введите 1 или 2.")
