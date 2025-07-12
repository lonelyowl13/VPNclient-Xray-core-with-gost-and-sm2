# Примеры (samples)

## Структура
- `make_cert/` — скрипты генерации тестовых сертификатов (SM2, GOST, ECDSA)
- `certs/` — сгенерированные сертификаты
- `configs/server/` — серверные конфиги VMess/VLESS
- `configs/client/` — клиентские конфиги
- `run/server/` — запуск сервера с нужным конфигом
- `run/client/` — запуск клиента
- `scripts/` — проверка сертификатов

## Использование
```bash
# Генерация всех сертификатов
cd make_cert && ./make_all_certs.sh

# Проверка всех сертификатов
cd scripts && ./verify_all_certs.sh

# Запуск сервера
cd run/server && ./run_vmess_sm2.sh

# Запуск клиента
cd run/client && ./run_vless_client_sm2.sh
```

Конфиги пересоздавать не нужно, используйте как есть.
Скрипты генерации сертификатов — только для теста. 