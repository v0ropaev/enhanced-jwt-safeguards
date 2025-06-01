# Enhanced JWT Safeguards API

**Проект для курсовой работы** — демонстрация безопасной аутентификации на FastAPI с JWT, рейтлимитингом, отзывом и обновлением токенов.

## 🔐 Особенности

- Аутентификация с помощью **JWT** (access + refresh токены)
- Проверка **алгоритма подписи** токена
- Защита с помощью **рейт-лимитов** (SlowAPI)
- Поддержка **отзыва refresh-токенов** (blacklist)
- Защита от повторного использования refresh-токена
- Swagger UI для тестирования `/docs`
- Обработка ошибок и логгирование

## 🚀 Запуск

1. Клонируй репозиторий:

```bash
git clone https://github.com/v0ropaev/enhanced-jwt-safeguards.git
cd enhanced-jwt-safeguards
```

2. Установи зависимости:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Генерация RSA ключей:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

4. Создай `.env`:

```env
PRIVATE_KEY_PATH=private.pem
PUBLIC_KEY_PATH=public.pem
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_MINUTES=60
```

5. Запусти приложение:

```bash
uvicorn app.main:app --reload
```

6. Перейди в Swagger UI:

```
http://127.0.0.1:8000/docs
```

---

## 📚 Документация по эндпоинтам

| Method | URL            | Описание                             |
|--------|----------------|--------------------------------------|
| POST   | `/register`    | Регистрация нового пользователя      |
| POST   | `/login`       | Аутентификация, получение токенов    |
| POST   | `/refresh`     | Обновление access и refresh токена   |
| POST   | `/logout`      | Отзыв refresh-токена                 |
| GET    | `/protected`   | Защищенный маршрут (access токен)    |

---

## 🧪 Тесты

Для запуска тестов:

```bash
PYTHONPATH=./ pytest
```

Тесты находятся в папке [`tests/`](./tests/), покрывают:
- регистрацию
- вход
- обновление токена
- защиту `/protected`

---

## 🛡 План по безопасности

- ✅ Проверка подписи и `alg`
- ✅ Проверка `scope` в refresh-токене
- ✅ Проверка отозванных токенов (`revoked`)
- ✅ Блок повторного использования refresh (`used`)
- ✅ Лимитирование на уровне API

---

## 📎 Зависимости

- FastAPI
- jose (JWT)
- passlib (bcrypt)
- slowapi (рейтлимитинг)
- dotenv
- uvicorn
