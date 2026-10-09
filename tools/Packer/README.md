# Packer — сервер обновлений для TelegramWSS

Утилиты для сборки, подписи и деплоя обновлений кастомного клиента TelegramWSS
(форк на актуальном upstream с WEB proxy; канал CDN без изменений).

## Структура

```
tools/Packer/
├── bump_version.py     # Bump/set версии во всех исходниках
├── packer.py           # Упаковщик: QDataStream Qt5.1 + LZMA, подпись v1 и/или v2
├── update_v2.py        # Формат v2 (TDUP + Ed25519), повторяет core/update_verify.cpp
├── update_keys.py      # Ключи v2: init / rotate / show
├── deploy.py           # Пайплайн: сборка -> упаковка -> JSON -> SFTP-загрузка
├── requirements.txt    # Python-зависимости
├── keys/               # Приватные ключи (.gitignored), бэкап обязателен
│   ├── stable_private.pem      # RSA v1
│   ├── stable_public.pem
│   ├── beta_private.pem
│   ├── beta_public.pem
│   ├── v2_root_private.pem     # Ed25519 root: подписывает только манифест
│   └── v2_release_<id>.pem     # Ed25519 release: подписывает пакеты
└── site/
    ├── nginx.conf
    └── www/
        ├── current4          # Заглушка ({}), заменяется deploy.py
        └── files/
```

## Архитектура

```mermaid
flowchart LR
    subgraph client [TelegramWSS]
        exe[TelegramWSS.exe]
        updater[Updater.exe]
    end
    subgraph server [cdn.honeydrinksomewine.com]
        current4[GET /current4]
        files[GET /files/tx64upd{N}]
    end
    exe -->|1. Check| current4
    current4 -->|version + link| exe
    exe -->|2. Download| files
    files -->|signed LZMA archive| exe
    exe -->|3. Verify RSA+SHA1| exe
    exe -->|4. Launch| updater
    updater -->|5. Copy + relaunch| exe
```

## Два формата обновлений

С 7.3 апстрим принимает только пакеты v2: конверт `TDUP`, подпись Ed25519
ключом из манифеста, манифест подписан корневым ключом, вшитым при сборке из
`Telegram/Resources/update/`. Клиенты 7.2.x принимают только наш v1 (RSA).
Поэтому фиды разведены:

| Клиенты | Префикс обновлений | Фид | Формат |
|---|---|---|---|
| до 7.2.80x | `https://cdn.honeydrinksomewine.com` | `/current4`, `/files/tx64upd{N}` | v1 |
| 7.3.1+ | `https://cdn.honeydrinksomewine.com/v2` | `/v2/current4`, `/v2/files/td-update-win-x64-{N}` | v2 |

`packer.py` и `deploy.py` по умолчанию (`--format both`) делают оба пакета из
одного сжатия и выкладывают каждый в свой фид, так что старые клиенты могут
обновиться сразу на любую новую версию.

### Ключи v2

Созданы командой `python update_keys.py init`: приватные в `keys/`, публичные
trust-файлы в `Telegram/Resources/update/` (коммитятся и вшиваются в клиент).

- **Корневой ключ не терять и не пересоздавать** (`init --force`): клиенты с
  другим корнем больше не примут ни одного обновления.
- `python update_keys.py rotate` — новый release-ключ, старый отзывается,
  `manifest_version` +1. Новый манифест едет внутри пакетов, клиенты его
  принимают автоматически; пересборка нужна только для новых установок.
- `python update_keys.py show` — проверить и показать манифест.
- При мерже апстрима файлы `Telegram/Resources/update/*` всегда оставлять наши.

## Предварительные требования

### 1. Python-зависимости

```powershell
pip install -r requirements.txt
```

### 2. RSA-ключи

Уже сгенерированы в `keys/`. Если нужны новые:

```bash
# Windows: через WSL
openssl genrsa -out keys/stable_private.pem 1024
openssl rsa -in keys/stable_private.pem -RSAPublicKey_out -out keys/stable_public.pem
openssl genrsa -out keys/beta_private.pem 1024
openssl rsa -in keys/beta_private.pem -RSAPublicKey_out -out keys/beta_public.pem
```

### 3. Настроенный DNS и сервер

- Домен: `cdn.honeydrinksomewine.com` -> A-запись на IP сервера
- На сервере: Nginx + Let's Encrypt (см. `site/nginx.conf`)

## Сборка и деплой обновления

### Быстрый запуск

```powershell
# С автоматическим увеличением версии
python deploy.py --bump --platform win64 ^
    --host update@cdn.honeydrinksomewine.com ^
    --remote-path /home/update/www ^
    --base-url https://cdn.honeydrinksomewine.com ^
    --ssh-key ~/.ssh/id_rsa

# С явной версией (без bump)
python deploy.py ^
    --version 6009301 ^
    --platform win64 ^
    --host update@cdn.honeydrinksomewine.com ^
    --remote-path /home/update/www ^
    --base-url https://cdn.honeydrinksomewine.com ^
    --ssh-key ~/.ssh/id_rsa
```

### Пошагово

#### 1. Собрать клиент

```powershell
cmake --build ..\..\out --config Release --target Telegram
```

#### 2. Упаковать обновление

```powershell
python packer.py ^
    --path ..\..\out\Release ^
    --version 6009301 ^
    --platform win64 ^
    --private-key keys\stable_private.pem ^
    --output tx64upd6009301
```

#### 3. Сгенерировать JSON

```powershell
# Содержимое current4:
@'
{
  "win64": {
    "stable": {
      "released": 6009301,
      "link": "/files/tx64upd6009301"
    }
  }
}
'@
```

#### 4. Загрузить на сервер

```powershell
scp tx64upd6009301 update@cdn.honeydrinksomewine.com:/home/update/www/files/
scp current4 update@cdn.honeydrinksomewine.com:/home/update/www/
```

## Настройка сервера

### Nginx

```bash
# Копировать конфиг
cp site/nginx.conf /etc/nginx/sites-available/cdn-update
ln -s /etc/nginx/sites-available/cdn-update /etc/nginx/sites-enabled/

# HTTPS
apt install certbot python3-certbot-nginx
certbot --nginx -d cdn.honeydrinksomewine.com

# Проверка
nginx -t
systemctl reload nginx
```

### Структура на сервере

```
/home/update/www/
├── current4
└── files/
    ├── tx64upd6009300
    ├── tx64upd6009301
    └── ...
```

## Версионирование

Формат: `MMMmmmppp` (major * 10^6 + minor * 10^3 + patch).

- `AppVersion = 6009300` = версия 6.9.300
- При каждом обновлении увеличивается patch: `6009300` -> `6009301` -> ...
- Сравнение числовое: `AppVersion` нового файла должен быть строго больше текущего

### bump_version.py

Обновляет все файлы версии:
`version.h`, `build/version`, `Telegram.rc`, `Updater.rc`

```powershell
# Увеличить patch
python bump_version.py --bump

# Задать вручную (semver или число)
python bump_version.py --set 6.9.301
python bump_version.py --set 6009301
```

После смены версии нужна пересборка клиента.

## Параметры deploy.py

| Параметр | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `--version` | нет* | — | Версия для упаковки: `6009301` или `6.9.301` |
| `--bump` | нет | — | Увеличить patch через `bump_version.py` |
| `--set-version` | нет | — | Задать версию в исходниках без bump |
| `--platform` | нет | `win64` | `win64`, `win`, `winarm`, `mac`, `armac`, `linux` |
| `--host` | да | — | `user@cdn.honeydrinksomewine.com` |
| `--remote-path` | нет | `/home/update/www` | Путь к webroot на сервере |
| `--base-url` | нет | `https://cdn.honeydrinksomewine.com` | Базовый URL для ссылок в JSON |
| `--private-key` | нет | `keys/stable_private.pem` | RSA-ключ для v1 |
| `--format` | нет | `both` | `v1` -> `/current4`, `v2` -> `/v2/current4`, `both` |
| `--ssh-key` | нет | `~/.ssh/id_rsa` | SSH-ключ для подключения |
| `--no-build` | нет | — | Пропустить cmake-сборку |
| `--pack-dir` | нет | — | Использовать готовую директорию с файлами |
| `--build-dir` | нет | — | Кастомная директория сборки |

## Параметры packer.py

| Параметр | Обязательный | Описание |
|---|---|---|
| `--path` | да | Директория с файлами для упаковки |
| `--version` | да | Числовая версия |
| `--platform` | да | `win64`, `win`, `winarm`, `mac`, `armac`, `linux` |
| `--private-key` | для v1 | Файл приватного RSA-ключа (v2-ключ берётся из `keys/` по манифесту) |
| `--output` | нет | Имя выходного файла v1 (v2 пишется в `Release/v2/`) |
| `--alpha` | нет | Alpha-версия (0 = не alpha), только v1 |
| `--format` | нет | `v1`, `v2`, `both` (по умолчанию) |
| `--channel` | нет | Канал v2: `stable` (по умолчанию) или `beta` |

## Проверка

```bash
# Убедиться, что JSON отдаётся
curl https://cdn.honeydrinksomewine.com/current4

# Убедиться, что файл доступен
curl -I https://cdn.honeydrinksomewine.com/files/tx64upd6009301

# v2-фид (клиенты 7.3+)
curl https://cdn.honeydrinksomewine.com/v2/current4
```

## Изменённые файлы клиента

| Файл | Изменение |
|---|---|
| `Telegram/Resources/update/*` | Наш корневой ключ и манифест v2 (`update_keys.py`) |
| `Telegram/SourceFiles/core/version.h` | `AppVersion`, `AppName=TelegramWSS Desktop` и др. |
| `Telegram/SourceFiles/storage/localstorage.cpp` | URL по умолчанию -> `cdn.honeydrinksomewine.com/v2` |
| `Telegram/build/version` | Синхронизирован с version.h |
| `Telegram/Resources/winrc/Telegram.rc` | FILEVERSION для свойств exe |
| `Telegram/Resources/winrc/Updater.rc` | FILEVERSION для Updater.exe |
| `Telegram/build/setup.iss` | GUID инсталлятора, имя приложения |
| `.gitignore` | Исключены `tools/Packer/keys/`, `tools/Packer/current4.json` |
