# Перенос AI Shield Guardian на Linux

## 1. Подготовка сервера

Рекомендуемая среда:

- Ubuntu 22.04/24.04 LTS или Debian 12
- Python 3.10+
- Node.js 18+ или 20+
- 2 CPU, 4 GB RAM для демо; больше для постоянного мониторинга

Установить базовые пакеты:

```bash
sudo apt update
sudo apt install -y git curl build-essential python3 python3-venv python3-pip
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs nginx
```

## 2. Перенос проекта

```bash
cd /opt
sudo git clone <repo-url> ai-shield-guardian
sudo chown -R $USER:$USER /opt/ai-shield-guardian
cd /opt/ai-shield-guardian
```

Если перенос выполняется архивом:

```bash
scp -r AFM_Hack user@server:/opt/ai-shield-guardian
```

## 3. Backend

```bash
cd /opt/ai-shield-guardian
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r backend/requirements.txt
python models/train_model.py
python backend/app.py
```

API должен открыться на:

```text
http://<server-ip>:8000/docs
```

Для полного мониторинга процессов и сетевых соединений может потребоваться запуск от пользователя с расширенными правами. Для production лучше дать точечные capabilities или запускать сервисом с минимально нужными правами, а не постоянно работать от root.

## 4. Frontend

Для dev-режима:

```bash
cd /opt/ai-shield-guardian/frontend
npm install
REACT_APP_API_BASE=http://<server-ip>:8000/api npm run dev
```

Для production-сборки:

```bash
cd /opt/ai-shield-guardian/frontend
npm install
REACT_APP_API_BASE=/api npm run build
sudo rm -rf /var/www/ai-shield-guardian
sudo mkdir -p /var/www/ai-shield-guardian
sudo cp -r build/* /var/www/ai-shield-guardian/
```

## 5. systemd для backend

Создать `/etc/systemd/system/ai-shield-api.service`:

```ini
[Unit]
Description=AI Shield Guardian API
After=network.target

[Service]
WorkingDirectory=/opt/ai-shield-guardian
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/ai-shield-guardian/.venv/bin/python backend/app.py
Restart=always
RestartSec=5
User=ai-shield
Group=ai-shield

[Install]
WantedBy=multi-user.target
```

Создать пользователя и запустить сервис:

```bash
sudo useradd --system --home /opt/ai-shield-guardian --shell /usr/sbin/nologin ai-shield
sudo chown -R ai-shield:ai-shield /opt/ai-shield-guardian
sudo systemctl daemon-reload
sudo systemctl enable --now ai-shield-api
sudo systemctl status ai-shield-api
```

## 6. nginx reverse proxy

Пример `/etc/nginx/sites-available/ai-shield-guardian`:

```nginx
server {
    listen 80;
    server_name _;

    root /var/www/ai-shield-guardian;
    index index.html;

    location / {
        try_files $uri /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000/health;
    }
}
```

Активировать:

```bash
sudo ln -s /etc/nginx/sites-available/ai-shield-guardian /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Проверка после переноса

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/status
curl -X POST http://127.0.0.1:8000/api/analyze
```

В браузере открыть:

```text
http://<server-ip>/
```

Проверить вкладки:

- Threat Center: общая корреляция сигналов и timeline
- Access AI: риск сессий и контекст процессов
- DLP Control: блокировки утечек и покрытие контролей
- Phishing Lab: фишинговые кампании и сетевой контекст
- Response: запуск AI-анализа, рекомендации и журнал действий

## 8. Реальные SOC-логи

В проект добавлены безопасные JSONL-логи из OTRF Security-Datasets:

```text
backend/data/otrf/
```

Источник:

```text
https://github.com/OTRF/Security-Datasets
```

Проверить доступные датасеты:

```bash
curl http://127.0.0.1:8000/api/soc/datasets
```

Загрузить все OTRF-события в replay-режим:

```bash
curl -X POST http://127.0.0.1:8000/api/soc/load \
  -H "Content-Type: application/json" \
  -d '{"dataset_id":"all","max_events":1600}'
```

Посмотреть нормализованные события:

```bash
curl http://127.0.0.1:8000/api/soc/events?limit=20
```

Вернуться к демо-режиму:

```bash
curl -X POST http://127.0.0.1:8000/api/soc/clear
```

В интерфейсе это делается кнопками `Load SOC` и `Demo data`.

## 9. Предложенные действия ИИ после анализа

ИИ формирует действия из двух источников: сценарий инцидента `/api/security-feed` и live-анализ `/api/analyze`.

Для критичного доступа:

- Require step-up MFA
- Revoke active tokens
- Open SOC incident
- Isolate high-risk host, если live-анализ показывает высокий уровень угрозы

Для DLP:

- Block file transfer
- Notify data owner
- Preserve audit trail
- Prepare incident report

Для phishing:

- Quarantine messages
- Block sender domain
- Reset exposed passwords
- Block suspicious network destinations, если live-анализ нашел сетевые аномалии

Для endpoint/process risk:

- Review high-risk processes
- Collect triage package
- Limit outbound traffic
- Escalate to SOC lead при HIGH/CRITICAL

Для OTRF replay:

- Credential access: Isolate host, Reset exposed credentials, Collect LSASS evidence
- Defense evasion: Restore logging policy, Open SOC incident, Hunt related processes
- Discovery: Review account enumeration, Correlate lateral movement, Watch host
- Collection: Block data transfer, Notify data owner, Preserve audit trail

## 10. Что усилить перед production

- Добавить авторизацию на API и dashboard
- Ограничить CORS вместо `allow_origins=["*"]`
- Включить HTTPS через Let's Encrypt
- Хранить историю инцидентов в PostgreSQL
- Добавить audit log действий response playbook
- Разнести права: frontend через nginx, backend отдельным пользователем
- Настроить ротацию логов systemd/nginx
- Запланировать обновление frontend-стека: `react-scripts` тянет устаревшие зависимости
