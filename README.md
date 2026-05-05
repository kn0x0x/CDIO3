# ThreatShield CDIO - Threat Intelligence Platform

Đồ án CDIO: **Xây dựng hệ thống Threat Intelligence hỗ trợ phát hiện sớm và cảnh báo tấn công mạng**.

Source này đã được hoàn thiện lại thành một bộ chạy demo đầy đủ gồm 3 phần:

- **Backend FastAPI**: collector, chuẩn hóa IoC, dedup, enrichment, risk scoring, MITRE ATT&CK mapping, API dashboard, export CSV, Telegram alert.
- **Data Analysis + ML**: thống kê severity/type/feed/country/timeline, heatmap, attack vector, mô hình scikit-learn dự đoán tactic, confusion matrix, train/evaluate/predict endpoint.
- **Frontend React**: login/register/forgot password, overview, map Leaflet, analytics Recharts, threats list + filter/export, feeds CRUD, activity, settings/demo controls.

---
## 2. Cấu trúc chính

```txt
.
├── threatfeeds_backend.py        # FastAPI backend all-in-one
├── requirements.txt              # Python dependencies
├── package.json                  # React/Vite frontend dependencies
├── src/app                       # Frontend pages/components/services
├── data/local-community-iocs.csv # Local/offline IoC feed for demo
├── scripts/demo_test.py          # Script test nhanh backend đang chạy
├── Dockerfile.backend
├── Dockerfile.frontend
├── docker-compose.yml
└── .env.example
```

Backend tự tạo các file runtime sau khi chạy lần đầu:

```txt
threatfeeds.db
models/ioc_tactic_model.joblib
```

Hai file này không bắt buộc có sẵn vì hệ thống sẽ tự seed dữ liệu và train model.

---

## 3. Chạy local không Docker

### 3.1. Backend

Yêu cầu: Python 3.10+.

```bash
cd ThreatShield-CDIO
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
python threatfeeds_backend.py
```

Mở:

```txt
API docs : http://localhost:8000/docs
Health   : http://localhost:8000/health
```

Nếu máy chạy chậm hoặc reload của Uvicorn bị treo, chạy chế độ production nhẹ hơn:

```bash
DEBUG=0 python threatfeeds_backend.py
```

Trên Windows PowerShell:

```powershell
$env:DEBUG="0"
python threatfeeds_backend.py
```

### 3.2. Frontend

Yêu cầu: Node.js 20+ hoặc 22+.

```bash
cd ThreatShield-CDIO
npm config set registry https://registry.npmjs.org/
npm install
npm run dev
```

Mở:

```txt
Frontend: http://localhost:5173
```

Frontend mặc định gọi backend tại `http://localhost:8000`. Nếu đổi backend URL:

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

---

## 4. Chạy bằng Docker Compose

Yêu cầu: Docker Desktop hoặc Docker Engine có Compose plugin.

```bash
cd ThreatShield-CDIO
docker compose up --build
```

Mở:

```txt
Frontend: http://localhost:5173
Backend : http://localhost:8000
Swagger : http://localhost:8000/docs
```

Dữ liệu SQLite được lưu trong Docker volume `backend-data`.

Reset toàn bộ Docker demo:

```bash
docker compose down -v
docker compose up --build
```

---

## 5. Chế độ feed online/offline

Mặc định project chạy nhanh ở chế độ demo offline:

```env
REMOTE_FEEDS_ENABLED=0
```

Khi bấm collector, hệ thống dùng local/offline fallback để tạo IoC nên vẫn demo được khi không có Internet.

Muốn gọi threat feed public thật, sửa `.env`:

```env
REMOTE_FEEDS_ENABLED=1
FEED_REQUEST_TIMEOUT=3
```

Sau đó restart backend. Nếu feed public lỗi/rate-limit, backend vẫn fallback và ghi log lỗi trong collector history.

---

## 6. Telegram alert

Tạo bot bằng BotFather, lấy `TELEGRAM_BOT_TOKEN` và `TELEGRAM_CHAT_ID`, sau đó điền vào `.env`:

```env
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
ALERT_THRESHOLD=80
```

Restart backend. Vào frontend `/settings`, bấm **Gửi test Telegram**. Backend cũng tự gửi cảnh báo khi IoC mới có risk score vượt `ALERT_THRESHOLD`.

---

## 7. Demo nhanh trước khi nộp

### 7.1. Test backend bằng script

Sau khi backend đang chạy:

```bash
python scripts/demo_test.py
```

Kết quả mong đợi:

```txt
GET /health: healthy
GET /api/v1/dashboard: dashboard loaded
GET /api/v1/alerts?limit=3: alerts fetched
POST /api/v1/pipeline/enrich/50.16.16.211: indicator enriched
POST /api/v1/ml/predict: ML prediction completed
GET /api/v1/collector/status: collector status
```

### 7.2. Test API bằng curl

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/dashboard
curl http://localhost:8000/api/v1/collector/status
curl "http://localhost:8000/api/v1/alerts?limit=5&severity=high"
```

Enrichment IP demo trong báo cáo:

```bash
curl -X POST http://localhost:8000/api/v1/pipeline/enrich/50.16.16.211
```

ML predict:

```bash
curl -X POST http://localhost:8000/api/v1/ml/predict \
  -H "Content-Type: application/json" \
  -d '{"indicator_value":"CVE-2024-3400","indicator_type":"cve","description":"remote exploit vulnerability","tags":["kev","exploit"]}'
```

Trigger collector thủ công:

```bash
curl -X POST http://localhost:8000/api/v1/collector/trigger
```

Export CSV:

```bash
curl -L http://localhost:8000/api/v1/export/alerts.csv -o threatshield-alerts.csv
```

---

## 8. Luồng demo giao diện

1. Đăng nhập bằng tài khoản admin.
2. Vào **Tổng quan**: kiểm tra tổng IoC, active incidents, countries, biểu đồ 7 ngày, top threats.
3. Vào **Bản đồ**: xem scatter map IoC theo quốc gia, severity và top countries.
4. Vào **Phân tích**:
   - Timeline ingest theo ngày.
   - Heatmap `indicator_type × severity`.
   - Stacked bar `feed × severity`.
   - Attack vectors.
   - MITRE coverage + ML summary + confusion matrix.
5. Vào **Mối đe dọa**:
   - Search IoC/title.
   - Filter severity.
   - Export CSV/JSON/XLS/HTML.
6. Vào **Nguồn dữ liệu**:
   - Xem 7 feed nguồn.
   - Admin có thể thêm/sửa/xóa/tạm dừng feed.
7. Vào **Cài đặt**:
   - Kiểm tra backend health.
   - Trigger collector.
   - Train lại ML.
   - Test Telegram.
   - Reset database demo.

---

## 9. API chính

| Nhóm | Endpoint | Mô tả |
|---|---|---|
| System | `GET /health` | Kiểm tra backend/database/ML |
| Dashboard | `GET /api/v1/dashboard` | Toàn bộ dữ liệu tổng quan |
| Feeds | `GET/POST/PATCH/DELETE /api/v1/feeds` | Quản lý nguồn feed |
| Alerts | `GET/POST/PATCH/DELETE /api/v1/alerts` | Quản lý IoC/cảnh báo |
| Stats | `GET /api/v1/stats/*` | Severity, type, timeline, countries, heatmap |
| Map | `GET /api/v1/map/threats` | Dữ liệu bản đồ Leaflet |
| Analytics | `GET /api/v1/analytics/summary` | Data Analysis tổng hợp |
| Pipeline | `POST /api/v1/pipeline/enrich/{target}` | Enrichment IoC/IP/domain/CVE |
| MITRE | `GET /api/v1/mitre/matrix` | Mapping tactic/technique |
| ML | `GET/POST /api/v1/ml/*` | Status, train, evaluate, predict |
| Collector | `GET/POST /api/v1/collector/*` | Status, trigger, history |
| Telegram | `POST /api/v1/telegram/test` | Test gửi bot |
| Export | `GET /api/v1/export/alerts.csv` | Xuất CSV |

---

## 10. Ghi chú kỹ thuật

- Database dùng SQLite để demo nhẹ, không cần cài PostgreSQL/Elasticsearch. API và schema được thiết kế để có thể nâng cấp sang PostgreSQL/Elasticsearch sau.
- ML dùng scikit-learn với TF-IDF + Multinomial Naive Bayes để phân loại tactic hỗ trợ. Rule-based MITRE vẫn được giữ để giải thích được quyết định.
- Risk score bám theo trọng số demo: reputation, CVE/CVSS, tần suất, độ tin cậy nguồn feed, liên quan ATT&CK/TTP.
- Hệ thống seed mặc định `SEED_ALERT_COUNT=916` IoC để dashboard có dữ liệu ngay khi demo.
- Frontend có fallback dữ liệu tối thiểu, nhưng để demo đầy đủ nên bật backend trước.

---

## 11. Troubleshooting

### NPM báo lỗi registry/403

Chạy:

```bash
npm config set registry https://registry.npmjs.org/
npm cache clean --force
npm install --registry=https://registry.npmjs.org/
```

### Frontend không gọi được backend

Kiểm tra backend:

```bash
curl http://localhost:8000/health
```

Nếu backend chạy port khác, set lại:

```bash
VITE_API_URL=http://localhost:8000 npm run dev
```

### Collector không lấy feed public

Để demo offline, giữ:

```env
REMOTE_FEEDS_ENABLED=0
```

Để gọi feed thật, đổi thành `1`. Một số nguồn public có thể rate-limit hoặc đổi format; backend có retry/fallback và ghi trong collector history.

### Muốn reset dữ liệu

```bash
curl -X POST http://localhost:8000/api/v1/reset
```

Hoặc trong frontend vào **Cài đặt** → **Reset database demo**.

