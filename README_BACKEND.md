# Backend notes

Backend chính nằm trong `threatfeeds_backend.py`. Tài liệu chạy đầy đủ nằm ở `README.md`.

Chạy nhanh:

```bash
pip install -r requirements.txt
DEBUG=0 python threatfeeds_backend.py
```

Mở Swagger UI: `http://localhost:8000/docs`.

Các module đã có: collector, IoC normalization/dedup, enrichment, risk scoring, MITRE ATT&CK mapping, ML train/evaluate/predict, Telegram test, dashboard API và export CSV.
