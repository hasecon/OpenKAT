# OpenKAT Development

## Repository

- **Upstream:** SSC-ICT-Innovatie/nl-kat-coordination
- **This repo:** Development fork (hasecon/OpenKAT)
- **Architecture docs:** See [hasecon/openkat-ideas](https://github.com/hasecon/openkat-ideas) for architecture documentation, proposals, and ADRs

## Stack

- **Language:** Python 3.13
- **Frontend:** Django 5.1 + Manon design system
- **Database:** PostgreSQL 15 (Rocky, Bytes, Katalogus, Scheduler) + XTDB (Octopoes)
- **Message Queue:** RabbitMQ 3.12
- **Package Manager:** uv (pyproject.toml + uv.lock) → exported to requirements.txt
- **Containerization:** Docker Compose
- **Code Quality:** ruff, mypy, pre-commit
- **Frontend build:** yarn, ParcelJS

## Code Navigation

### Rocky (Django Frontend — port 8000)

```
rocky/
├── rocky/
│   ├── views/              # Django views (class-based, organized by feature)
│   ├── templates/          # Django templates (Manon design system)
│   ├── forms/              # Form definitions
│   ├── urls.py             # URL routing
│   ├── middleware/         # Django middleware
│   ├── settings.py         # Django settings
│   └── migrations/         # Django database migrations
├── tools/
│   └── management/commands/ # Django management commands (setup_test_org, etc.)
├── tests/                  # pytest tests
├── assets/                 # Frontend source (JS/CSS, built by ParcelJS)
├── Dockerfile
└── Makefile                # utest, itest targets
```

### Octopoes (Knowledge Graph — port 8001)

```
octopoes/
├── octopoes/
│   ├── api/                # FastAPI endpoints
│   │   └── api.py          # Main API app
│   ├── models/
│   │   ├── ooi/            # OOI type definitions (one file per category)
│   │   └── types.py        # OOI type registry (all types must be registered here)
│   ├── repositories/       # XTDB data access
│   ├── core/
│   │   └── service.py      # Core business logic
│   ├── bits/               # Inference rules (create Findings from OOIs)
│   ├── xtdb/               # XTDB client and query builder
│   └── config/
│       └── settings.py     # Pydantic settings
├── tests/                  # pytest tests
├── docs/                   # Internal architecture docs
├── Dockerfile
└── Makefile                # itest target (no utest — run pytest in container)
```

### Boefjes (Scanner Plugins)

```
boefjes/
├── boefjes/
│   ├── plugins/            # Scanner plugin directory
│   │   └── kat_*/          # Each plugin: main.py, normalize.py, boefje.json, schema.json
│   ├── app.py              # Boefje/normalizer worker application
│   ├── katalogus/          # Katalogus service (plugin registry, port 8003)
│   │   ├── root.py         # FastAPI app
│   │   ├── storage/        # Database layer + migrations
│   │   └── plugins/        # Plugin management logic
│   └── config.py           # Settings
├── tests/                  # pytest tests
├── tools/
│   └── run_boefje.py       # Manual boefje execution tool
├── Dockerfile
└── Makefile                # utest, itest targets
```

### Bytes (Raw Data Storage — port 8002)

```
bytes/
├── bytes/
│   ├── api/                # FastAPI endpoints
│   │   └── router.py       # API routes
│   ├── repositories/       # Data access layer
│   ├── models.py           # SQLAlchemy models
│   ├── database/
│   │   └── migrations/     # Alembic migrations
│   ├── raw/                # Raw file storage handlers
│   └── config.py           # Settings
├── tests/                  # pytest tests
├── Dockerfile
└── Makefile                # utest, itest targets
```

### Mula / Scheduler (port 8004)

```
mula/
├── scheduler/
│   ├── schedulers/         # Scheduler implementations
│   │   ├── boefje.py       # BoefjeScheduler
│   │   ├── normalizer.py   # NormalizerScheduler
│   │   └── report.py       # ReportScheduler
│   ├── server/             # FastAPI server
│   ├── storage/            # Database layer + Alembic migrations
│   ├── models/             # Pydantic models (Task, Schedule, etc.)
│   └── config/
│       └── settings.py     # Settings
├── tests/                  # pytest tests
├── docs/                   # Architecture docs (C4 model)
├── Dockerfile
└── Makefile                # utest, itest targets
```

## Development Workflow

### Quick Start

```bash
git clone https://github.com/hasecon/OpenKAT.git
cd OpenKAT
make kat           # Build + start everything + create superuser
```

This runs: `make env-if-empty` → `make build` → `make up`

### Key Makefile Targets

| Target | Description |
|---|---|
| `make kat` | Full build + start (default) |
| `make build` | Build all Docker images |
| `make up` | Start all containers |
| `make stop` | Stop containers (preserve data) |
| `make down` | Remove containers (preserve volumes) |
| `make clean` | Remove containers AND volumes (data loss) |
| `make env` | Generate .env with random credentials |
| `make update` | Git pull + rebuild |
| `make reset` | Clean + rebuild (data loss) |
| `make docs` | Build Sphinx documentation |
| `make requirements` | Regenerate requirements.txt from uv.lock |

### Rebuild a Single Component

```bash
docker compose build rocky        # Rebuild only Rocky
docker compose up -d rocky        # Restart only Rocky
docker compose build octopoes_api # Rebuild Octopoes
docker compose up -d octopoes_api octopoes_api_worker  # Restart both
```

Hot-reload is enabled for development: code changes in mounted volumes are picked up automatically by uvicorn (Octopoes, Bytes, Katalogus) and Django runserver (Rocky).

### Frontend Development

```bash
cd rocky
yarn install
yarn build          # One-time build
yarn watch          # Watch mode for development
```

Frontend assets are built by ParcelJS from `rocky/assets/` to `rocky/assets/dist/`.

## Common Development Tasks

### Add a new Django view/template

1. Create view class in `rocky/rocky/views/`
2. Create template in `rocky/rocky/templates/`
3. Add URL pattern in `rocky/rocky/urls.py`
4. Add tests in `rocky/tests/`

### Add a new OOI type

1. Define the model class in `octopoes/octopoes/models/ooi/` (appropriate category file)
2. Register in `octopoes/octopoes/models/types.py`
3. Add tests

### Write a new boefje/normalizer plugin

1. Create directory `boefjes/boefjes/plugins/kat_<name>/`
2. Create `boefje.json` — plugin metadata (id, name, consumes, produces)
3. Create `main.py` — boefje logic (scan execution)
4. Create `normalize.py` — normalizer logic (parse raw → yield OOIs)
5. Optional: `schema.json` — JSON schema for plugin settings
6. Test with `boefjes/tools/run_boefje.py`

### Add a database migration

- **Rocky (Django):** `docker exec <rocky-container> python manage.py makemigrations`
- **Bytes/Katalogus/Scheduler (Alembic):** `docker exec <container> alembic revision --autogenerate -m "description"`

### Add a dependency

1. Add to `pyproject.toml` in the relevant component
2. Run `uv lock --project <component_dir>`
3. Run `make requirements` to regenerate requirements.txt files

## Testing

**Always run tests inside Docker containers, never locally.** There is no local Python venv.

### Per-Component Test Matrix

| Component | Unit tests | Integration tests | Notes |
|---|---|---|---|
| boefjes | `cd boefjes && make utest` | `cd boefjes && make itest` | |
| rocky | `cd rocky && make utest` | `cd rocky && make itest` | |
| bytes | `cd bytes && make utest` | `cd bytes && make itest` | |
| mula | `cd mula && make utest` | `cd mula && make itest` | |
| octopoes | `docker exec <container> python -m pytest tests/` | `cd octopoes && make itest` | Requires running stack |

- `make utest` / `make itest` spin up their own Docker environments
- Octopoes has no `utest` Makefile target — run pytest inside the container

### Run Specific Tests

```bash
# Specific test file
cd boefjes && make utest file=tests/test_specific.py

# Specific test function
docker exec <container> python -m pytest tests/test_file.py::test_function -v
```

### Pre-commit

```bash
pre-commit run --all-files    # Run all checks (ruff, mypy, etc.)
pre-commit run ruff --all-files  # Run only ruff
```

Always run `pre-commit run --all-files` before pushing.

## Debugging

### Container Logs

```bash
docker compose logs --tail 50 rocky           # Django errors
docker compose logs --tail 50 octopoes_api    # OOI/graph errors
docker compose logs --tail 50 bytes           # Raw data storage errors
docker compose logs --tail 30 scheduler       # Task scheduling errors
docker compose logs --tail 30 boefje          # Scan execution errors
docker compose logs --tail 30 normalizer      # Normalization errors
docker compose logs --tail 30 katalogus       # Plugin registry errors
```

### Filter for Errors

```bash
docker compose logs 2>&1 | grep -iE '(error|exception|traceback|500|failed)'
```

### Health Endpoints

| Service | Health check |
|---|---|
| Rocky | `curl http://localhost:8000` |
| Octopoes | `curl http://localhost:8001/health` |
| Bytes | `curl http://localhost:8002/health` |
| Katalogus | `curl http://localhost:8003/health` |
| Scheduler | `curl http://localhost:8004/health` |
| RabbitMQ | `curl http://localhost:15672` (management UI) |

### Django Admin / Shell

```bash
# Django admin: http://localhost:8000/admin/
# Django shell:
docker exec -it <rocky-container> python manage.py shell

# Direct database access:
docker exec -it <postgres-container> psql -U postgres rocky_db
```

### XTDB Direct Access

```bash
# Query XTDB directly:
curl http://localhost:3000/_xtdb/query -H 'Content-Type: application/edn' -d '{:query {:find [?e] :where [[?e :object_type "Hostname"]]}}'

# Or use the xtdb-cli tool in Octopoes:
docker exec <octopoes-container> python -m octopoes.xtdb.cli
```

### Known Non-Issues

- `IndexError: pop from an empty deque` in Bytes logs — transient RabbitMQ reconnect at startup, self-recovers
- `AttributeError: module 'bcrypt' has no attribute '__about__'` — benign startup warning

## Environment Configuration

| File | Purpose |
|---|---|
| `.env` | Local environment (auto-generated by `make env`, contains secrets) |
| `.env-defaults` | Default values (superuser credentials, service URLs) |
| `.env-dist` | Template for `.env` generation |
| `.env-prod` | Production environment template |

**Never commit `.env`** — it contains generated secrets.

## Commit Rules

- Short, descriptive title in imperative mood
- Keep commits focused on a single change
- No Co-Authored-By or AI attribution lines
- Always run `pre-commit run --all-files` before pushing
