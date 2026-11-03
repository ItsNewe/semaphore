COMPOSE = docker compose -f docker-compose.yml -f docker-compose.dev.yml

.PHONY: dev tui

dev:
	$(COMPOSE) up --build -d

tui:
	$(COMPOSE) exec -e TUI_RELOAD=1 semaphore semaphore-tui
