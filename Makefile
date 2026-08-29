.PHONY: all build test run clean docker-build deploy

PROJECT_ID ?= authenium-prod1
REGION ?= asia-southeast2
SERVICE_NAME ?= vid-generator

all: build test

build:
	@echo "Building binaries..."
	go build -o bin/server ./cmd/server
	go build -o bin/vid-cli ./cmd/cli
	@echo "Build complete."

test:
	@echo "Running unit tests..."
	go test -v ./tests/...

run: build
	@echo "Running local server..."
	./bin/server

docker-build:
	@echo "Building Docker image..."
	docker build -t gcr.io/$(PROJECT_ID)/$(SERVICE_NAME):latest .

deploy: docker-build
	@echo "Deploying to Google Cloud Run..."
	docker push gcr.io/$(PROJECT_ID)/$(SERVICE_NAME):latest
	gcloud run deploy $(SERVICE_NAME) \
		--image gcr.io/$(PROJECT_ID)/$(SERVICE_NAME):latest \
		--project $(PROJECT_ID) \
		--region $(REGION) \
		--set-env-vars PROJECT_ID=$(PROJECT_ID),DATABASE_ID=vid-registry,ENVIRONMENT=production \
		--no-allow-unauthenticated \
		--memory 256Mi \
		--cpu 1

clean:
	rm -rf bin/
