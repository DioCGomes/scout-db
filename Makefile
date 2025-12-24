.PHONY: all clone build clean clean-all download download-reviewed download-all help

OWNER = mlw157 # Owner of repo where you are uploading the databases
REPO_URL = https://github.com/github/advisory-database.git
REPO_DIR = advisory-database
RELEASE_URL = https://github.com/$(OWNER)/scout-db/releases/latest/download

# Default target
all: clone build

# Clone the GitHub Advisory Database
clone:
	@if [ -d "$(REPO_DIR)" ]; then \
		echo "Updating advisory database..."; \
		cd $(REPO_DIR) && git pull; \
	else \
		echo "Cloning advisory database..."; \
		git clone --depth 1 $(REPO_URL) $(REPO_DIR); \
	fi

# Build both databases
build:
	@echo "Building databases..."
	python3 dbupdate.py
	@echo "Done!"

# Download databases from latest release
download: download-reviewed download-all

download-reviewed:
	@echo "Downloading scout-reviewed.db..."
	curl -LO $(RELEASE_URL)/scout-reviewed.db

download-all:
	@echo "Downloading scout.db..."
	curl -LO $(RELEASE_URL)/scout.db

# Clean generated files
clean:
	@echo "Removing databases..."
	rm -f scout.db scout-reviewed.db

# Clean everything including cloned repo
clean-all: clean
	@echo "Removing advisory database..."
	rm -rf $(REPO_DIR)

# Help
help:
	@echo "Scout DB Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all              Clone advisory database and build (default)"
	@echo "  clone            Clone or update the GitHub Advisory Database"
	@echo "  build            Build both SQLite databases"
	@echo ""
	@echo "Download targets:"
	@echo "  download         Download both databases from latest release"
	@echo "  download-reviewed Download only reviewed database"
	@echo "  download-all     Download only all-vulns database"
	@echo ""
	@echo "Other targets:"
	@echo "  clean            Remove generated databases"
	@echo "  clean-all        Remove databases and cloned advisory repo"
	@echo "  help             Show this help message"

