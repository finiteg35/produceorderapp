# Produce Order App

A command-line produce ordering application that manages inventory, orders,
delivery dates, and store users using plain JSON files for storage.

## Features

- **Inventory management** – add, list, update, and remove produce items
- **Order submission** – place orders and retrieve full order history
- **Configurable delivery dates** – view and set allowed delivery dates
- **Store users** – list and add store accounts

## Prerequisites

- Python 3.9 or higher (no third-party packages required)

## Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/finiteg35/produceorderapp.git
   cd produceorderapp
   ```

2. **Run the app** – the data directory (`data/`) ships with example files and
   will be created automatically if it does not exist.

   ```bash
   python main.py --help
   ```

## Deployment (Hostinger VPS + Traefik + Docker Compose)

1. **Prerequisites**
   - Docker and Docker Compose installed on the VPS
   - Traefik already running on the VPS
   - A Docker external network named `traefik_proxy` available to Traefik
   - A Traefik TLS cert resolver named `letsencrypt` configured

2. **Clone the repository**

   ```bash
   git clone https://github.com/finiteg35/produceorderapp.git
   cd produceorderapp
   ```

3. **Create environment file and set your domain**

   ```bash
   cp .env.example .env
   ```

   Then edit `docker-compose.yml` and replace `yourdomain.com` in the Traefik
   label with your real domain.

4. **Start the app**

   ```bash
   docker compose up -d
   ```

5. **Important**
   - You must replace `yourdomain.com` in `docker-compose.yml` with your actual domain.
   - JSON flat-file data persists in `./data` on the host (mounted to `/data` in the container).

## Usage

```
python main.py <command> <subcommand> [options]
```

### Inventory

| Command | Description |
|---------|-------------|
| `python main.py inventory list` | List all inventory items |
| `python main.py inventory add --category CAT --item ITEM --qty QTY` | Add or update an item |
| `python main.py inventory update --category CAT --item ITEM --qty QTY` | Update quantity |
| `python main.py inventory remove --category CAT --item ITEM` | Remove an item |

### Orders

| Command | Description |
|---------|-------------|
| `python main.py orders list` | List all orders |
| `python main.py orders list --store STORE` | Filter orders by store name |
| `python main.py orders list --date DATE` | Filter by submission date prefix (e.g. `2025-04`) |
| `python main.py orders list --item ITEM` | Filter by item name |
| `python main.py orders add --store STORE --category CAT --item ITEM --qty QTY --date DATE [--by USER]` | Submit a new order |
| `python main.py orders remove --id ID` | Remove an order by ID |

### Delivery Dates

| Command | Description |
|---------|-------------|
| `python main.py dates list` | Show allowed delivery dates |
| `python main.py dates set "April 15, 2025" "April 16, 2025"` | Set specific dates |
| `python main.py dates generate` | Auto-generate dates for the next 7 days |

### Users

| Command | Description |
|---------|-------------|
| `python main.py users list` | List all store users |
| `python main.py users add --store STORE --username USERNAME` | Add a new user |

## Examples

```bash
# List inventory
python main.py inventory list

# Add a new inventory item
python main.py inventory add --category "Squash" --item "Butternut - 20# bag" --qty 50

# Generate allowed delivery dates for the coming week
python main.py dates generate

# Submit an order
python main.py orders add \
  --store "Scarborough Hannaford" \
  --category "Potatoes" \
  --item "White Chef - 50# bags" \
  --qty 5 \
  --date "April 15, 2025" \
  --by scarborough_hannaford

# List orders for a specific store
python main.py orders list --store "Scarborough"

# List all users
python main.py users list
```

## Data Files

All data is stored in the `data/` directory as human-readable JSON files:

| File | Description |
|------|-------------|
| `data/inventory.json` | Produce inventory items |
| `data/orders.json` | Submitted orders |
| `data/users.json` | Store user accounts |
| `data/settings.json` | App settings (allowed delivery dates) |

The files ship with example data and can be edited directly with any text editor.

## Project Structure

```
produceorderapp/
├── main.py          # Entire application – CLI entry point and all logic
├── requirements.txt # No dependencies (standard library only)
├── README.md        # This file
└── data/
    ├── inventory.json  # Example inventory data
    ├── orders.json     # Example orders
    └── users.json      # Example store users
```

## Customising the Data Directory

Set the `DATA_DIR` environment variable to store files elsewhere:

```bash
DATA_DIR=/path/to/my/data python main.py inventory list
```

## License

This project is open source. Feel free to use and modify it for your needs.
