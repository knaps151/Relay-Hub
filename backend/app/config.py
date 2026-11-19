from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:////data/relay.db"
    admin_password: str = "parktech"
    http_only: bool = True

    public_ui_url: str = "http://127.0.0.1:8000"
    headscale_url: str = "http://127.0.0.1:8080"
    wg_endpoint: str = "127.0.0.1:51820"
    openvpn_endpoint: str = "127.0.0.1:1194"

    headscale_api_url: str = "http://headscale:8080"
    headscale_api_key_file: str = "/data/headscale-api.key"
    headscale_socket: str = "/var/run/headscale/headscale.sock"
    headscale_user: str = "parktech"

    wg_interface: str = "wg0"
    wg_listen_port: int = 51820
    wg_hub_address: str = "10.100.0.1/24"
    wg_dry_run: bool = True
    nft_dry_run: bool = True

    openvpn_pki_dir: str = "/vpn/pki"
    openvpn_ccd_dir: str = "/vpn/ccd"
    openvpn_status_file: str = "/vpn/openvpn-status.log"
    openvpn_clients_dir: str = "/vpn/clients"

    default_base_cidr: str = "10.101.0.0/16"
    default_local_subnet: str = "192.168.1.0/24"
    poll_interval_seconds: int = 15
    sync_interval_seconds: int = 2


@lru_cache
def get_settings() -> Settings:
    return Settings()
