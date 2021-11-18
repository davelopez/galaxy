from abc import ABC
import json
import os
import yaml

from cryptography.fernet import Fernet, MultiFernet

try:
    from custos.clients.resource_secret_management_client import ResourceSecretManagementClient
    from custos.transport.settings import CustosServerClientSettings
    import custos.clients.utils.utilities as custos_util
    custos_sdk_available = True
except ImportError:
    custos_sdk_available = False

try:
    import hvac
except ImportError:
    hvac = None

from galaxy import model


class UnknownVaultTypeException(Exception):
    pass


class Vault(ABC):

    def read_secret(self, path: str) -> dict:
        pass

    def write_secret(self, path: str, value: dict) -> None:
        pass


class HashicorpVault(Vault):

    def __init__(self, config):
        if not hvac:
            raise UnknownVaultTypeException("Hashicorp vault library 'hvac' is not available. Make sure hvac is installed.")
        self.vault_address = config.get('vault_address')
        self.vault_token = config.get('vault_token')
        self.client = hvac.Client(url=self.vault_address, token=self.vault_token)

    def read_secret(self, path: str) -> dict:
        try:
            response = self.client.secrets.kv.read_secret_version(path=path)
            return response['data']['data']
        except hvac.exceptions.InvalidPath:
            return None

    def write_secret(self, path: str, value: dict) -> None:
        self.client.secrets.kv.v2.create_or_update_secret(path=path, secret=value)


class DatabaseVault(Vault):

    def __init__(self, sa_session, config):
        self.sa_session = sa_session
        self.encryption_keys = config.get('encryption_keys')
        self.fernet_keys = [Fernet(key.encode('utf-8')) for key in self.encryption_keys]

    def _get_multi_fernet(self) -> MultiFernet:
        return MultiFernet(self.fernet_keys)

    def _update_or_create(self, key, value):
        vault_entry = self.sa_session.query(model.Vault).filter_by(key=key).first()
        if vault_entry:
            vault_entry.value = value
        else:
            vault_entry = model.Vault(key=key, value=value)
        self.sa_session.merge(vault_entry)
        self.sa_session.flush()

    def read_secret(self, path: str) -> dict:
        key_obj = self.sa_session.query(model.Vault).filter_by(key=path).first()
        if key_obj:
            f = self._get_multi_fernet()
            return json.loads(f.decrypt(key_obj.value.encode('utf-8')).decode('utf-8'))
        return None

    def write_secret(self, path: str, value: dict) -> None:
        f = self._get_multi_fernet()
        token = f.encrypt(json.dumps(value).encode('utf-8'))
        self._update_or_create(key=path, value=token.decode('utf-8'))


class CustosVault(Vault):

    def __init__(self, config):
        if not custos_sdk_available:
            raise UnknownVaultTypeException("Custos sdk library 'custos-sdk' is not available. Make sure the custos-sdk is installed.")
        self.custos_settings = CustosServerClientSettings(custos_host=config.get('custos_host'),
                                                          custos_port=config.get('custos_port'),
                                                          custos_client_id=config.get('custos_client_id'),
                                                          custos_client_sec=config.get('custos_client_sec'))
        self.b64_encoded_custos_token = custos_util.get_token(custos_settings=self.custos_settings)
        self.client = ResourceSecretManagementClient(self.custos_settings)

    def read_secret(self, path: str) -> dict:
        try:
            response = self.client.get_KV_credential(token=self.b64_encoded_custos_token,
                                                     client_id=self.custos_settings.CUSTOS_CLIENT_ID,
                                                     key=path)
            return json.loads(json.loads(response)['value'])
        except Exception:
            return None

    def write_secret(self, path: str, value: dict) -> None:
        if self.read_secret(path):
            self.client.update_KV_credential(token=self.b64_encoded_custos_token,
                                             client_id=self.custos_settings.CUSTOS_CLIENT_ID,
                                             key=path, value=json.dumps(value))
        else:
            self.client.set_KV_credential(token=self.b64_encoded_custos_token,
                                          client_id=self.custos_settings.CUSTOS_CLIENT_ID,
                                          key=path, value=json.dumps(value))


class UserVaultWrapper(Vault):

    def __init__(self, vault: Vault, user):
        self.vault = vault
        self.user = user

    def read_secret(self, path: str) -> dict:
        return self.vault.read_secret(f"user/{self.user.id}/{path}")

    def write_secret(self, path: str, value: dict) -> None:
        return self.vault.write_secret(f"user/{self.user.id}/{path}", value)


class VaultFactory(object):

    @staticmethod
    def load_vault_config(vault_conf_yml: str) -> dict:
        if os.path.exists(vault_conf_yml):
            with open(vault_conf_yml) as f:
                return yaml.safe_load(f)
        return None

    @staticmethod
    def from_vault_type(app, vault_type: str, cfg: dict) -> Vault:
        if vault_type == "hashicorp":
            return HashicorpVault(cfg)
        elif vault_type == "database":
            return DatabaseVault(app.model.context, cfg)
        elif vault_type == "custos":
            return CustosVault(cfg)
        else:
            raise UnknownVaultTypeException(f"Unknown vault type: {vault_type}")

    @staticmethod
    def from_app_config(app) -> Vault:
        vault_config = VaultFactory.load_vault_config(app.config.vault_config_file)
        if vault_config:
            return VaultFactory.from_vault_type(app, vault_config.get('type'), vault_config)
        return None
