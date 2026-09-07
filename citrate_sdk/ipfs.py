"""
Real IPFS integration for Citrate Python SDK
"""

import requests
import json
import hashlib
from typing import Optional, Dict, Any
from .errors import CitrateError, IPFSError
from ._url_security import enforce_transport_security


class IPFSClient:
    """
    Real IPFS client for uploading and retrieving model data
    """

    def __init__(self, api_url: str = "http://localhost:5001",
                 allow_insecure_http: bool = False,
                 timeout: float = 30.0):
        """
        Initialize IPFS client

        Args:
            api_url: IPFS API endpoint URL
            allow_insecure_http: SECREM-01 WEB-4 (pre-audit 2026-06-09) —
                silence the cleartext-transport warning when intentionally
                using plain http:// to a remote IPFS API host. Localhost
                http:// is always allowed silently. Defaults to False.
            timeout: CIT-SDKPY-03 — per-request timeout (seconds) for every IPFS
                HTTP call. Was absent on upload/download/pin, so a hung IPFS host
                blocked the caller indefinitely. Defaults to 30s.
        """
        # SECREM-01 WEB-4: warn when uploading/fetching over plaintext http://
        # to a remote IPFS node.
        api_url = enforce_transport_security(api_url, allow_insecure_http=allow_insecure_http)
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'citrate-python-sdk/0.1.0'
        })

    def upload_bytes(self, data: bytes) -> str:
        """
        Upload bytes to IPFS and return the hash

        Args:
            data: Bytes to upload

        Returns:
            IPFS hash (CID)

        Raises:
            IPFSError: If upload fails
        """
        try:
            # Use IPFS HTTP API to add file
            files = {'file': ('model_data', data, 'application/octet-stream')}

            response = self.session.post(
                f"{self.api_url}/api/v0/add",
                files=files,
                params={'pin': 'true', 'wrap-with-directory': 'false'},
                timeout=self.timeout,
            )

            if response.status_code != 200:
                raise IPFSError(f"IPFS upload failed: HTTP {response.status_code}")

            result = response.json()
            ipfs_hash = result['Hash']

            # Verify the upload by getting file info
            self._verify_upload(ipfs_hash)

            return ipfs_hash

        except requests.exceptions.RequestException as e:
            raise IPFSError(f"IPFS connection error: {str(e)}")
        except json.JSONDecodeError as e:
            raise IPFSError(f"Invalid IPFS response: {str(e)}")
        except KeyError as e:
            raise IPFSError(f"Missing field in IPFS response: {str(e)}")

    def download_bytes(self, ipfs_hash: str) -> bytes:
        """
        Download bytes from IPFS using hash

        Args:
            ipfs_hash: IPFS hash (CID)

        Returns:
            Downloaded bytes

        Raises:
            IPFSError: If download fails
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/cat",
                params={'arg': ipfs_hash},
                timeout=self.timeout,
            )

            if response.status_code != 200:
                raise IPFSError(f"IPFS download failed: HTTP {response.status_code}")

            return response.content

        except requests.exceptions.RequestException as e:
            raise IPFSError(f"IPFS connection error: {str(e)}")

    def get_file_info(self, ipfs_hash: str) -> Dict[str, Any]:
        """
        Get file information from IPFS

        Args:
            ipfs_hash: IPFS hash (CID)

        Returns:
            File information dict
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/object/stat",
                params={'arg': ipfs_hash},
                timeout=self.timeout,
            )

            if response.status_code != 200:
                raise IPFSError(f"IPFS stat failed: HTTP {response.status_code}")

            return response.json()

        except requests.exceptions.RequestException as e:
            raise IPFSError(f"IPFS connection error: {str(e)}")
        except json.JSONDecodeError as e:
            raise IPFSError(f"Invalid IPFS response: {str(e)}")

    def pin_file(self, ipfs_hash: str) -> bool:
        """
        Pin file in IPFS to prevent garbage collection

        Args:
            ipfs_hash: IPFS hash (CID)

        Returns:
            True if pinning successful
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/pin/add",
                params={'arg': ipfs_hash},
                timeout=self.timeout,
            )

            return response.status_code == 200

        except requests.exceptions.RequestException:
            return False

    def is_available(self) -> bool:
        """
        Check if IPFS node is available

        Returns:
            True if IPFS node is reachable
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/version",
                timeout=5
            )
            return response.status_code == 200

        except requests.exceptions.RequestException:
            return False

    def get_version(self) -> Optional[str]:
        """
        Get IPFS node version

        Returns:
            Version string or None if unavailable
        """
        try:
            response = self.session.post(
                f"{self.api_url}/api/v0/version",
                timeout=5
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('Version')

        except (requests.exceptions.RequestException, json.JSONDecodeError):
            pass

        return None

    def _verify_upload(self, ipfs_hash: str) -> None:
        """
        Verify that file was uploaded successfully

        Args:
            ipfs_hash: IPFS hash to verify

        Raises:
            IPFSError: If verification fails
        """
        try:
            info = self.get_file_info(ipfs_hash)
            if not info:
                raise IPFSError("File verification failed - no file info")

        except Exception as e:
            raise IPFSError(f"File verification failed: {str(e)}")


class IPFSManager:
    """
    High-level IPFS manager with fallback mechanisms
    """

    def __init__(self, primary_url: str = "http://localhost:5001",
                 fallback_urls: Optional[list] = None,
                 allow_insecure_http: bool = False,
                 timeout: float = 30.0):
        """
        Initialize IPFS manager with primary and fallback nodes

        Args:
            primary_url: Primary IPFS node URL
            fallback_urls: List of fallback IPFS node URLs. CIT-SDKPY-03: there
                are NO implicit third-party fallbacks — pass explicit URLs to opt
                in. The pre-fix default silently added public gateways, so raw
                (possibly unencrypted) model bytes could be replicated off-box to
                a third party by default.
            allow_insecure_http: SECREM-01 WEB-4 (pre-audit 2026-06-09) —
                forwarded to every underlying IPFSClient so remote http://
                fallbacks are also covered by the cleartext-transport control.
            timeout: CIT-SDKPY-03 — per-request timeout forwarded to each client.
        """
        self.primary = IPFSClient(primary_url, allow_insecure_http=allow_insecure_http, timeout=timeout)
        self.fallbacks = [
            IPFSClient(url, allow_insecure_http=allow_insecure_http, timeout=timeout)
            for url in (fallback_urls or [])
        ]
        self.active_client = None

    def upload(self, data: bytes) -> str:
        """
        Upload data with automatic fallback

        Args:
            data: Bytes to upload

        Returns:
            IPFS hash

        Raises:
            IPFSError: If all nodes fail
        """
        clients = [self.primary] + self.fallbacks
        last_error = None

        for client in clients:
            try:
                if client.is_available():
                    ipfs_hash = client.upload_bytes(data)
                    self.active_client = client

                    # Try to pin on other available nodes for redundancy
                    self._replicate_to_other_nodes(ipfs_hash, clients, client)

                    return ipfs_hash

            except IPFSError as e:
                last_error = e
                continue

        if last_error:
            raise last_error
        else:
            raise IPFSError("No IPFS nodes available")

    def download(self, ipfs_hash: str) -> bytes:
        """
        Download data with automatic fallback

        Args:
            ipfs_hash: IPFS hash to download

        Returns:
            Downloaded bytes

        Raises:
            IPFSError: If all nodes fail
        """
        clients = [self.primary] + self.fallbacks
        last_error = None

        # Try active client first if available
        if self.active_client:
            try:
                return self.active_client.download_bytes(ipfs_hash)
            except IPFSError:
                pass

        # Try all clients
        for client in clients:
            try:
                if client.is_available():
                    return client.download_bytes(ipfs_hash)

            except IPFSError as e:
                last_error = e
                continue

        if last_error:
            raise last_error
        else:
            raise IPFSError("No IPFS nodes available")

    def _replicate_to_other_nodes(self, ipfs_hash: str, all_clients: list,
                                 exclude_client: IPFSClient) -> None:
        """
        Replicate file to other available nodes for redundancy
        """
        for client in all_clients:
            if client != exclude_client and client.is_available():
                try:
                    client.pin_file(ipfs_hash)
                except IPFSError:
                    # Ignore errors for replication
                    pass


# Global IPFS manager instance
_ipfs_manager = None


def get_ipfs_manager(ipfs_urls: Optional[list] = None) -> IPFSManager:
    """
    Get or create global IPFS manager instance

    Args:
        ipfs_urls: Optional list of IPFS node URLs

    Returns:
        IPFSManager instance
    """
    global _ipfs_manager

    if _ipfs_manager is None:
        # CIT-SDKPY-03: default to localhost only. No implicit third-party
        # fallbacks — the previous defaults (ipfs.infura.io, ipfs.fleek.co) sent
        # raw model bytes off-box to a third party by default, and both were
        # effectively defunct so the "redundancy" was illusory. Remote gateways
        # are opt-in via `ipfs_urls`.
        primary_url = "http://localhost:5001"
        fallback_urls: list = []

        if ipfs_urls:
            primary_url = ipfs_urls[0]
            fallback_urls = ipfs_urls[1:] if len(ipfs_urls) > 1 else []

        _ipfs_manager = IPFSManager(primary_url, fallback_urls)

    return _ipfs_manager


def upload_to_ipfs(data: bytes, ipfs_urls: Optional[list] = None) -> str:
    """
    Convenience function to upload data to IPFS

    Args:
        data: Bytes to upload
        ipfs_urls: Optional list of IPFS node URLs

    Returns:
        IPFS hash
    """
    manager = get_ipfs_manager(ipfs_urls)
    return manager.upload(data)


def download_from_ipfs(ipfs_hash: str, ipfs_urls: Optional[list] = None) -> bytes:
    """
    Convenience function to download data from IPFS

    Args:
        ipfs_hash: IPFS hash to download
        ipfs_urls: Optional list of IPFS node URLs

    Returns:
        Downloaded bytes
    """
    manager = get_ipfs_manager(ipfs_urls)
    return manager.download(ipfs_hash)