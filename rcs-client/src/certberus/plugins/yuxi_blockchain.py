from .base import CertberusPlugin
from web3 import Web3
from eth_account import Account
from cryptography.hazmat.primitives import hashes
import logging

logger = logging.getLogger(__name__)

class Plugin(CertberusPlugin):
    def name(self) -> str:
        return "yuxi_blockchain"

    def on_init(self) -> None:
        self.rpc_url = self.config.get("rpc_url", "http://127.0.0.1:8545")
        self.contract_address = self.config.get("contract_address")
        self.private_key = self.config.get("private_key")
        self.gas_limit = self.config.get("gas_limit", 300000)
        
        if self.enabled and self.rpc_url:
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
                if self.private_key:
                    self.account = Account.from_key(self.private_key)
                else:
                    self.account = None
            except Exception as e:
                logger.error(f"Yuxi Plugin failed to connect: {e}")
                self.w3 = None
        else:
            self.w3 = None

    def post_issue(self, cert_obj, **kwargs) -> None:
        if not self.enabled or not self.w3 or not self.account:
            return

        try:
            cert_hash_hex = cert_obj.fingerprint(hashes.SHA256()).hex()
            
            # Minimal ABI for anchorCertificate
            abi = [
                {
                    "inputs": [{"internalType": "bytes32", "name": "_certHash", "type": "bytes32"}],
                    "name": "anchorCertificate",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]
            contract = self.w3.eth.contract(address=self.contract_address, abi=abi)
            
            cert_hash_bytes = bytes.fromhex(cert_hash_hex.replace("0x", ""))
            
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            txn = contract.functions.anchorCertificate(cert_hash_bytes).build_transaction({
                'chainId': self.w3.eth.chain_id,
                'gas': self.gas_limit,
                'maxFeePerGas': self.w3.to_wei('2', 'gwei'),
                'maxPriorityFeePerGas': self.w3.to_wei('1', 'gwei'),
                'nonce': nonce,
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(txn, private_key=self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            logger.info(f"Yuxi Hook: Certificate anchored to blockchain. TX: {tx_hash.hex()}")
        except Exception as e:
            logger.error(f"Yuxi Hook Error: {e}")

    def is_ca_authorized(self, ca_address):
        """Used by the engine to check status."""
        if not self.enabled or not self.w3:
            return True
            
        try:
            abi = [
                {
                    "inputs": [{"internalType": "address", "name": "_caAddress", "type": "address"}],
                    "name": "isCAValid",
                    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            contract = self.w3.eth.contract(address=self.contract_address, abi=abi)
            return contract.functions.isCAValid(ca_address).call()
        except Exception as e:
            logger.error(f"Yuxi Plugin: Failed to check CA authorization: {e}")
            return False
