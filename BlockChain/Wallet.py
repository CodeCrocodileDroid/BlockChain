from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii
import hashlib
import json
from time import time
from typing import List, Dict

class Block:
    """A single block in our blockchain"""

    def __init__(self, index: int, transactions: List[Dict], timestamp: float, previous_hash: str, nonce: int = 0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        """Returns the hash of the block instance"""
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    """The blockchain class"""

    def __init__(self):
        self.chain: List[Block] = []
        self.unconfirmed_transactions: List[Dict] = []
        self.difficulty = 2
        self.create_genesis_block()

    def create_genesis_block(self):
        """Creates the first block in the blockchain"""
        genesis_block = Block(0, [], time(), "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self) -> Block:
        """Returns the last block in the chain"""
        return self.chain[-1]

    def proof_of_work(self, block: Block) -> str:
        """Proof of work algorithm"""
        block.nonce = 0
        computed_hash = block.compute_hash()

        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_block(self, block: Block, proof: str) -> bool:
        """Adds a new block to the chain after verification"""
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    def is_valid_proof(self, block: Block, block_hash: str) -> bool:
        """Checks if block hash is valid"""
        return (block_hash.startswith('0' * self.difficulty) and (block_hash == block.compute_hash()))

    def add_new_transaction(self, transaction: Dict) -> None:
        """Adds a new transaction to the list of unconfirmed transactions"""
        self.unconfirmed_transactions.append(transaction)

    def mine(self) -> int:
        """Mines new blocks and adds them to the chain"""
        if not self.unconfirmed_transactions:
            return -1

        last_block = self.last_block

        new_block = Block(
            index=last_block.index + 1,
            transactions=self.unconfirmed_transactions,
            timestamp=time(),
            previous_hash=last_block.hash
        )

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)
        self.unconfirmed_transactions = []
        return new_block.index

    def is_chain_valid(self) -> bool:
        """Validates the entire blockchain"""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True



class Wallet:
    """A wallet that can send and receive cryptocurrency"""

    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def sign_transaction(self, transaction: Dict) -> str:
        """Signs a transaction with the wallet's private key"""
        transaction_str = json.dumps(transaction, sort_keys=True)
        hash_obj = SHA256.new(transaction_str.encode('utf-8'))
        signature = pkcs1_15.new(self.private_key).sign(hash_obj)
        return binascii.hexlify(signature).decode('ascii')

    @staticmethod
    def verify_transaction(transaction: Dict, signature: str, public_key: str) -> bool:
        """Verifies a transaction signature"""
        sender_public_key = RSA.import_key(binascii.unhexlify(public_key))
        transaction_str = json.dumps(transaction, sort_keys=True)
        hash_obj = SHA256.new(transaction_str.encode('utf-8'))

        try:
            pkcs1_15.new(sender_public_key).verify(hash_obj, binascii.unhexlify(signature))
            return True
        except (ValueError, TypeError):
            return False


class CryptocurrencyBlockchain(Blockchain):
    """Extends the basic blockchain with cryptocurrency features"""

    def __init__(self):
        super().__init__()
        self.wallets = {}  # Maps public keys to balances

    def create_transaction(self, sender_wallet: Wallet, recipient_public_key: str, amount: float) -> bool:
        """Creates a new transaction"""
        if not self.wallets.get(sender_wallet.public_key.export_key().decode('ascii'), 0) >= amount:
            return False

        transaction = {
            'sender': sender_wallet.public_key.export_key().decode('ascii'),
            'recipient': recipient_public_key,
            'amount': amount,
            'timestamp': time()
        }

        signature = sender_wallet.sign_transaction(transaction)
        self.add_new_transaction({**transaction, 'signature': signature})
        return True

    def add_block(self, block: Block, proof: str) -> bool:
        """Overrides parent method to update wallet balances"""
        if not super().add_block(block, proof):
            return False

        # Update wallet balances
        for transaction in block.transactions:
            sender = transaction['sender']
            recipient = transaction['recipient']
            amount = transaction['amount']

            if sender in self.wallets:
                self.wallets[sender] -= amount
            if recipient in self.wallets:
                self.wallets[recipient] += amount
            else:
                self.wallets[recipient] = amount

        return True

    def validate_transaction(self, transaction: Dict) -> bool:
        """Validates a transaction"""
        required_fields = ['sender', 'recipient', 'amount', 'timestamp', 'signature']
        if not all(field in transaction for field in required_fields):
            return False

        # Verify signature
        signature = transaction.pop('signature')
        if not Wallet.verify_transaction(transaction, signature, transaction['sender']):
            return False

        # Check sender balance
        sender_balance = self.wallets.get(transaction['sender'], 0)
        if sender_balance < transaction['amount']:
            return False

        return True


# Example usage with cryptocurrency
if __name__ == "__main__":
    # Create wallets
    alice = Wallet()
    bob = Wallet()
    charlie = Wallet()

    # Initialize blockchain
    crypto_chain = CryptocurrencyBlockchain()

    # Add initial funds to Alice
    alice_public = alice.public_key.export_key().decode('ascii')
    crypto_chain.wallets[alice_public] = 1000

    # Alice sends money to Bob
    bob_public = bob.public_key.export_key().decode('ascii')
    crypto_chain.create_transaction(alice, bob_public, 50)

    # Bob sends money to Charlie
    charlie_public = charlie.public_key.export_key().decode('ascii')
    crypto_chain.create_transaction(bob, charlie_public, 25)

    # Mine a block
    print("Mining block with transactions...")
    crypto_chain.mine()

    # Print balances
    print("\nBalances:")
    print(f"Alice: {crypto_chain.wallets.get(alice_public, 0)}")
    print(f"Bob: {crypto_chain.wallets.get(bob_public, 0)}")
    print(f"Charlie: {crypto_chain.wallets.get(charlie_public, 0)}")