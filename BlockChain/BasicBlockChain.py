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


# Example usage
if __name__ == "__main__":
    blockchain = Blockchain()

    # Add some transactions
    blockchain.add_new_transaction({"sender": "Alice", "recipient": "Bob", "amount": 5})
    blockchain.add_new_transaction({"sender": "Bob", "recipient": "Charlie", "amount": 3})

    # Mine a new block
    print("Mining block 1...")
    blockchain.mine()

    # Add more transactions
    blockchain.add_new_transaction({"sender": "Charlie", "recipient": "Alice", "amount": 2})
    blockchain.add_new_transaction({"sender": "Dave", "recipient": "Eve", "amount": 10})

    # Mine another block
    print("Mining block 2...")
    blockchain.mine()

    # Print the blockchain
    print("\nBlockchain:")
    for block in blockchain.chain:
        print(f"Block {block.index}:")
        print(f"  Hash: {block.hash}")
        print(f"  Previous Hash: {block.previous_hash}")
        print(f"  Transactions: {block.transactions}")
        print(f"  Nonce: {block.nonce}\n")

    # Validate the chain
    print(f"Is blockchain valid? {blockchain.is_chain_valid()}")