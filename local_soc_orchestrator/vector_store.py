import chromadb
from chromadb.utils import embedding_functions

class LocalThreatKnowledgeBase:
    def __init__(self, persist_directory="./local_chroma_db"):
        # Initialize an embedded persistent client (writes directly to local disk)
        self.client = chromadb.PersistentClient(path=persist_directory)
        
        # Use a lightweight local sentence-transformer embedding function 
        # (Runs entirely on CPU/GPU locally without external API calls)
        self.embedding_fn = embedding_functions.DefaultEmbeddingFunction()
        
        self.collection = self.client.get_or_create_collection(
            name="security_threat_intel",
            embedding_function=self.embedding_fn
        )

    def add_threat_report(self, report_id: str, text_content: str, metadata: dict):
        """Ingests a historical threat report or playbook into the local vector database."""
        self.collection.add(
            ids=[report_id],
            documents=[text_content],
            metadatas=[metadata]
        )
        print(f"[+] Indexed threat report {report_id} into local vector store.")

    def query_similar_threats(self, query_text: str, n_results=2):
        """Performs semantic similarity search over your local security knowledge base."""
        results = self.collection.query(
            query_texts=[query_text],
            n_results=n_results
        )
        return results