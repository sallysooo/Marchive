# src/build_index.py
# 역할: chunks.jsonl(Q&A)와 snippets.jsonl(code snippet)을 불러 VectorDB(Chroma) 인덱스 생성
# 이후 retriever = Chroma(persist_directory=...).as_retriever(filter={"version":"2.4"})처럼 버전 필터 걸기!

import os
import json
from pathlib import Path
from typing import List
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
# (HuggingFace 예: from langchain_community.embeddings import HuggingFaceEmbeddings)

CHUNKS_PATH = Path("data/processed/chunks.jsonl")
SNIPPETS_PATH = Path("data/processed/snippets.jsonl")
INDEX_DIR = Path("indexes/chroma")             # Q&A 인덱스
SNIPPET_INDEX_DIR = Path("indexes/snippets")   # 스니펫 인덱스

# 임베딩: OpenAI 또는 HuggingFace 중 선택
def get_embeddings():
    use_hf = False  # 필요하면 True로 전환
    if use_hf:
        from langchain_community.embeddings import HuggingFaceEmbeddings
        return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    else:
        # OPENAI_API_KEY 필요 (openai 임베딩은 과금이 장난 아니라고 하니 주의하자..)
        return OpenAIEmbeddings(model="text-embedding-3-small")

def load_jsonl_as_documents(path: Path, content_key="content") -> List[Document]:
    docs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            content = obj.get(content_key)
            if not content:
                # 스니펫 파일은 content_key가 'code'일 수 있음
                continue
            meta = {k: v for k, v in obj.items() if k != content_key}
            docs.append(Document(page_content=content, metadata=meta))
    return docs

def build_main_index():
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    emb = get_embeddings()
    docs = load_jsonl_as_documents(CHUNKS_PATH, content_key="content")
    db = Chroma.from_documents(
        docs, emb,
        collection_name="torch_docs",
        persist_directory=str(INDEX_DIR)
    )
    print(f"Built main index: {len(docs)} docs → {INDEX_DIR}")

def build_snippet_index():
    SNIPPET_INDEX_DIR.mkdir(parents=True, exist_ok=True)
    emb = get_embeddings()
    docs = load_jsonl_as_documents(SNIPPETS_PATH, content_key="code")
    db = Chroma.from_documents(
        docs, emb,
        collection_name="torch_snippets",
        persist_directory=str(SNIPPET_INDEX_DIR)
    )
    print(f"Built snippet index: {len(docs)} docs → {SNIPPET_INDEX_DIR}")

if __name__ == "__main__":
    build_main_index()
    build_snippet_index()
