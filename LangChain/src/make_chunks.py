# src/make_chunks.py
# 역할: Load Markdown -> Chunking -> chunks.jsonl 생성 + 코드 블록만 모아 snippets.jsonl 생성

import os
import re
import json
from pathlib import Path
from typing import List, Tuple
from langchain_community.document_loaders import TextLoader, DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter

MD_DIR = Path("data/md")
OUT_DIR = Path("data/processed")
CHUNKS_PATH = OUT_DIR / "chunks.jsonl"
SNIPPETS_PATH = OUT_DIR / "snippets.jsonl"

# 간단한 fenced code block 추출용 regex (```python ... ```) => 이건 추후 수정하쟈
CODE_BLOCK_RE = re.compile(
    r"```(?P<lang>[a-zA-Z0-9_\-+]*)\s*\n(?P<code>[\s\S]*?)```",
    re.MULTILINE
)

def extract_code_blocks(md_text: str) -> List[Tuple[str, str]]:
    """
    return list of (language, code)
    """
    results = []
    for m in CODE_BLOCK_RE.finditer(md_text):
        lang = (m.group("lang") or "").strip().lower()
        code = m.group("code").strip()
        if code:
            results.append((lang, code))
    return results

def infer_meta_from_md_source(source_path: str):
    """
    source_path 예: data/md/stable/2.4/autograd/how_autograd_works.md
    """
    p = Path(source_path)
    parts = p.parts
    try:
        idx = parts.index("md")
        release = parts[idx+1] if len(parts) > idx+1 else "unknown"
        version = parts[idx+2] if len(parts) > idx+2 else "unknown"
        section_path = list(parts[idx+3:-1])
    except ValueError:
        release, version, section_path = "unknown", "unknown", []
    return release, version, section_path

def make_all():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    # 1) Markdown 로딩
    loader = DirectoryLoader(
        str(MD_DIR),
        glob="**/*.md",
        loader_cls=TextLoader,
        loader_kwargs={"encoding": "utf-8"},
        show_progress=True,
    )
    docs = loader.load()

    # 2) 코드 스니펫 추출 및 저장
    # Markdown 본문에서 fenced code block을 찾아 snippets.jsonl 생성
    with open(SNIPPETS_PATH, "w", encoding="utf-8") as sn_fp:
        for d in docs:
            rel, ver, sect = infer_meta_from_md_source(d.metadata.get("source", ""))
            code_blocks = extract_code_blocks(d.page_content)
            for lang, code in code_blocks:
                record = {
                    "language": lang or "text",
                    "code": code,
                    "version": ver,
                    "release": rel,
                    "section_path": sect,
                    "source_md": d.metadata.get("source", "")
                }
                sn_fp.write(json.dumps(record, ensure_ascii=False) + "\n")

    # 3) 청킹 (기본 분할; 필요 시 chunk_size/overlap 조절)
    # RecursiveCharacterTextSplitter로 문서 청킹 -> chunks.jsonl 생성
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=900,
        chunk_overlap=120,
        separators=["\n## ", "\n### ", "\n", " ", ""],  # 헤더 우선 분할 힌트
    )
    chunks = splitter.split_documents(docs)

    # 4) 청크 저장
    # 버전/섹션 경로는 파일 경로로부터 추론 (초기에는 이 정도로 일단 세팅)
    with open(CHUNKS_PATH, "w", encoding="utf-8") as ch_fp:
        for i, ch in enumerate(chunks):
            rel, ver, sect = infer_meta_from_md_source(ch.metadata.get("source", ""))
            record = {
                "chunk_id": f"chunk_{i:06d}",
                "content": ch.page_content,
                "version": ver,
                "release": rel,
                "section_path": sect,
                "source_md": ch.metadata.get("source", "")
                # 필요하면 여기서 URL 프래그먼트까지 계산해서 넣을 수 있음
            }
            ch_fp.write(json.dumps(record, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    make_all()
    print("make_chunks done -> data/processed/chunks.jsonl & snippets.jsonl")

