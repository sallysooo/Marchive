```
TorchDocs-RAG/
├─ data/
│  ├─ raw/                 # HTML 원본 (그대로 저장)
│  ├─ md/                  # HTML → Markdown/Text 변환본
│  │  └─ stable/2.4/...    # 버전별/섹션별 파일 구조
│  └─ processed/
│     ├─ documents.jsonl   # 문서 메타 
│     ├─ chunks.jsonl      # 청킹 결과 (검색 단위)
│     ├─ snippets.jsonl    # code snippet만 모은 파일
│     └─ embeddings.npy    # 임베딩 결과
├─ indexes/
│  ├─ chroma/              # Q&A index (vectorDB)
│  └─ snippets_chroma/     # snippet index (vectorDB)
├─ src/
│  ├─ crawl.py             # (optional) URL 리스트 받아 HTML 저장
│  ├─ transform.py         # HTML→Markdown/Text, 잡음 제거, 메타 추출
│  ├─ make_chunks.py       # 문서→청킹(JSONL 생성), 코드블록 추출
│  ├─ build_index.py       # chunks/snippets → vectorDB 구축
│  ├─ rag_qa.py            # Q&A mode chain (w/ version filter)
│  └─ rag_snippet.py       # snippet mode chain
├─ app/
│  └─ ui.py                # Streamlit/Gradio UI (모드 토글, 버전 선택, 인용 표시)
├─ configs/
│  └─ default.yaml         # 경로/파라미터(chuck_size, k값 등)
├─ .env.example            # OPENAI_API_KEY=...
├─ requirements.txt
└─ README.md
```

- crawl.py : URL 목록을 읽어 HTML 저장(rate limit, 중복 방지)
- transform.py : HTML에서 본문/코드만 뽑아 Markdown/Text 저장, 파일 경로로 버전/섹션 메타 부여
- make_chunks.py : 문서 → 청킹(chunk_size, overlap) / 스니펫 추출(e.g.```python 블록)
- build_index.py : chunks.jsonl, snippets.jsonl을 읽어 임베딩 + vectorDB 만들기
- rag_qa.py : Q&A retriever + LLM 체인 (인용/버전 필터 지원)
- rag_snippet.py : snippet retriever + LLM 체인 (최소 실행 예제로 재구성)
