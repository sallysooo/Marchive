# src/transform.py
# 역할: raw HTML -> Markdown/Text 변환 + 기본 메타데이터 추출(버전/섹션 경로/대략의 URL)

import os
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup
from markdownify import markdownify as md
from slugify import slugify
from datetime import datetime

RAW_DIR = Path("data/raw")         # 원본 HTML 위치
OUT_DIR = Path("data/md")          # 변환본 저장 위치
DOC_META_PATH = Path("data/processed/documents.jsonl")  # (optional) 문서 메타 기록

# 불필요한 요소 제거 규칙 (사이트 구조에 따라 조정)
REMOVE_SELECTORS = [
    "nav", "header", "footer", ".sphinxsidebar", ".bd-sidebar", ".toc", ".breadcrumbs"
]

# 1. 크롤러가 저장해둔 data/raw/...html을 읽어 Markdown으로 변환
def html_to_markdown(html_text: str) -> str:
    # 1) 잡음 제거를 위해 soup 사용
    soup = BeautifulSoup(html_text, "html.parser")
    for sel in REMOVE_SELECTORS:
        for tag in soup.select(sel):
            tag.decompose()
    # 2) 앵커 id 보존: heading에 id 없으면 생성
    for h in soup.find_all(re.compile("^h[1-6]$")):
        if not h.get("id"):
            h["id"] = slugify(h.get_text(" ", strip=True))[:80]
    # 3) 정제된 HTML → Markdown
    markdown = md(str(soup), heading_style="ATX")
    # 여분 공백/개행 정리
    markdown = re.sub(r"\n{3,}", "\n\n", markdown).strip()
    return markdown


# 2. 디렉토리 경로로부터 release/version/section_path를 추론해 메타에 포함
def infer_meta_from_path(src_path: Path):
    """
    예: data/raw/stable/2.4/autograd/how_autograd_works.html
    → release=stable, version=2.4, section_path=['autograd','how_autograd_works']
    """
    parts = src_path.parts
    # (..., 'raw', 'stable', '2.4', 'autograd', 'how_autograd_works.html')
    try:
        idx = parts.index("raw")
        release = parts[idx+1] if len(parts) > idx+1 else "unknown"
        version = parts[idx+2] if len(parts) > idx+2 else "unknown"
        section_path = list(parts[idx+3:-1])  # 파일명 제외
    except ValueError:
        release, version, section_path = "unknown", "unknown", []
    return {
        "release": release,
        "version": version,
        "section_path": section_path
    }

def transform_all():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    DOC_META_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(DOC_META_PATH, "a", encoding="utf-8") as meta_fp:
        for html_path in RAW_DIR.rglob("*.html"):
            rel = html_path.relative_to(RAW_DIR)
            # 출력 경로(md)는 raw의 하위 구조를 그대로 따르되 확장자 md로
            out_path = OUT_DIR / rel.with_suffix(".md")
            out_path.parent.mkdir(parents=True, exist_ok=True)

            html_text = html_path.read_text(encoding="utf-8", errors="ignore")
            markdown = html_to_markdown(html_text)
            out_path.write_text(markdown, encoding="utf-8")

            meta = infer_meta_from_path(html_path)
            # URL이 있다면 함께 저장 (크롤러가 저장 시 메타로 넣어둘 수도 있음)
            doc_record = {
                "doc_id": str(rel.with_suffix("")),
                "raw_path": str(html_path),
                "md_path": str(out_path),
                "release": meta["release"],
                "version": meta["version"],
                "section_path": meta["section_path"],
                "fetched_at": datetime.utcnow().isoformat(),
            }
            meta_fp.write(json.dumps(doc_record, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    transform_all()
    print("transform done -> data/md & data/processed/documents.jsonl")
