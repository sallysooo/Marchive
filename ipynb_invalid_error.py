# Script file for 'Invalid notebook' for .ipynb file in github
# Clean a Jupyter notebook by removing widget metadata and widget outputs

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent # Desktop
print(BASE_DIR)
src = Path(BASE_DIR / f"yourfile.ipynb")
dst = Path(BASE_DIR / f"yourfile_cleaned.ipynb")

# Load notebook JSON
with src.open("r", encoding="utf-8") as f:
    nb = json.load(f)

changes = {
    "removed_metadata_widgets": False,
    "removed_cell_widget_outputs": 0,
    "cells_processed": 0,
    "removed_cell_metadata_widgets": 0
}

# 1) Remove top-level metadata.widgets (GitHub error mentions this)
meta = nb.get("metadata", {})
if "widgets" in meta:
    changes["removed_metadata_widgets"] = True
    meta.pop("widgets", None)
    nb["metadata"] = meta

# 2) Iterate cells and strip widget outputs and widget-related metadata
for cell in nb.get("cells", []):
    changes["cells_processed"] += 1
    # Remove widget-related metadata in cell
    cm = cell.get("metadata", {})
    # Common keys that can appear
    removed_any = False
    for k in list(cm.keys()):
        if "widget" in k.lower() or k in {"outputExpanded"}:
            cm.pop(k, None)
            removed_any = True
    if removed_any:
        changes["removed_cell_metadata_widgets"] += 1
    cell["metadata"] = cm

    # Remove outputs that refer to widgets (vnd.jupyter.widget-view/state)
    if "outputs" in cell:
        new_outputs = []
        for out in cell["outputs"]:
            # Examine 'data' dict for MIME types
            data = out.get("data", {})
            if isinstance(data, dict) and any(
                mt in data for mt in (
                    "application/vnd.jupyter.widget-view+json",
                    "application/vnd.jupyter.widget-state+json"
                )
            ):
                changes["removed_cell_widget_outputs"] += 1
                continue  # skip this output
            new_outputs.append(out)
        cell["outputs"] = new_outputs

# 3) Ensure kernelspec / language_info exist (helps GitHub render)
nb.setdefault("metadata", {})
ks = nb["metadata"].get("kernelspec")
if not ks:
    nb["metadata"]["kernelspec"] = {
        "name": "python3",
        "display_name": "Python 3",
        "language": "python"
    }
li = nb["metadata"].get("language_info")
if not li:
    nb["metadata"]["language_info"] = {
        "name": "python",
        "version": "3.11"
    }

# 4) Save cleaned notebook
with dst.open("w", encoding="utf-8") as f:
    json.dump(nb, f, ensure_ascii=False, indent=1)

print("Cleaned notebook saved:", str(dst))
print("Changes summary:", changes)
