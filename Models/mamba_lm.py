import os
import math
import random
from dataclasses import dataclass
from typing import List, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

# Mamba block from mamba-ssm
from mamba_ssm.modules.mamba_simple import Mamba

class CharTokenizer:
    # Build vocabulary from a given text corpus
    # string <-> list of integer ids
    def __init__(self, text):
        chars = sorted(list(set(text)))
        self.stoi = {ch: i for i, ch in enumerate(chars)}
        self.itos = {i : ch for ch, i in self.stoi.items()}
    
    @property
    def vocab_size(self):
        return len(self.stoi)
    
    def encode(self, s):
        return [self.stoi[ch] for ch in s]
    
    def decode(self, ids):
        return "".join(self.itos[i] for i in ids)
    

# Dataset for next-token prediction
class NextTokenDataset(Dataset):
    """
    Given a long token id sequence, returns (x, y) where:
    x : length = window_size
    y : length = window_size (x shifted by 1 as next-token targets)
    
    Example:
        ids: [10, 20, 30, 40, 50], window_size = 3
        x : [10, 20, 30]
        y : [20, 30, 40]
    """
    def __init__(self, ids, window_size):
        self.ids = torch.tensor(ids, dtype=torch.long)
        self.window_size = window_size

    def __len__(self):
        # number of possible windows
        return max(0, len(self.ids) - self.window_size - 1)
    
    def __getitem__(self, idx):
        x = self.ids[idx : idx + self.window_size]
        y = self.ids[idx + 1 : idx + 1 + self.window_size]
        return x, y
    

# Tiny mamba LM model
class TinyMambaLM(nn.Module):
    def __init__(self, 
                 vocab_size: int,
                 d_model: int = 256,
                 n_layers: int = 4,
                 d_state: int = 16,
                 d_conv: int = 4,
                 expand: int = 2,
                 dropout: float = 0.0,
    ):
        super().__init__()
        self.vocab_size = vocab_size
        self.d_model = d_model

        # 1) Token embedding
        self.tok_emb = nn.Embedding(vocab_size, d_model)

        # 2) Stack of Mamba Blocks (sequence mixer)
        self.layers = nn.ModuleList([
            nn.ModuleDict({
                "ln": nn.LayerNorm(d_model),
                "mamba": Mamba(
                    d_model=d_model,
                    d_state=d_state,
                    d_conv=d_conv,
                    expand=expand,
                ),
                "drop": nn.Dropout(dropout),
            })
            for _ in range(n_layers)
        ])

        # Final normalization + LM head
        self.ln_f = nn.LayerNorm(d_model)
        self.lm_head = nn.Linear(d_model,vocab_size, bias=False)

    def forward(self, idx):
        # idx: (B, L) token ids
        # returns logits: (B, L, vocab_size)
        x = self.tok_emb(idx) # (B, L, d_model)

        # Eaxh layer: pre-LN -> Mamba -> residual
        for layer in self.layers:
            h = layer["ln"](x)
            h = layer["mamba"](h)   # (B, L, d_model)
            h = layer["drop"](h)
            x = x + h               # residual connection

        x = self.ln_f(x)            # (B, L, d_model)
        logits = self.lm_head(x)    # (B, L, vocab_size)
        return logits

# Training utilities
@dataclass
class TrainConfig:
    window_size = 256
    batch_size = 32
    lr = 3e-4
    max_steps = 2000
    eval_every = 200
    device = "cuda" if torch.cuda.is_available() else "cpu"

@torch.no_grad()
def estimate_loss(model, loader, device, max_batches=50):
    model.eval()
    losses = []
    for i, (x, y) in enumerate(loader):
        if i >= max_batches:
            break
        x = x.to(device)
        y = y.to(device)

        logits = model(x)   # (B, L, V)
        loss = F.cross_entropy(logits.view(-1, logits.size(-1)), y.view(-1))
        losses.append(loss.item())
    model.train()
    return sum(losses) / max(1, len(losses))

def train_tiny_mamba(text):
    cfg = TrainConfig()

    # 1) Build Tokenizer + ids
    tokenizer = CharTokenizer(text)
    ids = tokenizer.encode(text)

    # 2) Train/val split
    split = int(0.9 * len(ids))
    train_ids = ids[:split]
    val_ids = ids[split:]

    train_ds = NextTokenDataset(train_ids, cfg.window_size)
    val_ds = NextTokenDataset(val_ids, cfg.window_size)

    train_loader = DataLoader(train_ds, batch_size=cfg.batch_size, shuffle=True, drop_last=True)
    val_loader = DataLoader(val_ds, batch_size=cfg.batch_size, shuffle=False, drop_last=True)

    # 3) Model
    model = TinyMambaLM(
        vocab_size=tokenizer.vocab_size,
        d_model=256,
        n_layers=4,
        d_state=16,
        d_conv=4,
        expand=2,
        dropout=0.1,
    ).to(cfg.device)

    # 4) Optimizer
    optim = torch.optim.AdamW(model.parameters(), lr=cfg.lr)

    # 5) Training loop
    step = 0
    while step < cfg.max_steps:
        for x, y in train_loader:
            x = x.to(cfg.device)
            y = y.to(cfg.device)

            logits = model(x)
            loss = F.cross_entropy(logits.view(-1, logits.size(-1)), y.view(-1))

            optim.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optim.step()

            step += 1

            if step % cfg.eval_every == 0:
                train_loss = loss.item()
                val_loss = estimate_loss(model, val_loader, cfg.device)
                print(f"step {step:5d} | train_loss {train_loss:.4f} | val_loss {val_loss:.4f}")

            if step >= cfg.max_steps:
                break

    # 6) Quick sampling demo
    print("\n--- Sampling demo ---")
    prompt = "hello"
    context = torch.tensor([tokenizer.encode(prompt)], dtype=torch.long).to(cfg.device)

    model.eval()
    for _ in range(200):
        logits = model(context[:, -cfg.window_size:])  # keep last window_size tokens
        next_logits = logits[:, -1, :]                # last position
        probs = F.softmax(next_logits, dim=-1)
        next_id = torch.multinomial(probs, num_samples=1)  # sample
        context = torch.cat([context, next_id], dim=1)

    out = tokenizer.decode(context[0].tolist())
    print(out)


if __name__ == "__main__":
    toy_text = (
        "mamba is a sequence model. "
        "it reads tokens from left to right and updates an internal state. "
        "this is a tiny toy language model demo.\n"
    ) * 200  # repeat to make it longer

    train_tiny_mamba(toy_text)



