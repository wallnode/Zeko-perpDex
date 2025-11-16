# ZEKO Perp DEX — Ready Repo

Perp DEX zkApp for ZEKO L2 (o1js). Features:
- IM/MM separation, insurance fund
- Funding via EMA(mark–index)
- OPEN / CLOSE / LIQUIDATE / INCREASE / REDUCE
- Slippage guard + user-signed fees (bps, ±)
- Batch-ready core (kept simple in tests)

## Run tests (LocalBlockchain)
```bash
pnpm install
pnpm test
```

## Notes
- Admin is initially the zkApp itself (adminPublicKey = zkApp address). Admin signatures use the `zkappKey` private key in tests.
- Funding is disabled in tests (`K=0`) for determinism; only fees affect balances.
- To try funding, set non-zero `fundingKBpsPer1x` / `fundingCapBps` and add scenarios.
