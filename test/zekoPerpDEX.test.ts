
// file: test/zekoPerpDEX.test.ts
import {
  Mina, PrivateKey, PublicKey, Field, UInt64, Signature, Poseidon, MerkleMap, AccountUpdate
} from 'o1js';
import {
  ZekoPerpDEX, Update, Position, OracleSnapshot,
  computeUserKeyOffchain, posHashOffchain,
} from '../src/ZekoPerpDEX';

const SCALE = Field(1_000_000);

describe('ZekoPerpDEX – open → increase → reduce → close', () => {
  const Local = Mina.LocalBlockchain({ proofsEnabled: false });
  Mina.setActiveInstance(Local);

  const feePayer = Local.testAccounts[0];
  const userSK = PrivateKey.random();
  const userPK = userSK.toPublicKey();

  const zkappKey = PrivateKey.random();
  const zkappAddr = zkappKey.toPublicKey();

  const oracleSK = PrivateKey.random();
  const oraclePK = oracleSK.toPublicKey();

  const assetId = Field(1);
  const px = (n: number) => UInt64.from(BigInt(Math.floor(n * 1e6)));

  // local mirrors
  const posMap = new MerkleMap();
  const tsMap = new MerkleMap();
  const emaMap = new MerkleMap();
  const tsKey = Poseidon.hash([assetId]);
  const emaKey = Poseidon.hash([assetId]);

  const signOracle = (price: UInt64, ts: number): OracleSnapshot => ({
    markPrice: price,
    indexPrice: price,
    assetId,
    timestamp: UInt64.from(ts),
    signature: Signature.create(oracleSK, [
      price.value, price.value, assetId, Field(ts),
    ]),
  } as any);

  it('happy path', () => {
    // deploy & set params
    const zkapp = new ZekoPerpDEX(zkappAddr);
    const deployTx = Mina.transaction({ sender: feePayer.publicKey }, () => {
      AccountUpdate.fundNewAccount(feePayer.publicKey);
      zkapp.deploy({ zkappKey });
      // Admin is zkApp itself after init, so admin signatures use zkappKey
      zkapp.setOraclePublicKey(
        oraclePK,
        Signature.create(zkappKey, [Field(9002), ...oraclePK.toFields()])
      );
      // K=0, cap=0 → funding 0; max fee cap = 100 bps
      zkapp.setParams(
        Field(5), Field(500), Field(300),
        Field(0), Field(0), Field(1), Field(24),
        Field(100),
        Signature.create(zkappKey, [
          Field(9001),
          Field(5), Field(500), Field(300),
          Field(0), Field(0), Field(1), Field(24),
          Field(100),
        ])
      );
      zkapp.depositInsurance(UInt64.from(1_000_000_000n));
    });
    deployTx.prove(); deployTx.sign([feePayer.privateKey, zkappKey]).send();

    // seed EMA leaf = 0
    {
      const wit = emaMap.getWitness(emaKey);
      const tx = Mina.transaction({ sender: feePayer.publicKey }, () => {
        zkapp.adminSetFundingEmaLeaf(
          assetId, UInt64.from(0), Field(1), wit,
          Signature.create(zkappKey, [Field(9005), assetId, Field(0), Field(1)])
        );
      });
      tx.prove(); tx.sign([feePayer.privateKey, zkappKey]).send();
      emaMap.set(emaKey, Poseidon.hash([Field(0), Field(1)]));
    }

    const userKey = computeUserKeyOffchain(userPK, assetId);
    const price100 = px(100);

    // ---------- OPEN LONG ----------
    const pos0 = new Position({
      owner: userPK,
      collateral: UInt64.from(5_000_000n), // $5
      size: UInt64.from(1_000_000n),       // 1
      direction: Field(1),
      entryPrice: price100,
      nonce: UInt64.from(1),
    });

    const o1 = signOracle(price100, 3600);
    const updOpen = new Update({
      action: Field(0),
      userKey,
      position: pos0,
      deltaSize: UInt64.from(0),
      feeBpsAbs: Field(0),
      feeSign: Field(1),
      limitPrice: px(105),   // max acceptable
      limitIsMin: Field(0),
      preHash: Field(0),
      witness: posMap.getWitness(userKey),
      userSig: Signature.create(userSK, [
        Field(1111), userKey,
        pos0.collateral.value, pos0.size.value,
        pos0.direction, pos0.entryPrice.value, pos0.nonce.value,
        Field(0), Field(0), Field(1),
        px(105).value, Field(0),
        o1.markPrice.value, o1.assetId, o1.timestamp.value,
      ]),
    });

    const tx1 = Mina.transaction({ sender: feePayer.publicKey }, () => {
      zkapp.openPosition(
        updOpen, o1,
        UInt64.from(tsMap.get(tsKey)), tsMap.getWitness(tsKey),
        UInt64.from(0), Field(1), emaMap.getWitness(emaKey)
      );
    });
    tx1.prove(); tx1.sign([feePayer.privateKey]).send();
    // mirrors
    posMap.set(userKey, posHashOffchain(pos0));
    tsMap.set(tsKey, o1.timestamp.value);

    // ---------- INCREASE +0.5 ----------
    const d1 = UInt64.from(500_000n);
    const o2 = signOracle(price100, 7200);
    const updInc = new Update({
      action: Field(4),
      userKey,
      position: pos0,
      deltaSize: d1,
      feeBpsAbs: Field(0),
      feeSign: Field(1),
      limitPrice: px(101), // max
      limitIsMin: Field(0),
      preHash: posHashOffchain(pos0),
      witness: posMap.getWitness(userKey),
      userSig: Signature.create(userSK, [
        Field(4444), userKey,
        pos0.collateral.value, pos0.size.value,
        pos0.direction, pos0.entryPrice.value, pos0.nonce.value,
        d1.value, Field(0), Field(1),
        px(101).value, Field(0),
        o2.markPrice.value, o2.assetId, o2.timestamp.value,
      ]),
    });

    const tx2 = Mina.transaction({ sender: feePayer.publicKey }, () => {
      zkapp.increasePosition(
        updInc, o2,
        UInt64.from(tsMap.get(tsKey)), tsMap.getWitness(tsKey),
        UInt64.from(0), Field(1), emaMap.getWitness(emaKey)
      );
    });
    tx2.prove(); tx2.sign([feePayer.privateKey]).send();

    // compute VWAP entry after increase
    const size1 = UInt64.from(pos0.size.value.add(d1.value));
    const notionalOld = pos0.size.value.mul(pos0.entryPrice.value).div(SCALE);
    const notionalAdd = d1.value.mul(price100.value).div(SCALE);
    const entry1 = UInt64.from(notionalOld.add(notionalAdd).mul(SCALE).div(size1.value));
    const pos1 = new Position({
      owner: pos0.owner,
      collateral: pos0.collateral,
      size: size1,
      direction: pos0.direction,
      entryPrice: entry1,
      nonce: pos0.nonce,
    });
    posMap.set(userKey, posHashOffchain(pos1));
    tsMap.set(tsKey, o2.timestamp.value);

    // ---------- REDUCE half (fee 10 bps) ----------
    const d2 = UInt64.from(size1.value.div(Field(2)));
    const o3 = signOracle(price100, 10_800);
    const feeBps = Field(10); // 10 bps
    const updRed = new Update({
      action: Field(5),
      userKey,
      position: pos1,
      deltaSize: d2,
      feeBpsAbs: feeBps,
      feeSign: Field(1),         // pay
      limitPrice: px(99),        // min price
      limitIsMin: Field(1),
      preHash: posMap.get(userKey),
      witness: posMap.getWitness(userKey),
      userSig: Signature.create(userSK, [
        Field(5555), userKey,
        pos1.collateral.value, pos1.size.value,
        pos1.direction, pos1.entryPrice.value, pos1.nonce.value,
        d2.value, feeBps, Field(1),
        px(99).value, Field(1),
        o3.markPrice.value, o3.assetId, o3.timestamp.value,
      ]),
    });

    const tx3 = Mina.transaction({ sender: feePayer.publicKey }, () => {
      zkapp.reducePosition(
        updRed, o3,
        UInt64.from(tsMap.get(tsKey)), tsMap.getWitness(tsKey),
        UInt64.from(0), Field(1), emaMap.getWitness(emaKey)
      );
    });
    tx3.prove(); tx3.sign([feePayer.privateKey]).send();
    // mirrors: funding=0 (K=0). PnL=0. closed notional = d2*100.
    const f = d2.value.mul(SCALE).div(size1.value);
    const collShare = UInt64.from(pos1.collateral.value.mul(f).div(SCALE));
    const feeAbs = UInt64.from(d2.value.mul(price100.value).div(SCALE).mul(feeBps).div(Field(10_000)));
    const closedFinal = UInt64.from(
      collShare.value.sub(feeAbs.value)
    );
    const remainColl = UInt64.from(pos1.collateral.value.sub(collShare.value));
    const coll2 = UInt64.from(remainColl.value.add(closedFinal.value));
    const size2 = UInt64.from(size1.value.sub(d2.value));
    const pos2 = new Position({
      owner: pos1.owner,
      collateral: coll2,
      size: size2,
      direction: pos1.direction,
      entryPrice: pos1.entryPrice,
      nonce: pos1.nonce,
    });
    posMap.set(userKey, posHashOffchain(pos2));
    tsMap.set(tsKey, o3.timestamp.value);

    // ---------- CLOSE rest (fee 10 bps) ----------
    const o4 = signOracle(price100, 14_400);
    const updClose = new Update({
      action: Field(1),
      userKey,
      position: pos2,
      deltaSize: UInt64.from(0),
      feeBpsAbs: feeBps,
      feeSign: Field(1),
      limitPrice: px(98),
      limitIsMin: Field(1),
      preHash: posMap.get(userKey),
      witness: posMap.getWitness(userKey),
      userSig: Signature.create(userSK, [
        Field(2222), userKey,
        pos2.collateral.value, pos2.size.value,
        pos2.direction, pos2.entryPrice.value, pos2.nonce.value,
        Field(0), feeBps, Field(1),
        px(98).value, Field(1),
        o4.markPrice.value, o4.assetId, o4.timestamp.value,
      ]),
    });

    const tx4 = Mina.transaction({ sender: feePayer.publicKey }, () => {
      zkapp.closePosition(
        updClose, o4,
        UInt64.from(tsMap.get(tsKey)), tsMap.getWitness(tsKey),
        UInt64.from(0), Field(1), emaMap.getWitness(emaKey)
      );
    });
    tx4.prove(); tx4.sign([feePayer.privateKey]).send();
  });
});
