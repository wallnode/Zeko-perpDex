
// file: src/ZekoPerpDEX.ts
import {
  SmartContract,
  state, State,
  method,
  Field,
  PublicKey,
  Signature,
  Struct,
  MerkleMap,
  MerkleMapWitness,
  UInt64,
  Provable,
  Poseidon,
  AccountUpdate,
} from 'o1js';

/* ---------------------- Math helpers ---------------------- */

const SCALE_NUM = 1_000_000; // 1e6 price scale
const SCALE = Field(SCALE_NUM);
const BPS_DEN = Field(10_000);
const SECONDS_PER_HOUR = Field(3600);

function fpMulU64(a: UInt64, b: UInt64): UInt64 {
  const num = a.value.mul(b.value);
  const q = num.div(SCALE);
  return UInt64.from(q);
}
function fpDivU64(numeratorNotional: UInt64, denomSize: UInt64): UInt64 {
  const num = numeratorNotional.value.mul(SCALE);
  const q = num.div(denomSize.value);
  return UInt64.from(q);
}
function bpsMulU64(amount: UInt64, bps: Field): UInt64 {
  const num = amount.value.mul(bps);
  const q = num.div(BPS_DEN);
  return UInt64.from(q);
}
function u64AddChecked(a: UInt64, b: UInt64): UInt64 {
  return UInt64.from(a.value.add(b.value));
}
function u64SubSaturating(a: UInt64, b: UInt64): UInt64 {
  const lt = a.lessThan(b);
  const diffField = a.value.sub(b.value);
  const chosen = Provable.if(lt, Field(0), diffField);
  return UInt64.from(chosen);
}
function mulU64ByRatio(a: UInt64, num: UInt64, den: UInt64): UInt64 {
  const q = a.value.mul(num.value).div(den.value);
  return UInt64.from(q);
}

/* ---------------------- Keys/helpers (exported for tests) ---------------------- */

export function computeUserKeyOffchain(owner: PublicKey, assetId: Field): Field {
  const f = owner.toFields();
  return Poseidon.hash([f[0], f[1], assetId]);
}
function computeAssetKey(assetId: Field): Field {
  return Poseidon.hash([assetId]);
}
function packFundingEmaLeaf(abs: Field, sign: Field): Field {
  return Poseidon.hash([abs, sign]);
}

/* ---------------------- Data Types ---------------------- */

export class Position extends Struct({
  owner: PublicKey,
  collateral: UInt64,
  size: UInt64,
  direction: Field,    // ±1
  entryPrice: UInt64,
  nonce: UInt64,
}) {
  assertInvariants() {
    this.direction.mul(this.direction).assertEquals(Field(1), 'direction must be ±1');
    this.size.value.assertGreaterThan(Field(0), 'size must be > 0');
    this.entryPrice.value.assertGreaterThan(Field(0), 'entryPrice must be > 0');
  }
}

export function posHashOffchain(p: Position): Field {
  const fields = [
    ...p.owner.toFields(),
    p.collateral.value,
    p.size.value,
    p.direction,
    p.entryPrice.value,
    p.nonce.value,
  ];
  return Poseidon.hash(fields);
}

/** Oracle snapshot: funding türetimi için mark & index. */
export class OracleSnapshot extends Struct({
  markPrice: UInt64,
  indexPrice: UInt64,
  assetId: Field,
  timestamp: UInt64,
  signature: Signature,
}) {}

/** Update: 0=open, 1=close, 2=noop, 3=liquidate, 4=increase, 5=reduce */
export class Update extends Struct({
  action: Field,
  userKey: Field,
  position: Position,        // pre-update position (for inc/reduce/close/liq) OR final leaf for open
  deltaSize: UInt64,         // used for increase/reduce; 0 otherwise
  feeBpsAbs: Field,          // ≥0
  feeSign: Field,            // ±1
  limitPrice: UInt64,        // user guard
  limitIsMin: Field,         // 1: require mark≥limit, 0: require mark≤limit
  preHash: Field,            // expected old leaf (close/inc/red/liq) or 0 for open
  witness: MerkleMapWitness,
  userSig: Signature,
}) {}

class UpdateWithOracle extends Struct({
  upd: Update,
  oracle: OracleSnapshot,
  prevOracleTs: UInt64,
  tsWitness: MerkleMapWitness,
  prevEmaAbs: UInt64,
  prevEmaSign: Field,
  emaWitness: MerkleMapWitness,
}) {}

/* ---------------------- Contract ---------------------- */

export class ZekoPerpDEX extends SmartContract {
  /* state */
  @state(Field) positionsRoot = State<Field>();
  @state(Field) oracleTsRoot = State<Field>();       // key: Poseidon(assetId) -> lastTs(Field)
  @state(Field) fundingEmaRoot = State<Field>();     // key: Poseidon(assetId) -> Poseidon(emaAbs, emaSign)
  @state(PublicKey) oraclePublicKey = State<PublicKey>();

  @state(Field) takerFeeBps = State<Field>();
  @state(Field) initialMarginBps = State<Field>();       // IM
  @state(Field) maintenanceMarginBps = State<Field>();   // MM
  @state(Field) maxFeeBpsAbs = State<Field>();           // |feeBps| cap
  @state(UInt64) insuranceFund = State<UInt64>();

  // Funding params
  @state(Field) fundingKBpsPer1x = State<Field>();   // sensitivity
  @state(Field) fundingCapBps = State<Field>();      // per-hour cap
  @state(Field) fundingAlphaNum = State<Field>();    // EMA α numerator
  @state(Field) fundingAlphaDen = State<Field>();    // EMA α denominator

  // Admin
  @state(PublicKey) adminPublicKey = State<PublicKey>();

  /* Domains */
  static OPEN_DOMAIN = Field(1111);
  static CLOSE_DOMAIN = Field(2222);
  static INCR_DOMAIN = Field(4444);
  static REDUCE_DOMAIN = Field(5555);

  init() {
    super.init();
    this.positionsRoot.set(new MerkleMap().getRoot());
    this.oracleTsRoot.set(new MerkleMap().getRoot());
    this.fundingEmaRoot.set(new MerkleMap().getRoot());

    // Bootstrap: admin = zkApp address (so tests can sign with zkappKey)
    this.adminPublicKey.set(this.address);

    // Placeholder; will be set by admin in tests
    this.oraclePublicKey.set(this.address);

    this.takerFeeBps.set(Field(5));             // 0.05%
    this.initialMarginBps.set(Field(500));      // 5% IM
    this.maintenanceMarginBps.set(Field(300));  // 3% MM
    this.maxFeeBpsAbs.set(Field(50));           // 0.50% cap (example)
    this.insuranceFund.set(UInt64.from(0));

    // Funding defaults: K = 500 bps per 1x spread, cap = 100 bps/h, α=1/24
    this.fundingKBpsPer1x.set(Field(500));
    this.fundingCapBps.set(Field(100));
    this.fundingAlphaNum.set(Field(1));
    this.fundingAlphaDen.set(Field(24));
  }

  /* ---------------------- Admin ---------------------- */

  private verifyAdmin(sig: Signature, fields: Field[]) {
    const admin = this.adminPublicKey.getAndAssertEquals();
    sig.verify(admin, fields).assertTrue('admin signature invalid');
  }

  @method setParams(
    takerFeeBps: Field,
    initialMarginBps: Field,
    maintenanceMarginBps: Field,
    fundingKBpsPer1x: Field,
    fundingCapBps: Field,
    fundingAlphaNum: Field,
    fundingAlphaDen: Field,
    maxFeeBpsAbs: Field,
    adminSig: Signature
  ) {
    const msg: Field[] = [
      Field(9001),
      takerFeeBps, initialMarginBps, maintenanceMarginBps,
      fundingKBpsPer1x, fundingCapBps, fundingAlphaNum, fundingAlphaDen,
      maxFeeBpsAbs,
    ];
    this.verifyAdmin(adminSig, msg);
    this.takerFeeBps.set(takerFeeBps);
    this.initialMarginBps.set(initialMarginBps);
    this.maintenanceMarginBps.set(maintenanceMarginBps);
    this.fundingKBpsPer1x.set(fundingKBpsPer1x);
    this.fundingCapBps.set(fundingCapBps);
    this.fundingAlphaNum.set(fundingAlphaNum);
    this.fundingAlphaDen.set(fundingAlphaDen);
    this.maxFeeBpsAbs.set(maxFeeBpsAbs);
  }

  @method setOraclePublicKey(newPk: PublicKey, adminSig: Signature) {
    const msg: Field[] = [Field(9002), ...newPk.toFields()];
    this.verifyAdmin(adminSig, msg);
    this.oraclePublicKey.set(newPk);
  }

  @method setAdmin(newPk: PublicKey, adminSig: Signature) {
    const msg: Field[] = [Field(9003), ...newPk.toFields()];
    this.verifyAdmin(adminSig, msg);
    this.adminPublicKey.set(newPk);
  }

  @method depositInsurance(amount: UInt64) {
    const cur = this.insuranceFund.getAndAssertEquals();
    this.insuranceFund.set(u64AddChecked(cur, amount));
  }

  @method withdrawInsurance(amount: UInt64, adminSig: Signature) {
    const msg: Field[] = [Field(9004), amount.value];
    this.verifyAdmin(adminSig, msg);
    const cur = this.insuranceFund.getAndAssertEquals();
    cur.lessThan(amount).assertFalse('insufficient insurance fund');
    this.insuranceFund.set(u64SubSaturating(cur, amount));
  }

  /** Admin: fundingEmaRoot’a belirli asset leaf’ini set etmek için (ilk seed). */
  @method adminSetFundingEmaLeaf(
    assetId: Field,
    abs: UInt64,
    sign: Field,
    witness: MerkleMapWitness,
    adminSig: Signature
  ) {
    const msg: Field[] = [Field(9005), assetId, abs.value, sign];
    this.verifyAdmin(adminSig, msg);

    const curr = this.fundingEmaRoot.getAndAssertEquals();
    const key = computeAssetKey(assetId);
    const [root0, witKey] = witness.computeRootAndKey(Field(0));
    root0.assertEquals(curr, 'EMA seed: root mismatch');
    witKey.assertEquals(key, 'EMA seed: key mismatch');

    const newLeaf = packFundingEmaLeaf(abs.value, sign);
    const newRoot = witness.computeRoot(newLeaf);
    this.fundingEmaRoot.set(newRoot);
  }

  /* ---------------------- Oracle + Funding ---------------------- */

  private verifyOracleSig(oracle: OracleSnapshot) {
    const pk = this.oraclePublicKey.getAndAssertEquals();
    oracle.signature
      .verify(pk, [
        oracle.markPrice.value,
        oracle.indexPrice.value,
        oracle.assetId,
        oracle.timestamp.value,
      ])
      .assertTrue('oracle signature invalid');
  }

  private bumpOracleTimestamp(
    oracle: OracleSnapshot,
    prevTs: UInt64,
    tsWitness: MerkleMapWitness
  ) {
    const currRoot = this.oracleTsRoot.getAndAssertEquals();
    const key = computeAssetKey(oracle.assetId);
    const [rootFromWit, witKey] = tsWitness.computeRootAndKey(prevTs.value);
    rootFromWit.assertEquals(currRoot, 'oracle TS: root mismatch');
    witKey.assertEquals(key, 'oracle TS: key mismatch');
    oracle.timestamp.greaterThanOrEqual(prevTs).assertTrue('stale oracle ts');
    const newRoot = tsWitness.computeRoot(oracle.timestamp.value);
    this.oracleTsRoot.set(newRoot);
  }

  private deriveInstantFundingBpsAbsSign(oracle: OracleSnapshot): { abs: UInt64; sign: Field } {
    const mark = oracle.markPrice;
    const index = oracle.indexPrice;

    const markLtIndex = mark.lessThan(index);
    const diffAbs = UInt64.from(
      Provable.if(
        markLtIndex,
        index.value.sub(mark.value),
        mark.value.sub(index.value)
      )
    );
    const sign = Provable.if(markLtIndex, Field(-1), Field(1));

    // ratio_bps = (diff / index) * 10_000
    const ratioBps = diffAbs.value.mul(BPS_DEN).div(index.value);

    // sensitivity: inst = ratioBps * K / 10_000
    const K = this.fundingKBpsPer1x.getAndAssertEquals();
    const instRaw = ratioBps.mul(K).div(BPS_DEN);

    const cap = this.fundingCapBps.getAndAssertEquals();
    const instAbs = UInt64.from(
      Provable.if(instRaw.lessThanOrEqual(cap), instRaw, cap)
    );

    return { abs: instAbs, sign };
  }

  private deriveEmaNextAbsSign(
    prevAbs: UInt64,
    prevSign: Field,
    instAbs: UInt64,
    instSign: Field
  ): { nextAbs: UInt64; nextSign: Field } {
    const num = UInt64.from(this.fundingAlphaNum.getAndAssertEquals());
    const den = UInt64.from(this.fundingAlphaDen.getAndAssertEquals());
    const denMinusNum = UInt64.from(den.value.sub(num.value));

    const aPrev = UInt64.from(prevAbs.value.mul(denMinusNum.value));
    const aInst = UInt64.from(instAbs.value.mul(num.value));

    const sameSign = prevSign.equals(instSign);
    const prevGEinst = aPrev.lessThan(aInst).not();

    const scaledAbsIfSame = u64AddChecked(aPrev, aInst);
    const scaledAbsIfPrevGE = u64SubSaturating(aPrev, aInst);
    const scaledAbsIfInstGE = u64SubSaturating(aInst, aPrev);
    const scaledAbsIfOpposite = UInt64.from(
      Provable.if(prevGEinst, scaledAbsIfPrevGE.value, scaledAbsIfInstGE.value)
    );
    const scaledAbs = UInt64.from(
      Provable.if(sameSign, scaledAbsIfSame.value, scaledAbsIfOpposite.value)
    );

    const signIfOpposite = Provable.if(prevGEinst, prevSign, instSign);
    const nextSign = Provable.if(sameSign, prevSign, signIfOpposite);

    const nextAbs = UInt64.from(scaledAbs.value.div(den.value));
    return { nextAbs, nextSign };
  }

  /** Oracle doğrula, TS bump, EMA bump; eff funding (bps abs, sign) döndür. */
  private deriveFundingAndBump(
    oracle: OracleSnapshot,
    prevTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ): { effBpsAbs: Field; effSign: Field } {
    this.verifyOracleSig(oracle);
    this.bumpOracleTimestamp(oracle, prevTs, tsWitness);

    const currEmaRoot = this.fundingEmaRoot.getAndAssertEquals();
    const key = computeAssetKey(oracle.assetId);
    const prevLeaf = packFundingEmaLeaf(prevEmaAbs.value, prevEmaSign);
    const [rootFromWit, witKey] = emaWitness.computeRootAndKey(prevLeaf);
    rootFromWit.assertEquals(currEmaRoot, 'funding EMA: root mismatch');
    witKey.assertEquals(key, 'funding EMA: key mismatch');

    const inst = this.deriveInstantFundingBpsAbsSign(oracle);
    const next = this.deriveEmaNextAbsSign(prevEmaAbs, prevEmaSign, inst.abs, inst.sign);

    const newLeaf = packFundingEmaLeaf(next.nextAbs.value, next.nextSign);
    const newRoot = emaWitness.computeRoot(newLeaf);
    this.fundingEmaRoot.set(newRoot);

    const dt = oracle.timestamp.value.sub(prevTs.value);
    const effBpsAbs = next.nextAbs.value.mul(dt).div(SECONDS_PER_HOUR);
    return { effBpsAbs, effSign: next.nextSign };
  }

  /* ---------------------- Risk ---------------------- */

  private computeGainLoss(
    size: UInt64,
    entryPrice: UInt64,
    markPrice: UInt64,
    direction: Field
  ): { gain: UInt64; loss: UInt64; notional: UInt64 } {
    const markNotional = fpMulU64(size, markPrice);
    const entryNotional = fpMulU64(size, entryPrice);
    const isLong = direction.equals(Field(1));
    const longGain = u64SubSaturating(markNotional, entryNotional);
    const longLoss = u64SubSaturating(entryNotional, markNotional);
    const shortGain = u64SubSaturating(entryNotional, markNotional);
    const shortLoss = u64SubSaturating(markNotional, entryNotional);
    const gain = UInt64.from(Provable.if(isLong, longGain.value, shortGain.value));
    const loss = UInt64.from(Provable.if(isLong, longLoss.value, shortLoss.value));
    return { gain, loss, notional: markNotional };
  }

  private computeShortfallWithFundingAndFee(
    collateral: UInt64,
    gain: UInt64,
    loss: UInt64,
    notional: UInt64,
    direction: Field,
    effFundingBpsAbs: Field,
    effFundingSign: Field,
    feeBpsAbs: Field,
    feeSign: Field
  ): UInt64 {
    const fundingAbs = bpsMulU64(notional, effFundingBpsAbs);
    const feeAbs = bpsMulU64(notional, feeBpsAbs);
    const isLong = direction.equals(Field(1));
    const longPaysFunding = effFundingSign.equals(Field(1));
    const payerIsLong = isLong.and(longPaysFunding).or(isLong.not().and(longPaysFunding.not()));

    const liabilityFunding = UInt64.from(Provable.if(payerIsLong, fundingAbs.value, Field(0)));
    const assetsFunding = UInt64.from(Provable.if(payerIsLong, Field(0), fundingAbs.value));

    const liabilityFee = UInt64.from(Provable.if(feeSign.equals(Field(1)), feeAbs.value, Field(0)));
    const assetsFee = UInt64.from(Provable.if(feeSign.equals(Field(1)), Field(0), feeAbs.value));

    const liabilities = u64AddChecked(loss, u64AddChecked(liabilityFunding, liabilityFee));
    const assets = u64AddChecked(collateral, u64AddChecked(gain, u64AddChecked(assetsFunding, assetsFee)));

    return u64SubSaturating(liabilities, assets);
  }

  /* ---------------------- Guards ---------------------- */

  private assertInitialMarginOk(size: UInt64, price: UInt64, collateral: UInt64) {
    const notional = fpMulU64(size, price);
    const imBps = this.initialMarginBps.getAndAssertEquals();
    const imReq = bpsMulU64(notional, imBps);
    collateral.lessThan(imReq).assertFalse('insufficient initial margin');
  }

  private assertFeeWithinCap(feeBpsAbs: Field) {
    const cap = this.maxFeeBpsAbs.getAndAssertEquals();
    feeBpsAbs.assertLessThanOrEqual(cap, 'fee bps exceeds cap');
  }

  private assertSlippage(mark: UInt64, limitPrice: UInt64, limitIsMin: Field) {
    const okMin = mark.greaterThanOrEqual(limitPrice);
    const okMax = mark.lessThanOrEqual(limitPrice);
    Provable.if(limitIsMin.equals(Field(1)), okMin, okMax).assertTrue('slippage guard violated');
  }

  /* ---------------------- Methods: OPEN/CLOSE/LIQ/INCREASE/REDUCE ---------------------- */

  @method openPosition(
    upd: Update,
    oracle: OracleSnapshot,
    prevOracleTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ) {
    this.deriveFundingAndBump(oracle, prevOracleTs, tsWitness, prevEmaAbs, prevEmaSign, emaWitness);

    upd.action.assertEquals(Field(0), 'expected OPEN');
    upd.position.assertInvariants();

    const expectedKey = computeUserKeyOffchain(upd.position.owner, oracle.assetId);
    upd.userKey.assertEquals(expectedKey, 'userKey mismatch');
    upd.position.entryPrice.value.assertEquals(oracle.markPrice.value, 'entry must equal mark');

    this.assertFeeWithinCap(upd.feeBpsAbs);
    this.assertSlippage(oracle.markPrice, upd.limitPrice, upd.limitIsMin);
    this.assertInitialMarginOk(upd.position.size, oracle.markPrice, upd.position.collateral);

    const currentRoot = this.positionsRoot.getAndAssertEquals();
    const [rootIfEmpty, keyEmpty] = upd.witness.computeRootAndKey(Field(0));
    rootIfEmpty.assertEquals(currentRoot, 'slot not empty');
    keyEmpty.assertEquals(upd.userKey, 'Merkle key mismatch');

    const msg: Field[] = [
      ZekoPerpDEX.OPEN_DOMAIN, upd.userKey,
      upd.position.collateral.value, upd.position.size.value,
      upd.position.direction, upd.position.entryPrice.value, upd.position.nonce.value,
      upd.deltaSize.value, // 0 on open
      upd.feeBpsAbs, upd.feeSign,
      upd.limitPrice.value, upd.limitIsMin,
      oracle.markPrice.value, oracle.assetId, oracle.timestamp.value,
    ];
    upd.userSig.verify(upd.position.owner, msg).assertTrue('OPEN: user sig invalid');

    const newRoot = upd.witness.computeRoot(upd.position.hash());
    this.positionsRoot.set(newRoot);
  }

  @method closePosition(
    upd: Update,
    oracle: OracleSnapshot,
    prevOracleTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ) {
    const { effBpsAbs, effSign } = this.deriveFundingAndBump(
      oracle, prevOracleTs, tsWitness, prevEmaAbs, prevEmaSign, emaWitness
    );

    upd.action.assertEquals(Field(1), 'expected CLOSE');
    upd.position.assertInvariants();

    const expectedKey = computeUserKeyOffchain(upd.position.owner, oracle.assetId);
    upd.userKey.assertEquals(expectedKey, 'userKey mismatch');

    this.assertFeeWithinCap(upd.feeBpsAbs);
    this.assertSlippage(oracle.markPrice, upd.limitPrice, upd.limitIsMin);

    const currentRoot = this.positionsRoot.getAndAssertEquals();
    const [rootFromWit, key] = upd.witness.computeRootAndKey(upd.position.hash());
    rootFromWit.assertEquals(currentRoot, 'Merkle root mismatch');
    key.assertEquals(upd.userKey, 'Merkle key mismatch');

    const msg: Field[] = [
      ZekoPerpDEX.CLOSE_DOMAIN, upd.userKey,
      upd.position.collateral.value, upd.position.size.value,
      upd.position.direction, upd.position.entryPrice.value, upd.position.nonce.value,
      upd.deltaSize.value, // 0 on close
      upd.feeBpsAbs, upd.feeSign,
      upd.limitPrice.value, upd.limitIsMin,
      oracle.markPrice.value, oracle.assetId, oracle.timestamp.value,
    ];
    upd.userSig.verify(upd.position.owner, msg).assertTrue('CLOSE: user sig invalid');

    const { gain, loss, notional } = this.computeGainLoss(
      upd.position.size, upd.position.entryPrice, oracle.markPrice, upd.position.direction
    );
    const shortfall = this.computeShortfallWithFundingAndFee(
      upd.position.collateral, gain, loss, notional,
      upd.position.direction, effBpsAbs, effSign, upd.feeBpsAbs, upd.feeSign
    );

    const fund = this.insuranceFund.getAndAssertEquals();
    fund.lessThan(shortfall).assertFalse('Insurance fund insufficient');
    this.insuranceFund.set(u64SubSaturating(fund, shortfall));

    const newRoot = upd.witness.computeRoot(Field(0));
    this.positionsRoot.set(newRoot);
  }

  @method liquidate(
    upd: Update,
    oracle: OracleSnapshot,
    prevOracleTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ) {
    const { effBpsAbs, effSign } = this.deriveFundingAndBump(
      oracle, prevOracleTs, tsWitness, prevEmaAbs, prevEmaSign, emaWitness
    );
    upd.action.assertEquals(Field(3), 'expected LIQ');
    upd.position.assertInvariants();

    const expectedKey = computeUserKeyOffchain(upd.position.owner, oracle.assetId);
    upd.userKey.assertEquals(expectedKey, 'userKey mismatch');

    const currentRoot = this.positionsRoot.getAndAssertEquals();
    const [rootFromWit, key] = upd.witness.computeRootAndKey(upd.position.hash());
    rootFromWit.assertEquals(currentRoot, 'Merkle root mismatch');
    key.assertEquals(upd.userKey, 'Merkle key mismatch');

    const { gain, loss, notional } = this.computeGainLoss(
      upd.position.size, upd.position.entryPrice, oracle.markPrice, upd.position.direction
    );
    const maintBps = this.maintenanceMarginBps.getAndAssertEquals();
    const maintReq = bpsMulU64(notional, maintBps);
    const baseAssets = u64AddChecked(upd.position.collateral, gain);
    const equityNoFunding = u64SubSaturating(baseAssets, loss);
    equityNoFunding.lessThan(maintReq).assertTrue('not liquidatable by base equity');

    const shortfall = this.computeShortfallWithFundingAndFee(
      upd.position.collateral, gain, loss, notional,
      upd.position.direction, effBpsAbs, effSign, Field(0), Field(1)
    );

    const fund = this.insuranceFund.getAndAssertEquals();
    fund.lessThan(shortfall).assertFalse('Insurance fund insufficient');
    this.insuranceFund.set(u64SubSaturating(fund, shortfall));

    const newRoot = upd.witness.computeRoot(Field(0));
    this.positionsRoot.set(newRoot);
  }

  @method increasePosition(
    upd: Update,
    oracle: OracleSnapshot,
    prevOracleTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ) {
    this.deriveFundingAndBump(oracle, prevOracleTs, tsWitness, prevEmaAbs, prevEmaSign, emaWitness);

    upd.action.assertEquals(Field(4), 'expected INCREASE');
    upd.position.assertInvariants();
    upd.deltaSize.value.assertGreaterThan(Field(0), 'deltaSize must be > 0');

    const expectedKey = computeUserKeyOffchain(upd.position.owner, oracle.assetId);
    upd.userKey.assertEquals(expectedKey, 'userKey mismatch');

    this.assertFeeWithinCap(upd.feeBpsAbs); // fee validated only
    this.assertSlippage(oracle.markPrice, upd.limitPrice, upd.limitIsMin);

    const currentRoot = this.positionsRoot.getAndAssertEquals();
    const [rootFromWit, key] = upd.witness.computeRootAndKey(upd.position.hash());
    rootFromWit.assertEquals(currentRoot, 'Merkle root mismatch');
    key.assertEquals(upd.userKey, 'Merkle key mismatch');

    const msg: Field[] = [
      ZekoPerpDEX.INCR_DOMAIN, upd.userKey,
      upd.position.collateral.value, upd.position.size.value,
      upd.position.direction, upd.position.entryPrice.value, upd.position.nonce.value,
      upd.deltaSize.value,
      upd.feeBpsAbs, upd.feeSign,
      upd.limitPrice.value, upd.limitIsMin,
      oracle.markPrice.value, oracle.assetId, oracle.timestamp.value,
    ];
    upd.userSig.verify(upd.position.owner, msg).assertTrue('INCREASE: user sig invalid');

    const newSize = UInt64.from(upd.position.size.value.add(upd.deltaSize.value));
    const notionalOld = fpMulU64(upd.position.size, upd.position.entryPrice);
    const notionalAdd = fpMulU64(upd.deltaSize, oracle.markPrice);
    const notionalSum = u64AddChecked(notionalOld, notionalAdd);
    const newEntry = fpDivU64(notionalSum, newSize);

    this.assertInitialMarginOk(newSize, oracle.markPrice, upd.position.collateral);

    const nextPos = new Position({
      owner: upd.position.owner,
      collateral: upd.position.collateral,
      size: newSize,
      direction: upd.position.direction,
      entryPrice: newEntry,
      nonce: upd.position.nonce,
    });
    const newRoot = upd.witness.computeRoot(nextPos.hash());
    this.positionsRoot.set(newRoot);
  }

  @method reducePosition(
    upd: Update,
    oracle: OracleSnapshot,
    prevOracleTs: UInt64,
    tsWitness: MerkleMapWitness,
    prevEmaAbs: UInt64,
    prevEmaSign: Field,
    emaWitness: MerkleMapWitness
  ) {
    const { effBpsAbs, effSign } = this.deriveFundingAndBump(
      oracle, prevOracleTs, tsWitness, prevEmaAbs, prevEmaSign, emaWitness
    );

    upd.action.assertEquals(Field(5), 'expected REDUCE');
    upd.position.assertInvariants();
    upd.deltaSize.value.assertGreaterThan(Field(0), 'deltaSize must be > 0');
    upd.position.size.value.assertGreaterThanOrEqual(upd.deltaSize.value, 'deltaSize > size');

    const expectedKey = computeUserKeyOffchain(upd.position.owner, oracle.assetId);
    upd.userKey.assertEquals(expectedKey, 'userKey mismatch');

    this.assertFeeWithinCap(upd.feeBpsAbs);
    this.assertSlippage(oracle.markPrice, upd.limitPrice, upd.limitIsMin);

    const currentRoot = this.positionsRoot.getAndAssertEquals();
    const [rootFromWit, key] = upd.witness.computeRootAndKey(upd.position.hash());
    rootFromWit.assertEquals(currentRoot, 'Merkle root mismatch');
    key.assertEquals(upd.userKey, 'Merkle key mismatch');

    const msg: Field[] = [
      ZekoPerpDEX.REDUCE_DOMAIN, upd.userKey,
      upd.position.collateral.value, upd.position.size.value,
      upd.position.direction, upd.position.entryPrice.value, upd.position.nonce.value,
      upd.deltaSize.value,
      upd.feeBpsAbs, upd.feeSign,
      upd.limitPrice.value, upd.limitIsMin,
      oracle.markPrice.value, oracle.assetId, oracle.timestamp.value,
    ];
    upd.userSig.verify(upd.position.owner, msg).assertTrue('REDUCE: user sig invalid');

    const newSize = UInt64.from(upd.position.size.value.sub(upd.deltaSize.value));
    const { gain, loss } = this.computeGainLoss(
      upd.position.size, upd.position.entryPrice, oracle.markPrice, upd.position.direction
    );
    const fGain = mulU64ByRatio(gain, upd.deltaSize, upd.position.size);
    const fLoss = mulU64ByRatio(loss, upd.deltaSize, upd.position.size);
    const collateralShare = mulU64ByRatio(upd.position.collateral, upd.deltaSize, upd.position.size);

    const dNotional = fpMulU64(upd.deltaSize, oracle.markPrice);

    const fundingClosedAbs = bpsMulU64(dNotional, effBpsAbs);
    const isLong = upd.position.direction.equals(Field(1));
    const longPays = Field(1).equals(effSign);
    const payerIsLong = isLong.and(longPays).or(isLong.not().and(longPays.not()));

    const baseAfterLoss = u64SubSaturating(u64AddChecked(collateralShare, fGain), fLoss);
    const afterFunding = UInt64.from(
      Provable.if(
        payerIsLong,
        u64SubSaturating(baseAfterLoss, fundingClosedAbs).value,
        u64AddChecked(baseAfterLoss, fundingClosedAbs).value
      )
    );
    const feeAbs = bpsMulU64(dNotional, upd.feeBpsAbs);
    const afterFee = UInt64.from(
      Provable.if(
        upd.feeSign.equals(Field(1)),
        u64SubSaturating(afterFunding, feeAbs).value,
        u64AddChecked(afterFunding, feeAbs).value
      )
    );

    const shortfallClosed = this.computeShortfallWithFundingAndFee(
      collateralShare, fGain, fLoss, dNotional,
      upd.position.direction, effBpsAbs, effSign, upd.feeBpsAbs, upd.feeSign
    );

    const fund = this.insuranceFund.getAndAssertEquals();
    fund.lessThan(shortfallClosed).assertFalse('Insurance fund insufficient');
    this.insuranceFund.set(u64SubSaturating(fund, shortfallClosed));

    const remainColl = u64SubSaturating(upd.position.collateral, collateralShare);
    const newCollateral = u64AddChecked(remainColl, afterFee);

    const leaf =
      Provable.if(
        newSize.value.equals(Field(0)),
        Field(0),
        new Position({
          owner: upd.position.owner,
          collateral: newCollateral,
          size: newSize,
          direction: upd.position.direction,
          entryPrice: upd.position.entryPrice,
          nonce: upd.position.nonce,
        }).hash()
      );

    const newRoot = upd.witness.computeRoot(leaf);
    this.positionsRoot.set(newRoot);
  }
}
