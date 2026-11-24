/* Unsigned SIGHASH_ALL PSBT builder for a single-input, two-output payment.
   No keys, no signatures, no finalizer. */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  root.Ok67286Psbt = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const BECH32_CONST = 1;
  const BECH32M_CONST = 0x2bc830a3;
  const SIGHASH_ALL = 1;
  const DUST_SATS = 330;

  function polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (let i = 0; i < values.length; i += 1) {
      const b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[i];
      for (let j = 0; j < 5; j += 1) {
        if ((b >> j) & 1) chk ^= GEN[j];
      }
    }
    return chk >>> 0;
  }

  function hrpExpand(hrp) {
    const ret = [];
    for (let i = 0; i < hrp.length; i += 1) ret.push(hrp.charCodeAt(i) >> 5);
    ret.push(0);
    for (let i = 0; i < hrp.length; i += 1) ret.push(hrp.charCodeAt(i) & 31);
    return ret;
  }

  function convertBits(data, from, to, pad) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << to) - 1;
    for (let i = 0; i < data.length; i += 1) {
      const value = data[i];
      if (value < 0 || value >> from !== 0) {
        throw new Error('地址数据无效');
      }
      acc = (acc << from) | value;
      bits += from;
      while (bits >= to) {
        bits -= to;
        ret.push((acc >> bits) & maxv);
      }
    }
    if (pad) {
      if (bits) ret.push((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
      throw new Error('地址填充无效');
    }
    return ret;
  }

  function decodeSegwitAddress(address) {
    if (typeof address !== 'string') throw new Error('地址为空');
    const trimmed = address.trim();
    const lower = trimmed.toLowerCase();
    if (lower !== trimmed && trimmed !== trimmed.toUpperCase()) {
      throw new Error('地址大小写混用');
    }
    const pos = lower.lastIndexOf('1');
    if (pos < 1 || pos + 7 > lower.length) throw new Error('不是 SegWit 地址');
    const hrp = lower.slice(0, pos);
    if (hrp !== 'tb') throw new Error('需要 Signet 地址（tb1 开头）');
    const data = [];
    for (let i = pos + 1; i < lower.length; i += 1) {
      const d = CHARSET.indexOf(lower[i]);
      if (d === -1) throw new Error('地址含有非法字符');
      data.push(d);
    }
    const spec = polymod(hrpExpand(hrp).concat(data));
    let encoding = '';
    if (spec === BECH32_CONST) encoding = 'bech32';
    else if (spec === BECH32M_CONST) encoding = 'bech32m';
    else throw new Error('地址校验失败');
    const payload = data.slice(0, -6);
    if (!payload.length) throw new Error('地址缺少 witness 版本');
    const version = payload[0];
    const program = convertBits(payload.slice(1), 5, 8, false);
    if (version === 0 && encoding !== 'bech32') {
      throw new Error('v0 地址必须使用 bech32');
    }
    if (version !== 0 && encoding !== 'bech32m') {
      throw new Error('v1 地址必须使用 bech32m');
    }
    return { hrp, version, program: Uint8Array.from(program) };
  }

  function outputScript(address) {
    const decoded = decodeSegwitAddress(address);
    const program = decoded.program;
    if (decoded.version === 1 && program.length === 32) {
      const script = new Uint8Array(34);
      script[0] = 0x51;
      script[1] = 0x20;
      script.set(program, 2);
      return script;
    }
    if (decoded.version === 0 && program.length === 20) {
      const script = new Uint8Array(22);
      script[0] = 0x00;
      script[1] = 0x14;
      script.set(program, 2);
      return script;
    }
    if (decoded.version === 0 && program.length === 32) {
      const script = new Uint8Array(34);
      script[0] = 0x00;
      script[1] = 0x20;
      script.set(program, 2);
      return script;
    }
    throw new Error('只接受 tb1p（Taproot）或 tb1q（隔离见证）地址');
  }

  function isTaprootAddress(address) {
    const decoded = decodeSegwitAddress(address);
    return decoded.version === 1 && decoded.program.length === 32;
  }

  function concat(parts) {
    let len = 0;
    for (let i = 0; i < parts.length; i += 1) len += parts[i].length;
    const out = new Uint8Array(len);
    let offset = 0;
    for (let i = 0; i < parts.length; i += 1) {
      out.set(parts[i], offset);
      offset += parts[i].length;
    }
    return out;
  }

  function u32le(n) {
    const b = new Uint8Array(4);
    const v = n >>> 0;
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 24) & 0xff;
    return b;
  }

  function u64le(n) {
    const b = new Uint8Array(8);
    let x = BigInt(n);
    if (x < 0n) throw new Error('金额不能为负');
    for (let i = 0; i < 8; i += 1) {
      b[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    if (x !== 0n) throw new Error('金额超出范围');
    return b;
  }

  function compactSize(n) {
    if (n < 0xfd) return Uint8Array.of(n);
    throw new Error('脚本过长');
  }

  function txidBytesReversed(txid) {
    const hex = String(txid).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('txid 必须是 64 位十六进制');
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) {
      out[31 - i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function toHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i += 1) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function psbtPair(typeByte, value) {
    return concat([
      compactSize(1),
      Uint8Array.of(typeByte),
      compactSize(value.length),
      value,
    ]);
  }

  function buildPaymentPsbt(input) {
    const account = String(input.accountAddress || '').trim();
    const receive = String(input.receiveAddress || '').trim();
    const txid = String(input.txid || '').trim();
    const vout = Number(input.vout);
    const inputValue = BigInt(input.inputValue);
    const sendValue = BigInt(input.sendValue);
    const fee = BigInt(input.fee);
    if (!Number.isInteger(vout) || vout < 0 || vout > 0xffffffff) {
      throw new Error('vout 不是有效的输出序号');
    }
    if (!isTaprootAddress(account)) {
      throw new Error('测试账户必须是 Signet Taproot 地址（tb1p）');
    }
    if (account.toLowerCase() === receive.toLowerCase()) {
      throw new Error('收款地址必须和测试账户不同');
    }
    if (sendValue < BigInt(DUST_SATS) || fee <= 0n) {
      throw new Error('外部收款至少 330 sat，手续费必须大于 0');
    }
    const change = inputValue - sendValue - fee;
    if (change < BigInt(DUST_SATS)) {
      throw new Error(
        '找零不足 330 sat。换一笔更大的 UTXO，或减小收款金额 / 手续费',
      );
    }
    const accountScript = outputScript(account);
    const receiveScript = outputScript(receive);
    const outputs = [
      { script: receiveScript, value: sendValue, address: receive, kind: 'external' },
      { script: accountScript, value: change, address: account, kind: 'change' },
    ];
    const txParts = [
      u32le(2),
      compactSize(1),
      txidBytesReversed(txid),
      u32le(vout),
      compactSize(0),
      u32le(0xffffffff),
      compactSize(outputs.length),
    ];
    for (let i = 0; i < outputs.length; i += 1) {
      txParts.push(u64le(outputs[i].value));
      txParts.push(compactSize(outputs[i].script.length));
      txParts.push(outputs[i].script);
    }
    txParts.push(u32le(0));
    const unsignedTx = concat(txParts);
    const witnessUtxo = concat([
      u64le(inputValue),
      compactSize(accountScript.length),
      accountScript,
    ]);
    const psbt = concat([
      Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff]),
      psbtPair(0x00, unsignedTx),
      Uint8Array.of(0x00),
      psbtPair(0x01, witnessUtxo),
      psbtPair(0x03, u32le(SIGHASH_ALL)),
      Uint8Array.of(0x00),
      Uint8Array.of(0x00),
      Uint8Array.of(0x00),
    ]);
    return {
      psbtHex: toHex(psbt),
      sighash: 'SIGHASH_ALL',
      sighashType: SIGHASH_ALL,
      input: { txid: txid.toLowerCase(), vout, value: inputValue.toString() },
      external: { address: receive, value: sendValue.toString() },
      change: { address: account, value: change.toString() },
      fee: fee.toString(),
    };
  }

  function hexToBytes(hex) {
    const clean = String(hex).trim().replace(/\s+/g, '').toLowerCase();
    if (clean.length % 2 !== 0 || /[^0-9a-f]/.test(clean)) {
      throw new Error('PSBT 不是合法的十六进制');
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function makeReader(bytes) {
    let offset = 0;
    return {
      remaining: () => bytes.length - offset,
      readByte() {
        if (offset >= bytes.length) throw new Error('PSBT 数据提前结束');
        const b = bytes[offset];
        offset += 1;
        return b;
      },
      read(n) {
        if (offset + n > bytes.length) throw new Error('PSBT 数据提前结束');
        const slice = bytes.slice(offset, offset + n);
        offset += n;
        return slice;
      },
      readVarint() {
        const first = this.readByte();
        if (first < 0xfd) return first;
        if (first === 0xfd) {
          const b = this.read(2);
          return b[0] | (b[1] << 8);
        }
        if (first === 0xfe) {
          const b = this.read(4);
          return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] * 0x1000000)) >>> 0;
        }
        const b = this.read(8);
        let v = 0n;
        for (let i = 7; i >= 0; i -= 1) v = (v << 8n) | BigInt(b[i]);
        return Number(v);
      },
      readU32le() {
        const b = this.read(4);
        return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] * 0x1000000)) >>> 0;
      },
      readU64le() {
        const b = this.read(8);
        let v = 0n;
        for (let i = 7; i >= 0; i -= 1) v = (v << 8n) | BigInt(b[i]);
        return v;
      },
    };
  }

  function parseUnsignedTx(bytes) {
    const r = makeReader(bytes);
    r.readU32le(); // version
    const inputCount = r.readVarint();
    for (let i = 0; i < inputCount; i += 1) {
      r.read(32);
      r.readU32le();
      const scriptLen = r.readVarint();
      r.read(scriptLen);
      r.readU32le();
    }
    const outputCount = r.readVarint();
    const outputs = [];
    for (let i = 0; i < outputCount; i += 1) {
      const value = r.readU64le();
      const scriptLen = r.readVarint();
      const script = r.read(scriptLen);
      outputs.push({ value: value.toString(), scriptHex: toHex(script) });
    }
    return { inputCount, outputs };
  }

  function decodePsbt(hex) {
    const bytes = hexToBytes(hex);
    const magic = [0x70, 0x73, 0x62, 0x74, 0xff];
    for (let i = 0; i < magic.length; i += 1) {
      if (bytes[i] !== magic[i]) throw new Error('不是 PSBT（magic 不匹配）');
    }
    const r = makeReader(bytes.slice(magic.length));
    let unsignedTx = null;
    for (;;) {
      const keyLen = r.readVarint();
      if (keyLen === 0) break;
      const key = r.read(keyLen);
      const valLen = r.readVarint();
      const val = r.read(valLen);
      if (key[0] === 0x00) unsignedTx = val;
    }
    if (!unsignedTx) throw new Error('PSBT 缺少 unsigned tx');
    const tx = parseUnsignedTx(unsignedTx);
    const inputs = [];
    for (let i = 0; i < tx.inputCount; i += 1) {
      let sighashType;
      for (;;) {
        const keyLen = r.readVarint();
        if (keyLen === 0) break;
        const key = r.read(keyLen);
        const valLen = r.readVarint();
        const val = r.read(valLen);
        if (key[0] === 0x03 && val.length === 4) {
          sighashType = (val[0] | (val[1] << 8) | (val[2] << 16) | (val[3] * 0x1000000)) >>> 0;
        }
      }
      inputs.push({ sighashType });
    }
    return { inputs, outputs: tx.outputs };
  }

  function sighashName(type) {
    if (type === undefined) return 'DEFAULT（未声明，按 ALL）';
    const map = {
      0x01: 'ALL',
      0x02: 'NONE',
      0x03: 'SINGLE',
      0x81: 'ALL|ANYONECANPAY',
      0x82: 'NONE|ANYONECANPAY',
      0x83: 'SINGLE|ANYONECANPAY',
    };
    const name = map[type] || '未知';
    return '0x' + type.toString(16) + '（' + name + '）';
  }

  return {
    DUST_SATS,
    SIGHASH_ALL,
    decodeSegwitAddress,
    isTaprootAddress,
    outputScript,
    buildPaymentPsbt,
    decodePsbt,
    sighashName,
    toHex,
  };
});
