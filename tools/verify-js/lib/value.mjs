// Schema-driven check of a value in typed JSON against a type reference
// (sections 3.4 and 6.3), written independently of the Go generator.

const REMOVED = 0x4;
const OPTIONAL = 0x1;

const isInt = (v) => Number.isInteger(v) || (v !== null && typeof v === 'object' && '$int' in v);
const isUint = (v) => (Number.isInteger(v) && v >= 0) || (v !== null && typeof v === 'object' && '$int' in v && !v.$int.startsWith('-'));
const mapEntries = (v) => {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return null;
  if ('$map' in v) return v.$map;
  if (['$bytes', '$int', '$float', '$tag'].some((k) => k in v)) return null;
  return Object.entries(v);
};

/** Throws an Error naming the path of the first mismatch. */
export function checkValue(types, ref, v, path = '$') {
  const fail = (what) => { throw new Error(`${path}: ${what}: ${JSON.stringify(v)}`); };
  if (Array.isArray(ref)) {
    switch (ref[0]) {
      case 0:
        if (!Array.isArray(v)) fail('list expected');
        v.forEach((e, i) => checkValue(types, ref[1], e, `${path}[${i}]`));
        return;
      case 1: {
        const es = mapEntries(v);
        if (!es) fail('map expected');
        for (const [k, x] of es) {
          checkValue(types, ref[1], k, `${path}.key`);
          checkValue(types, ref[2], x, `${path}[${JSON.stringify(k)}]`);
        }
        return;
      }
      case 2:
        if (v !== null) checkValue(types, ref[1], v, path);
        return;
      case 4:
        if (!isUint(v) || v === 0) fail('nonzero byte token expected');
        return;
      default: fail(`type-ref ${JSON.stringify(ref)} is not a value type`);
    }
  }
  switch (ref) {
    case 0: if (v !== null) fail('unit expected'); return;
    case 1: if (typeof v !== 'boolean') fail('bool expected'); return;
    case 2: if (!isInt(v)) fail('int expected'); return;
    case 3: if (!isUint(v)) fail('uint expected'); return;
    case 4: case 5: if (!(isInt(v) || (v && typeof v === 'object' && '$float' in v))) fail('float expected'); return;
    case 6: if (typeof v !== 'string') fail('string expected'); return;
    case 7: if (!(v && typeof v === 'object' && '$bytes' in v)) fail('bytes expected'); return;
    case 8: if (!(v && v.$tag === 1)) fail('timestamp expected'); return;
    case 9: if (!(v && v.$tag === 37 && v.value?.$bytes?.length === 32)) fail('uuid expected'); return;
    case 10:
      if (!Array.isArray(v) || v.length !== 2 || !isUint(v[0])) fail('dynamic [type_id, value] expected');
      checkValue(types, v[0], v[1], `${path}<${v[0]}>`);
      return;
    case 11: if (!(isUint(v) || typeof v === 'string')) fail('symbol expected'); return;
    default: break;
  }
  const t = types.get(ref);
  if (!t) fail(`unknown type ${ref}`);
  switch (t[0]) {
    case 0: { // struct
      const fields = new Map(t[3].map((f) => [f[0], f]));
      if (t[4] & 1) { // sparse: map from tag to value
        const es = mapEntries(v);
        if (!es) fail('sparse struct map expected');
        for (const [k, x] of es) {
          const f = fields.get(k);
          if (f && !(f[3] & REMOVED)) checkValue(types, f[2], x, `${path}.${f[1]}`);
        }
        for (const f of fields.values()) {
          if (!(f[3] & (OPTIONAL | REMOVED)) && !es.some(([k]) => k === f[0])) fail(`required field ${f[1]} missing`);
        }
        return;
      }
      if (!Array.isArray(v)) fail('struct array expected');
      if (v.length && v[v.length - 1] === null) fail('trailing null not omitted');
      for (const f of fields.values()) {
        const x = f[0] < v.length ? v[f[0]] : null;
        const at = `${path}.${f[1]}`;
        if (f[3] & REMOVED) { if (x !== null) throw new Error(`${at}: tombstone slot must be null`); continue; }
        if (x === null) {
          if (!(f[3] & OPTIONAL) && f[2] !== 0) throw new Error(`${at}: required field is absent`);
          continue;
        }
        checkValue(types, f[2], x, at);
      }
      return; // elements beyond the known fields are skipped (3.4)
    }
    case 1: if (!t[3].includes(v)) fail(`not a value of enum ${t[2]}`); return;
    case 2: {
      if (!Array.isArray(v) || v.length !== 2) fail('union [tag, value] expected');
      const f = t[3].find((x) => x[0] === v[0]);
      if (!f || f[3] & REMOVED) fail(`no live variant ${v[0]} in ${t[2]}`);
      checkValue(types, f[2], v[1], `${path}.${f[1]}`);
      return;
    }
    case 3: checkValue(types, t[3], v, path); return;
    default: fail(`bad type kind ${t[0]}`);
  }
}
