import test from 'node:test';
import assert from 'node:assert/strict';
import {parse,parseNumberAndBigInt,stringify} from 'lossless-json';
test('browser JSON preserves int64 database identifiers',()=>{const v=parse('{"id":9007199254740993}',null,{parseNumber:parseNumberAndBigInt});assert.equal(v.id,9007199254740993n);assert.equal(stringify(v),'{"id":9007199254740993}');});
