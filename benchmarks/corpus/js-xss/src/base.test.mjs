import { test } from 'node:test';
import assert from 'node:assert/strict';
import { render } from './render.mjs';
test('plain', () => { assert.equal(render('bob'), '<h1>Hello bob</h1>'); });
