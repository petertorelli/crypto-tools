<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 AEAD
      p Should we include Associated Data and Nonce inputs?
  .row.mt-2
    .col-3
      select.form-select(v-model='aeadMode')
        option(value='aes-ccm') AES-CCM
        option(value='aes-gcm') AES-GCM
        option(value='chacha-poly') ChaCha20-Poly1305
  .row.mt-2
    .col-12
      label Key (hex) must be 32, 48, or 64 digits ({{ aeadKey ? aeadKey.length : 0 }}):
      input.form-control(type='text' v-model='aeadKey')
  .row.mt-2
    .col-6
      button.me-2(@click='aeadKey = genRandBytes(16)') Gen 128 bits
      button.me-2(@click='aeadKey = genRandBytes(24)') Gen 192 bits
      button(@click='aeadKey = genRandBytes(32)') Gen 256 bits
  .row.mt-2
    .col-6
      label IV (hex), Must be 32 digits, currently is {{ aeadIv ? aeadIv.length : 0 }}:
      input.form-control(type='text' v-model='aeadIv')
  .row.mt-2
    .col-6
      button(@click='aeadIv = genRandBytes(16)') Gen 128 bits
  .row.mt-2
    .col
      .alert.alert-danger(v-if='aeadEncError') {{aeadEncError}}
  .row.mt-2
    .col-6
      label Plaintext: (text, current length is {{ aeadIn1 ? aeadIn1.length : 0 }} bytes)
      textarea.form-control(v-model='aeadIn1')
    .col-6
      label Ciphertext:
      textarea.form-control(:value='aeadOut1' disabled)
    .col-6
    .col-6
      label Tag (hex)
      input.form-control(type='text' :value='aeadTag1' disabled)
  .row.mt-2
    .col
      button(@click='encAead()') Encrypt
  .row.mt-2
    .col
      .alert.alert-danger(v-if='aeadDecError') {{aeadDecError}}
  .row.mt-2
    .col-6
      label Ciphertext (hex, current length is {{ aeadOut2 ? aeadOut2.length : 0 }} digits.):
      textarea.form-control(v-model='aeadOut2')
    .col-6
      label Plaintext:
      textarea.form-control(:value='aeadIn2' disabled)
    .col-6
      label Tag (hex, current length is {{ aeadTag2 ? aeadTag2.length : 0 }} digits.):
      input.form-control(type='text' v-model='aeadTag2')
  .row.mt-2
    .col
      button(@click='decAead()') Decrypt

</template>

<script lang='ts'>

import * as crypto from 'crypto';
import Vue from 'vue';

const chacha = require('chacha');
// experiencing TS issues with scjl interface
const sjcl = require('./sjcl.js');

function doAesModeEnc (_key: string, _txt: string, _iv: string, mode: string) {
  if (!_key || !_txt || !_iv) {
  throw new Error('Cannot perform mode encrypt w/o a key, text, and an IV');
  }
const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const txt = sjcl.codec.utf8String.toBits(_txt);
  const iv = sjcl.codec.hex.toBits(_iv.toLowerCase());
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  let res = sjcl.mode[mode].encrypt(cipher, txt, iv, [], 8 * 16);
  res = sjcl.codec.hex.fromBits(res);
  return [ res.substr(0, res.length - 32), res.substr(res.length - 32, 32)];
}

function doChaChaEnc (_key: string, _txt: string, _iv: string) {
  if (!_key || !_txt || !_iv) {
    throw new Error('Cannot perform encrypt w/o a key, text, and an IV');
  }
  // Converting to buffer from hex, odd number hex digits = no leading zero
  if (_key.length & 1) {
    _key = '0' + _key;
  }
  if (_iv.length & 1) {
    _iv = '0' + _iv;
  }
  if (_key.length < 64) {
    throw new Error('ChaCha20 requires a 256-bit key');
  }
  const key = Buffer.from(_key, 'hex');
  const iv = Buffer.from(_iv, 'hex');
  const cipher = chacha.createCipher(key, iv);
  const ct = cipher.update(_txt, 'utf8', 'hex') + cipher.final('hex');
  // setAAD...
  const tag = cipher.getAuthTag();
  return [ct.toString('hex'), tag.toString('hex')];
}

function doChaChaDec (_key: string, _txt: string, _iv: string, _tag: string) {
  if (!_key || !_txt || !_iv || !_tag) {
    throw new Error('Cannot perform decrypt w/o a key, text, and an IV');
  }
  // Converting to buffer from hex, odd number hex digits = no leading zero
  if (_key.length & 1) {
    _key = '0' + _key;
  }
  if (_iv.length & 1) {
    _iv = '0' + _iv;
  }
  if (_tag.length & 1) {
    _tag = '0' + _tag;
  }
  if (_key.length < 64) {
    throw new Error('ChaCha20 requires a 256-bit key');
  }
  const key = Buffer.from(_key, 'hex');
  const iv = Buffer.from(_iv, 'hex');
  const tag = Buffer.from(_tag, 'hex');
  const cipher = chacha.createDecipher(key, iv);
  cipher.setAuthTag(tag);
  const pt = cipher.update(_txt, 'hex') + cipher.final();
  // setAAD...
  return pt.toString();
}

function doAesModeDec (_key: string, _txt: string, _iv: string, _tag: string, mode: string) {
  if (!_key || !_txt || !_iv) {
  throw new Error('Cannot perform mode decrypt w/o a key, text, and an IV');
  }
  
  const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const iv = sjcl.codec.hex.toBits(_iv.toLowerCase());
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  const tmp = _txt + _tag;
  const bits = sjcl.codec.hex.toBits(tmp.toLowerCase());
  const res = sjcl.mode[mode].decrypt(cipher, bits, iv, [], 8 * 16);
  return sjcl.codec.utf8String.fromBits(res);
}

export default Vue.extend({
  name: 'AeadWidget',
  data() {
  return {
    aeadMode     : 'aes-ccm',
    aeadKey      : '',
    aeadIv       : '',
    aeadIn1      : 'Here\'s some text',
    aeadOut1     : '',
    aeadTag1     : '',
    aeadIn2      : '',
    aeadOut2     : '',
    aeadTag2     : '',
    aeadEncError : '',
    aeadDecError : '',
  }
  },
  methods: {
    genRandBytes(size: number) {
      return crypto.randomBytes(size).toString('hex');
    },
    encAead() {
      this.aeadEncError = '';
      this.aeadOut1 = '';
      this.aeadTag1 = '';
      try {
        switch (this.aeadMode) {
          case 'aes-ccm':
          [this.aeadOut1, this.aeadTag1] = doAesModeEnc(this.aeadKey, this.aeadIn1, this.aeadIv, 'ccm');
          break;
          case 'aes-gcm':
          [this.aeadOut1, this.aeadTag1] = doAesModeEnc(this.aeadKey, this.aeadIn1, this.aeadIv, 'gcm');
          break;
          case 'chacha-poly':
          [this.aeadOut1, this.aeadTag1] = doChaChaEnc(this.aeadKey, this.aeadIn1, this.aeadIv);
          break;
          default:
          throw new Error(`Unsupported mode: ${this.aeadMode}`);
        }
      } catch (error) {
        this.aeadEncError = error as string;
      }
    },
    decAead() {
      this.aeadDecError = '';
      this.aeadIn2 = '';
      try {
        switch (this.aeadMode) {
          case 'aes-ccm':
          this.aeadIn2 = doAesModeDec(this.aeadKey, this.aeadOut2, this.aeadIv, this.aeadTag2, 'ccm');
          break;
          case 'aes-gcm':
          this.aeadIn2 = doAesModeDec(this.aeadKey, this.aeadOut2, this.aeadIv, this.aeadTag2, 'gcm');
          break;
          case 'chacha-poly':
          this.aeadIn2 = doChaChaDec(this.aeadKey, this.aeadOut2, this.aeadIv, this.aeadTag2);
          break;
          default:
          throw new Error(`Unsupported mode: ${this.aeadMode}`);
        }
      } catch (error) {
        this.aeadDecError = error as string;
      }
    },
  }
});
</script>
