<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Ciphers
  .row.mt-2
    .col-3
      select.form-select(v-model='cipherMode')
        option(selected value='aes-ecb') AES-ECB
        option(value='aes-ctr') AES-CTR
  .row.mt-2
    .col-12
      label Key (hex) must be 32, 48, or 64 digits ({{ cipherKey.length }}):
      input.form-control(type='text' v-model='cipherKey')
  .row.mt-2
    .col
      button.me-2(@click='cipherKey = genRandBytes(16)') Gen 128 bits
      button.me-2(@click='cipherKey = genRandBytes(24)') Gen 192 bits
      button(@click='cipherKey = genRandBytes(32)') Gen 256 bits
  .row.mt-2(v-if='cipherMode!="aes-ecb"')
    .col-6
      label IV (hex), Must be 32 digits ({{ cipherIv.length }}):
      input.form-control(type='text' v-model='cipherIv')
  .row.mt-2(v-if='cipherMode!="aes-ecb"')
    .col-6
      button(@click='cipherIv = genRandBytes(16)') Gen 128 bits
  .row.mt-2
    .col
      .alert.alert-danger(v-if='cipherEncError') {{cipherEncError}}
  .row.mt-2
    .col-6
      label Plaintext: ({{ cipherIn1.length}} chars/digits)
      textarea.form-control(v-model='cipherIn1')
    .col-6
      label Ciphertext:
      textarea.form-control(:value='cipherOut1' disabled)
  .row.mt-2
    .col
      .form-check.form-switch
        input.form-check-input(type='checkbox' v-model='isHex')
        label.form-check-label Input is {{ isHex ? 'Hex' : 'ASCII' }}
  .row.mt-2
    .col
      button(@click='encCipher()') Encrypt
  .row.mt-2
    .col
      .alert.alert-danger(v-if='cipherDecError') {{cipherDecError}}
  .row.mt-2
    .col-6
      label Ciphertext (hex, {{ cipherOut2.length }} digits):
      textarea.form-control(v-model='cipherOut2')
    .col-6
      label Plaintext:
      textarea.form-control(:value='cipherIn2' disabled)
  .row.mt-2
    .col
      button(@click='decCipher()') Decrypt

</template>

<script lang='ts'>

import * as crypto from 'crypto';
import Vue from 'vue';

// experiencing TS issues with scjl interface
const sjcl = require('./sjcl.js');
  /* Required to use some functionality */
((sjcl.beware &&
sjcl.beware["CTR mode is dangerous because it doesn't protect message integrity."]) ||
function(){})();

function doAesEcbEnc (_key: string, _hex: string) {
  if (!_key || !_hex) {
    throw new Error('Cannot perform ECB encrypt w/o a key and text');
  }
  const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const txt = sjcl.codec.hex.toBits(_hex);
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  const res = cipher.encrypt(txt);
  return sjcl.codec.hex.fromBits(res);
}

function doAesEcbDec (_key: string, _hex: string, hexOut: boolean = false) {
  if (!_key || !_hex) {
    throw new Error('Cannot perform ECB decrypt w/o a key and text');
  }
  const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const txt = sjcl.codec.hex.toBits(_hex.toLowerCase());
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  const res = cipher.decrypt(txt);
  return hexOut ? 
    sjcl.codec.hex.fromBits(res) :
    sjcl.codec.utf8String.fromBits(res);
}

function doAesCtrEnc (_key: string, _hex: string, _iv: string) {
  if (!_key || !_hex || !_iv) {
    throw new Error('Cannot perform mode encrypt w/o a key, text, and an IV');
  }
  const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const txt = sjcl.codec.hex.toBits(_hex.toLowerCase());
  const iv = sjcl.codec.hex.toBits(_iv.toLowerCase());
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  const res = sjcl.mode.ctr.encrypt(cipher, txt, iv);
  return sjcl.codec.hex.fromBits(res);
}

function doAesCtrDec (_key: string, _hex: string, _iv: string, hexOut: boolean = false) {
  if (!_key || !_hex || !_iv) {
    throw new Error('Cannot perform mode decrypt w/o a key, text, and an IV');
  }
  const key = sjcl.codec.hex.toBits(_key.toLowerCase());
  const iv = sjcl.codec.hex.toBits(_iv.toLowerCase());
  // eslint-disable-next-line new-cap
  const cipher = new sjcl.cipher.aes(key);
  const bits = sjcl.codec.hex.toBits(_hex.toLowerCase());
  const res = sjcl.mode.ctr.decrypt(cipher, bits, iv);
  return hexOut ? 
    sjcl.codec.hex.fromBits(res) :
    sjcl.codec.utf8String.fromBits(res);
}

export default Vue.extend({
  name: 'CipherWidget',
  data() {
    return {
      cipherMode     : 'aes-ecb',
      cipherKey      : '',
      cipherIv       : '',
      cipherIn1      : 'Here\'s some text',
      cipherOut1     : '',
      cipherIn2      : '',
      cipherOut2     : '',
      cipherEncError : '',
      cipherDecError : '',
      isHex          : false,
    }
  },
  methods: {
    genRandBytes(size: number) {
      return crypto.randomBytes(size).toString('hex');
    },
    encCipher() {
      this.cipherEncError = '';
      this.cipherOut1 = '';
      try {
        let input = this.cipherIn1;
        if (!this.isHex) {
          const tmp = Buffer.from(input);
          input = tmp.toString('hex');
        } else if (!input.match(/^[0-9a-fA-F]+$/)) {
          throw new Error('Input is not valid hex');
        }
        switch (this.cipherMode) {
          case 'aes-ecb':
          this.cipherOut1 = doAesEcbEnc(this.cipherKey, input);
          break;
          case 'aes-ctr':
          this.cipherOut1 = doAesCtrEnc(this.cipherKey, input, this.cipherIv);
          break;
          default:
          throw new Error(`Unsupported mode: ${this.cipherMode}`);
        }
      } catch (error) {
        this.cipherEncError = error as string;
      }
    },
    decCipher() {
      this.cipherDecError = '';
      this.cipherIn2 = '';
      try {
        switch (this.cipherMode) {
          case 'aes-ecb':
          this.cipherIn2 = doAesEcbDec(this.cipherKey, this.cipherOut2, this.isHex);
          break;
          case 'aes-ctr':
          this.cipherIn2 = doAesCtrDec(this.cipherKey, this.cipherOut2, this.cipherIv, this.isHex);
          break;
          default:
          throw new Error(`Unsupported mode: ${this.cipherMode}`);
        }
      } catch (error) {
        this.cipherDecError = error as string;
      }
    },
  }
});
</script>
