<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Utilities
  .row.mt-2
    .col
      .alert.alert-danger(v-if='utilError') {{utilError}}
  .row.mt-2
    .col-12
      label Text ({{textData.length}}):
      textarea.form-control(v-model='textData' rows=5)
    .col-12.mt-2
      button.me-2(@click='t2h()') Text to Hex
    .col-12.mt-2
      label Hex ({{hexData.length}}):
      textarea.form-control(v-model='hexData' rows=5 )
    .col-12.mt-2
      button.me-2(@click='h2t()') Hex to Text
      button.me-2(@click='h2c()') Hex to Code
    .col-12.mt-2
      label Code:
      textarea.form-control(v-model='codeData' rows=5).code
    .col-12.mt-2
      button.me-2(@click='c2h()') Code to Hex
</template>

<script lang='ts'>

import Vue from 'vue';
import { sprintf } from 'sprintf-js';

export default Vue.extend({
  name: 'ByteUtilsWidget',
  data() {
    return {
      textData: 'This is a long line of test, more than 16 chars.',
      hexData: '',
      codeData: '',
      utilError: '',
    }
  },
  methods: {
    h2t() {
      try {
        this.utilError = '';
        this.textData = '';
        const buf = Buffer.from(this.hexData, 'hex');
        const text = buf.toString('ascii');
        this.textData = text;
      } catch (error) {
        this.utilError = String(error);
      }
    },
    t2h() {
      this.hexData = '';
      const buf = Buffer.from(this.textData, 'ascii');
      const hex = buf.toString('hex');
      this.hexData = hex;
    },
    h2c() {
      this.codeData = '';
      this.utilError = '';
      try {
        const buf = Buffer.from(this.hexData, 'hex');
        for (let x=1; x<buf.length+1; ++x) {
          this.codeData += sprintf("0x%02x,", buf[x-1]);
          if ((x) % 16 === 0) {
            this.codeData += '\n';
          }
        }
      } catch (error) {
        this.utilError = error as string;
      }
    },
    c2h() {
      this.hexData = '';
      this.utilError = '';
      this.hexData = this.codeData;
      this.hexData = this.hexData.replace(/0x/gi, '');
      this.hexData = this.hexData.replace(/[^0-9a-f]/gi, '');
    }
  }
});
</script>
<style scoped>
textarea, input {
  font-family: consolas;
}
</style>
