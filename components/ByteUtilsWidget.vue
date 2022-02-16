<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Utilities
  .row.mt-2
    .col
      .alert.alert-danger(v-if='utilError') {{utilError}}
  .row.mt-2
    .col-6
      label Text In ({{textIn.length}}):
      textarea.form-control(v-model='textIn' rows=5)
    .col-6
      label Hex Out ({{hexOut.length}}):
      textarea.form-control(v-model='hexOut' rows=5 )
    .col-12
      label Code Out:
      textarea.form-control(v-model='codeOut' rows=5).code
  .row.mt-2
    .col
      button(@click='t2h()') Text to Hex
      button(@click='h2c()') Hex to Code
      button(@click='c2h()') Code to Hex
</template>

<script lang='ts'>

import Vue from 'vue';
import { sprintf } from 'sprintf-js';

export default Vue.extend({
  name: 'ByteUtilsWidget',
  data() {
    return {
      textIn: 'This is a long line of test, more than 16 chars.',
      hexIn: '',
      textOut: '',
      hexOut: '',
      codeOut: '',
      utilError: '',
    }
  },
  methods: {
    t2h() {
      this.hexOut = '';
      const buf = Buffer.from(this.textIn, 'ascii');
      const hex = buf.toString('hex');
      this.hexOut = hex;
    },
    h2c() {
      this.codeOut = '';
      this.utilError = '';
      try {
        const buf = Buffer.from(this.hexOut, 'hex');
        for (let x=1; x<buf.length+1; ++x) {
          this.codeOut += sprintf("0x%02x,", buf[x-1]);
          if ((x) % 16 === 0) {
            this.codeOut += '\n';
          }
        }
      } catch (error) {
        this.utilError = error as string;
      }
    },
    c2h() {
      this.hexOut = '';
      this.utilError = '';
      this.hexOut = this.codeOut;
      this.hexOut = this.hexOut.replace(/0x/gi, '');
      this.hexOut = this.hexOut.replace(/[^0-9a-f]/gi, '');
    }
  }
});
</script>
<style scoped>
textarea, input {
  font-family: consolas;
}
</style>
