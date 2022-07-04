<template lang='pug'>
.container
  h1.mt-2 Hashes
  .row.mt-2
    .col
      .alert.alert-danger(v-if='hashError') {{hashError}}
  .row.mt-2
    .col-sm-12.col-md-3
      select.form-select(v-model='hashMode')
        option(selected value='sha256') SHA-256 
        option(value='sha384') SHA-384
        option(value='sha512') SHA-512
  .row.mt-2
    .col-sm-12.col-md-6
      label Input ({{hashIn.length}}  {{ isHex ? "hex digits" : "characters" }}):
      textarea.form-control(v-model='hashIn' rows=5)
    .col-sm-12.col-md-6
      label Digest ({{hashOut.length}}):
      textarea.form-control(:value='hashOut' rows=5 disabled)
  .row.mt-2
    .col
      .form-check.form-switch
        input.form-check-input(type='checkbox' v-model='isHex')
        label.form-check-label Input is {{ isHex ? 'Hex' : 'ASCII' }}
  .row.mt-2
    .col
      button(@click='computeHash()') Hash
  .mb-3
</template>

<script lang='ts'>

import Vue from 'vue';
import forge from 'node-forge';

type HashMode = 'sha256' | 'sha384' | 'sha512';

export default Vue.extend({
  name: 'HashWidget',
  data() {
    return {
      hashMode    : 'sha256' as HashMode,
      hashIn      : 'Some text',
      hashOut     : '',
      hashError   : '',
      isHex       : false,
    }
  },
  methods: {
    computeHash() {
      if (!this.hashIn) {
        return;
      }
      this.hashError = '';
      try {
        let i = this.hashIn;
        if (this.isHex) {
          if (!this.hashIn.match(/^[0-9a-fA-F]+$/)) {
            throw new Error('Input is not valid hex');
          }
          i = forge.util.hexToBytes(this.hashIn);
        }
        const hashMode = this.hashMode as HashMode; // oh, typscript... :)
        this.hashOut = forge.md[hashMode].create().update(i).digest().toHex();
      } catch (error) {
        this.hashError = error as string;
      }
    },  
  }
});
</script>
<style scoped>
textarea, input {
  font-family: consolas;
}
</style>
