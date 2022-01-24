<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Hashes
  .row.mt-2
    .col-3
      select.form-select(v-model='hashMode')
        option(selected value='sha256') SHA-256 
        option(value='sha384') SHA-384
        option(value='sha512') SHA-512
  .row.mt-2
    .col-6
      label Input ({{hashIn.length}}):
      textarea.form-control(v-model='hashIn' rows=5)
    .col-6
      label Digest ({{hashOut.length}}):
      textarea.form-control(:value='hashOut' rows=5 disabled)
  .row.mt-2
    .col
      button(@click='computeHash()') Hash
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
      hashIn      : 'Message to hash',
      hashOut     : '',
    }
  },
  methods: {
    computeHash() {
      if (!this.hashIn) {
        return;
      }
      const i = this.hashIn;
      const hashMode = this.hashMode as HashMode; // oh, typscript... :)
      this.hashOut = forge.md[hashMode].create().update(i).digest().toHex();
    },  
  }
});
</script>
