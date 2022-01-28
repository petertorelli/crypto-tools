<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Key Mixing
  .row.mt-2
    .col-4
      select.form-select(v-model='kxMode')
        option(value='p256') ECDH SEC-P256R1
        option(value='p384') ECDH NIST-P384 
        option(value='x25519') X25519
  .row.mt-2
    .col
      .alert.alert-danger.mt-2(v-if='kxError') {{kxError}}
  .row.mt-2
    .col-6.mt-2
      label Private Key ({{ kxPrivate ? kxPrivate.length : 0 }} digits):
      textarea.form-control(rows=5 v-model='kxPrivate')
    .col-6.mt-2
      label Peer Public Key ({{ kxPeerPublic ? kxPeerPublic.length : 0 }} digits):
      textarea.form-control(rows=5 v-model='kxPeerPublic')
  .row.mt-2
    .col-12.mt-2
      label Shared ({{ kxShared ? kxShared.length : 0 }} digits):
      textarea.form-control(rows=5 :value='kxShared' disabled)
  .row.mt-2
    .col
      button(@click='kxMix()') Mix

</template>

<script lang='ts'>

import Vue from 'vue';
import { ec as EC } from 'elliptic';
import * as ed from '@noble/ed25519';

function doEcdh(curve: string, pri: string, pub: string) {
  const ec = new EC(curve);
  const key1 = ec.keyFromPrivate(pri, 'hex');
  const key2 = ec.keyFromPublic('04' + pub, 'hex');
  const shared = key1.derive(key2.getPublic()).toString(16);
  return shared;
}

export default Vue.extend({
  name: 'KeyMixingWidget',
  data() {
    return {
      kxMode       : 'p256',
      kxPrivate    : '',
      kxPeerPublic : '',
      kxShared     : '',
      kxError      : '',
    }
  },
  methods: {
    async kxMix() {
      this.kxError = '';
      try {
        switch (this.kxMode) {
          case 'p384':
          case 'p256':
            this.kxShared = doEcdh(this.kxMode, this.kxPrivate, this.kxPeerPublic);
            break;
          case "x25519":  {
       //       const m = await ed.getSharedSecret(this.kxPrivate, this.kxPeerPublic);
              const m = await ed.curve25519.scalarMult(this.kxPrivate, this.kxPeerPublic);
              this.kxShared = Buffer.from(m).toString('hex');
            }
            break;
          default:
            break;
        }
      } catch (error) {
        this.kxError = error as string;
      }
    },
  }
});
</script>
