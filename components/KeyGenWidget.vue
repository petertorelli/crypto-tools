<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 PKI Key Generation
      p All ECC keys are in raw format, RSA are ASN.1/DER
  .row.mt-2
    .col-4
      select.form-select(v-model='keygenMode')
        option(value='p256') ECC SECG-P256R1
        option(value='p384') ECC NIST-P384 
        option(value='curve25519') ECC C25519
        option(value='ed25519') Ed25519
        option(value='2048') RSA 2048
        option(value='3072') RSA 3072
        option(value='4096') RSA 4096
  .row.mt-2
    .col
      .alert.alert-danger.mt-2(v-if='keygenError') {{keygenError}}
  .row.mt-2
    .col-6.mt-2
      label Private Key ({{ keygenPrivate.length }} digits):
      textarea.form-control(rows=5 v-model='keygenPrivate' disabled)
    .col-6.mt-2
      label Public Key ({{ keygenPublic.length }} digits):
      textarea.form-control(rows=5 :value='keygenPublic' disabled)
  .row.mt-2
    .col-6.mt-2
      label Private Key X:
      textarea.form-control(v-model='keygenPrivateX' disabled)
    .col-6.mt-2
      label Public Key X:
      textarea.form-control(:value='keygenPublicX' disabled)
    .col-6.mt-2
      label Private Key Y:
      textarea.form-control(v-model='keygenPrivateY' disabled)
    .col-6.mt-2
      label Public Key Y:
      textarea.form-control(:value='keygenPublicY' disabled)
  .row.mt-2
    .col
      button(@click='genKey()') Generate

</template>

<script lang='ts'>

import Vue from 'vue';
import forge from 'node-forge';
import { ec as EC } from 'elliptic';
import * as ed from '@noble/ed25519';

export default Vue.extend({
  name: 'KeyGenWidget',
  data() {
    return {
      keygenMode     : 'p256',
      keygenPrivate  : '',
      keygenPublic   : '',
      keygenError    : '',
      keygenPublicX  : '',
      keygenPublicY  : '',
      keygenPrivateX : '',
      keygenPrivateY : '',
    }
  },
  methods: {
    async genKey() {
      try {
        this.keygenPrivate = '';
        this.keygenPrivateX = '';
        this.keygenPrivateY = '';
        this.keygenPublic = '';
        this.keygenPublicX = '';
        this.keygenPublicY = '';
        switch (this.keygenMode) {
          case "p256":
          case "p384": {
              const ec = new EC(this.keygenMode);
              const key = ec.genKeyPair();
              const pad = this.keygenMode === 'p256' ? 64 : 96;
              this.keygenPublicX = key.getPublic().getX().toString('hex').padStart(pad, '0');
              this.keygenPublicY = key.getPublic().getY().toString('hex').padStart(pad, '0');
              this.keygenPublic = this.keygenPublicX + this.keygenPublicY;
              this.keygenPrivate = key.getPrivate().toString('hex');
            }
            break;
          case "curve25519": {
              const pri = ed.utils.randomPrivateKey();
              const pub = ed.curve25519.scalarMultBase(pri);
              this.keygenPrivate = Buffer.from(pri).toString('hex');
              this.keygenPublic = Buffer.from(pub).toString('hex');
            }
            break;
          case "ed25519": {
              const pri = ed.utils.randomPrivateKey();
              const pub = await ed.getPublicKey(pri);
              this.keygenPrivate = Buffer.from(pri).toString('hex');
              this.keygenPublic = Buffer.from(pub).toString('hex');
            }
            break;
          case "2048":
          case "3072":
          case "4096":
            // eslint-disable-next-line no-lone-blocks
            {
              forge.pki.rsa.generateKeyPair({
                  bits: parseInt(this.keygenMode)
                }, (err, keypair) => {
                if (err) {
                  throw err;
                }
                const pub = forge.pki.publicKeyToAsn1(keypair.publicKey);
                const pri = forge.pki.privateKeyToAsn1(keypair.privateKey);
                const pubDer = forge.asn1.toDer(pub).toHex();
                const priDer = forge.asn1.toDer(pri).toHex();
                this.keygenPublic = pubDer;
                this.keygenPrivate = priDer;
              });
            }
            break;
          default:
            throw new Error(`Unsupported mode: ${this.keygenMode}`);
        }
      } catch (error) {
        this.keygenError = error as string;
      }
    },
  }
});
</script>
