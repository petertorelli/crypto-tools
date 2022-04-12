<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Sign/Verify
  .row.mt-2
    .col-6
      select.form-select(v-model='dsaMode')
        option(value='p256') SEC-P256R1, DetK + HMAC_SHA256
        option(selected value='p384') NIST-P384, DetK + HMAC_SHA256 [sic]
        option(value='ed25519') Ed25519
        option(value='rsassl') RSA (PKCS1)
  .row.mt-2
    .col
      .alert.alert-danger(v-if='dsaError') {{dsaError}}
  .row.mt-2
    .col-6
      label Private Key ({{ dsaPrivate.length }} hex digits):
      textarea.form-control(rows=5 v-model='dsaPrivate')
    .col-6
      label Hash to sign ({{ dsaHash.length }} hex digits):
      .input-group
        input.form-control(type='text' v-model='dsaHash')
  .row.mt-2
    .col-12
      label Signature ({{ dsaSignature.length }} hex digits):
      textarea.form-control(rows=5 v-model='dsaSignature' )
  .row.mt-2
    .col
      button(@click='dsaSign()') Sign
  .row.mt-2
    .col-12
      label Public Key ({{ dsaPublicKey.length }} hex digits):
      textarea.form-control(rows=5 v-model='dsaPublicKey')
    .col-12
      p Did it verify? {{ dsaVerified ? 'Yes' : 'No' }}
  .row.mt-2
    .col
      button(@click='dsaVerify()') Verify

</template>

<script lang='ts'>

import Vue from 'vue';
import forge from 'node-forge';
import { ec as EC } from 'elliptic';
import * as ed from '@noble/ed25519';
import HASH from 'hash.js';

export default Vue.extend({
  name: 'DsaWidget',
  data() {
    return {
      dsaMode      : 'rsassl',
      dsaPrivate   : '',
      dsaPublicKey : '',
      dsaHash      : '',
      dsaSignature : '',
      dsaVerified  : false,
      dsaError     : '',
      isHex        : false,
    }
  },
  methods: {
    async dsaSign() {
      this.dsaError = '';
      try {
        switch (this.dsaMode) {
          case "p384":
          case "p256": {
              const ec = new EC(this.dsaMode);
              ec.hash = HASH.sha256;
              // 306502300298d18ecf181ad97d1e2f067ad707f0ad10c2fff611b741821b2ed52de5a59323e98baefe3bd8517dd8b5072009fc86023100efc5fbae6d43a5317ad403e8ed5328f3bbc94073f40e1c8c5ddc8419269f9157a4c0eab4f7172f0aade3e9a6cab2d91b
              // 3065023066cd28bdd6d914e563af5ef999e25a55045d4b754667659aa6a9e8c42f8bdf3cec6cbebe30881813ccb873c44eaacb56023100d56c7594b6943342268ad06c23fc87828ed3fa02de6eb68a0dd7143dae2ba96a5ef885914c5a0d493b787b065dc7d6c8
              const key = ec.keyFromPrivate(this.dsaPrivate);
              /**
               * 1. Elliptic is deterministic by default, see RFC6979
               * 2. The input message is the hash, which is converted to a
               *    BigNum and then truncated to the bit size of the curve's N.
               */
              const sig = key.sign(this.dsaHash);
              this.dsaSignature = sig.toDER('hex');
            }
            break;
          case "ed25519": {
              const signature = await ed.sign(this.dsaHash, this.dsaPrivate);
              this.dsaSignature = ed.utils.bytesToHex(signature);
            }
            break;
          case 'rsassl': {
              const pri = forge.pki.privateKeyFromAsn1(
                forge.asn1.fromDer(
                  forge.util.createBuffer(
                    forge.util.binary.hex.decode(this.dsaPrivate)))) as forge.pki.rsa.PrivateKey;
              const finalDigest = forge.util.hexToBytes(this.dsaHash);
              const signature = pri.sign(finalDigest, 'NONE');
              this.dsaSignature = Buffer.from(signature, 'ascii').toString('hex');
            }
            break;
          default:
            break;
        }
      } catch (error) {
        this.dsaError = error as string;
      }
    },
    async dsaVerify () {
      this.dsaError = '';
      try {
        switch (this.dsaMode) {
          case "p384":
          case "p256": {
            const ec = new EC(this.dsaMode);
            const pub = ec.keyFromPublic('04' + this.dsaPublicKey, 'hex');
            this.dsaVerified = pub.verify(this.dsaHash, this.dsaSignature);
          }
          break;
        case "ed25519":
          this.dsaVerified = await ed.verify(
            this.dsaSignature,
            this.dsaHash,
            this.dsaPublicKey);
          break;
        case "rsassl":{
              const pub = forge.pki.publicKeyFromAsn1(
                forge.asn1.fromDer(
                  forge.util.createBuffer(
                    forge.util.binary.hex.decode(this.dsaPublicKey)))) as forge.pki.rsa.PublicKey;
              const finalDigest = forge.util.hexToBytes(this.dsaHash);
              const signature = forge.util.hexToBytes(this.dsaSignature);
              this.dsaVerified = pub.verify(finalDigest, signature, 'NONE');
            }

          break;
        default:
          break;
        }
      } catch (error) {
        this.dsaError = error as string;
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
