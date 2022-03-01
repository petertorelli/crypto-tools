<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 Sign/Verify
  .row.mt-2
    .col-6
      select.form-select(v-model='dsaMode')
        option(value='p256') SEC-P256R1, RFC6979 + SHA256
        option(selected value='p384') NIST-P384, RFC6979 + SHA256 [sic]
        option(value='ed25519') Ed25519
        option(value='rsa') RSA (PKCS1 v1.5)
  .row.mt-2
    .col
      .alert.alert-danger(v-if='dsaError') {{dsaError}}
  .row.mt-2
    .col-6
      label Private Key ({{ dsaPrivate.length }} hex digits):
      textarea.form-control(rows=5 v-model='dsaPrivate')
    .col-6(v-if='dsaMode == "rsa" || dsaMode == "ed25519"')
      label Message to sign ({{ dsaMessage.length }} {{ isHex ? "hex digits" : "characters" }}):
      textarea.form-control(rows=5 v-model='dsaMessage')
  .row.mt-2(v-if='dsaMode == "rsa" || dsaMode == "ed25519"')
    .col-6
    .col-6
      .form-check.form-switch
        input.form-check-input(type='checkbox' v-model='isHex')
        label.form-check-label Input is {{ isHex ? 'Hex' : 'ASCII' }}
  .row.mt-2()
    .col-12
      label Hash to sign ({{ dsaHash.length }} hex digits):
      .input-group
        input.form-control(type='text' v-model='dsaHash')
  .row.mt-2(v-if='dsaMode == "ed25519"')
    .col-12
      label Signature (Raw: {{ dsaRawBytes.length }} hex digits):
      textarea.form-control(rows=2 v-model='dsaRawBytes' disabled)
  .row.mt-2
    .col-12
      label Signature ({{ dsaSignature.length }} hex digits):
      textarea.form-control(rows=5 v-model='dsaSignature' disabled)
  //-.row.mt-2
    .col-12
      label Raw Bytes ({{ dsaRawBytes.length }} digits):
      textarea.form-control(rows=5 v-model='dsaRawBytes' disabled)
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
      dsaMode      : 'rsa',
      dsaPrivate   : '',
      dsaPublicKey : '',
      dsaMessage   : 'test',
      dsaHash      : '',
      dsaSignature : '',
      dsaRawBytes  : '',
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
            /*
              let m;
              if (this.isHex) {
                m = this.dsaMessage;
              } else {
                m = forge.util.hexToBytes(this.dsaMessage);
              }
              ec.hash = HASH.sha256;
            */
              const ec = new EC(this.dsaMode);
              const key = ec.keyFromPrivate(this.dsaPrivate);
              ec.hash = HASH.sha256;
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
              let m;
              if (this.isHex) {
                m = Buffer.from(this.dsaMessage, 'hex');
              } else {
                m = this.dsaMessage;
              }
              const pri = this.dsaPrivate;
              const signature = await ed.sign(Buffer.from(m), pri);
              const r = signature.slice(0, 32);
              const s = signature.slice(32, 64);
              let R = ed.utils.bytesToHex(r);
              let S = ed.utils.bytesToHex(s);
              if (r[0] & 0x80) {
                R = '00' + R;
              }
              if (s[0] & 0x80) {
                S = '00' + S;
              }
              const Rlen = R.length / 2;
              const Slen = S.length / 2;
              const tlen = Rlen + Slen + 4;
              const DER
                = '30' + tlen.toString(16)
                + '02' + Rlen.toString(16) + R
                + '02' + Slen.toString(16) + S;
              this.dsaSignature = DER;
              this.dsaRawBytes = ed.utils.bytesToHex(signature);
            }
            break;
          case 'rsa': {
              const pri = forge.pki.privateKeyFromAsn1(
                forge.asn1.fromDer(
                  forge.util.createBuffer(
                    forge.util.binary.hex.decode(this.dsaPrivate)))) as forge.pki.rsa.PrivateKey;
              const md = forge.md.sha256.create();
              if (this.isHex) {
                md.update(forge.util.hexToBytes(this.dsaMessage));
              } else {
                md.update(this.dsaMessage, 'utf8');
              }
              const signature = pri.sign(md, 'RSASSA-PKCS1-V1_5');
              this.dsaSignature = Buffer.from(signature, 'ascii').toString('hex');
              // Without this, verify fails.
              this.dsaHash = md.digest().toHex();
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
            /*
            let m;
            if (this.isHex) {
              m = this.dsaMessage;
            } else {
              m = forge.util.hexToBytes(this.dsaMessage);
            }
            const ec = new EC(this.dsaMode);
            ec.hash = HASH.sha256;
            const key = ec.keyFromPrivate(this.dsaPrivate);
            // Elliptic is deterministic by default.
            const sig = key.sign(m);
            this.dsaSignature = sig.toDER('hex');
            const pub = ec.keyFromPublic('04' + this.dsaPublicKey, 'hex');
            */
            const ec = new EC(this.dsaMode);
            const pub = ec.keyFromPublic('04' + this.dsaPublicKey, 'hex');
            this.dsaVerified = pub.verify(this.dsaHash, this.dsaSignature);
          }
          break;
        case "ed25519": {
            const m = Buffer.from(this.dsaMessage);
            const pub = this.dsaPublicKey;
            const sig = this.dsaSignature;
            const der = Buffer.from(sig, 'hex');
            let R = der.slice(4, der[3] + 4).toString('hex');
            let S = der.slice(4 + der[3] + 2, der.length).toString('hex');
            R = R.replace(/^00/, '');
            S = S.replace(/^00/, '');
            this.dsaVerified = await ed.verify(R + S, m, pub);
          }
          break;
        case 'rsa': {
            const md = forge.md.sha256.create();
            md.update(this.dsaMessage, 'utf8');
            const pub = forge.pki.publicKeyFromAsn1(
              forge.asn1.fromDer(
                forge.util.createBuffer(
                  forge.util.binary.hex.decode(this.dsaPublicKey)))) as forge.pki.rsa.PublicKey;
            const sig = forge.util.hexToBytes(this.dsaSignature);
            // this error should go away when we move this to a TS library.
            this.dsaVerified = pub.verify(md.digest().bytes(),sig);
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
