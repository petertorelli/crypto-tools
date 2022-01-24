<template lang='pug'>
.container
  .row.mt-2
    .col
      h1 DSA
  .row.mt-2
    .col-6
      select.form-select(v-model='dsaMode')
        option(selected value='p384') ECDSA NIST-P384 / SHA256 (Det.)
        option(value='p256') ECDSA SEC-P256R1 / SHA256 (Det.)
        option(value='ed25519') Ed25519
        option(value='rsa') RSA
  .row.mt-2
    .col
      .alert.alert-danger(v-if='dsaError') {{dsaError}}
  .row.mt-2
    .col-6
      label Private Key ({{ dsaPrivate ? dsaPrivate.length : 0 }} digits):
      textarea.form-control(rows=5 v-model='dsaPrivate')
    .col-6
      label Message ({{ dsaMessage ? dsaMessage.length : 0 }} digits):
      textarea.form-control(rows=5 v-model='dsaMessage')
  .row.mt-2
    .col-12
      label Hash ({{ dsaHash ? dsaHash.length : 0 }} digits):
      textarea.form-control(rows=1 v-model='dsaHash')
  .row.mt-2
    .col-12
      label Signature (ASN.1/DER: {{ dsaSignature ? dsaSignature.length : 0 }} digits):
      textarea.form-control(rows=5 v-model='dsaSignature')
  .row.mt-2
    .col
      button(@click='dsaSign()') Sign
  .row.mt-2
    .col-12
      label Public Key ({{ dsaPublicKey ? dsaPublicKey.length : 0 }} digits):
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
      dsaVerified  : false,
      dsaError     : '',
    }
  },
  methods: {
    async dsaSign() {
      this.dsaError = '';
      try {
        switch (this.dsaMode) {
          case "p384":
          case "p256": {
              const m = this.dsaMessage;
              const hash = forge.md.sha256.create().update(m).digest().toHex();
              this.dsaHash = hash;
              const ec = new EC(this.dsaMode);
              const key = ec.keyFromPrivate(this.dsaPrivate);
              const sig = key.sign(hash);
              this.dsaSignature = sig.toDER('hex');
            }
            break;
          case "ed25519": {
              const m = this.dsaMessage;
              const hash = forge.md.sha256.create().update(m).digest().toHex();
              this.dsaHash = hash;
              const pri = this.dsaPrivate;
              const signature = await ed.sign(hash, pri);
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
            }
            break;
          case 'rsa': {
              const pri = forge.pki.privateKeyFromAsn1(
                forge.asn1.fromDer(
                  forge.util.createBuffer(
                    forge.util.binary.hex.decode(this.dsaPrivate)))) as forge.pki.rsa.PrivateKey;
              const md = forge.md.sha256.create();
              const hash = md.update(this.dsaMessage, 'utf8');
              // this error should go away when we move this to a TS library.
              const signature = pri.sign(hash);
              // N.B. I used 'utf8' as the encoder and it mixed in 3 byte chars.
              this.dsaSignature = Buffer.from(signature, 'ascii').toString('hex');
              this.dsaHash = hash.digest().toHex();
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
            const hash = this.dsaHash;
            const pub = ec.keyFromPublic('04' + this.dsaPublicKey, 'hex');
            this.dsaVerified = pub.verify(hash, this.dsaSignature);
          }
          break;
        case "ed25519": {
            const hash = this.dsaHash;
            const pub = this.dsaPublicKey;
            const sig = this.dsaSignature;
            const der = Buffer.from(sig, 'hex');
            let R = der.slice(4, der[3] + 4).toString('hex');
            let S = der.slice(4 + der[3] + 2, der.length).toString('hex');
            R = R.replace(/^00/, '');
            S = S.replace(/^00/, '');
            this.dsaVerified = await ed.verify(R + S, hash, pub);
          }
          break;
        case 'rsa': {
            const pub = forge.pki.publicKeyFromAsn1(
              forge.asn1.fromDer(
                forge.util.createBuffer(
                  forge.util.binary.hex.decode(this.dsaPublicKey)))) as forge.pki.rsa.PublicKey;
            const hash = forge.util.hexToBytes(this.dsaHash);
            const sig = forge.util.hexToBytes(this.dsaSignature);
            // this error should go away when we move this to a TS library.
            this.dsaVerified = pub.verify(hash,sig);
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
