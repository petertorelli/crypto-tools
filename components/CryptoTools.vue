<template lang='pug'>
.container
  ul#myTab.nav.nav-tabs(role='tablist')
    li.nav-item(role='presentation')
      button.nav-link.active(
        data-bs-toggle='tab'
        data-bs-target='#hashes'
        type='button'
        role='tab'
      ) Hashes
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#ciphers'
        type='button'
        role='tab'
      ) Ciphers
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#aead'
        type='button'
        role='tab'
      ) AEAD
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#keygen'
        type='button'
        role='tab'
      ) Key Gen.
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#keymix'
        type='button'
        role='tab'
      ) Key Mixing
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#dsa'
        type='button'
        role='tab'
      ) Sign/Verify
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#utils'
        type='button'
        role='tab'
      ) Hex&lt;&gt;Text
    li.nav-item(role='presentation')
      button.nav-link(
        data-bs-toggle='tab'
        data-bs-target='#asn1'
        type='button'
        role='tab'
      ) ASN.1/DER
  #myTabContent.tab-content
    HashWidget#hashes.tab-pane.fade.show.active(role='tabpanel')
    CipherWidget#ciphers.tab-pane.fade(role='tabpanel')
    AeadWidget#aead.tab-pane.fade(role='tabpanel')
    KeyGenWidget#keygen.tab-pane.fade(role='tabpanel')
    KeyMixingWidget#keymix.tab-pane.fade(role='tabpanel')
    DsaWidget#dsa.tab-pane.fade(role='tabpanel')
    ByteUtilsWidget#utils.tab-pane.fade(role='tabpanel')
    Asn1Widget#asn1.tab-pane.fade(role='tabpanel')
</template>

<script>
export default {
  name: 'CryptoTools',
}
</script>
