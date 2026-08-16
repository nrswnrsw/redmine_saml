(function () {
  'use strict';

  // The input of the request that triggered a SAML Sudo Mode confirmation is
  // kept in sessionStorage while the browser visits the IdP: it survives the
  // redirects, it is scoped to this one tab, and it is dropped when the tab is
  // closed. The value itself is opaque, sealed by the server.
  //
  // sessionStorage is unavailable in some privacy modes and can throw on quota
  // errors. Losing the draft is an acceptable outcome and is what the pages
  // below say; a broken page is not. Every access therefore fails silently.
  var PREFIX = 'redmine_saml_sudo_continuation:';

  function storage() {
    try {
      return window.sessionStorage || null;
    } catch (e) {
      return null;
    }
  }

  function write(key, value) {
    var store = storage();

    if (!store) {
      return;
    }

    try {
      store.setItem(PREFIX + key, value);
    } catch (e) {
      // Out of quota or storage denied: the draft is not kept.
    }
  }

  function read(key) {
    var store = storage();

    if (!store) {
      return null;
    }

    try {
      return store.getItem(PREFIX + key);
    } catch (e) {
      return null;
    }
  }

  function forget(key) {
    var store = storage();

    if (!store) {
      return;
    }

    try {
      store.removeItem(PREFIX + key);
    } catch (e) {
      // Nothing left to do; the entry expires with the tab in any case.
    }
  }

  // Sudo confirmation page: keep the continuation when the user leaves for the
  // IdP, and only then.
  function stashOnConfirm() {
    var form = document.getElementById('saml-sudo-reauth-form');

    if (!form) {
      return;
    }

    var key = form.getAttribute('data-saml-sudo-stash-key');
    var value = form.getAttribute('data-saml-sudo-stash');

    if (!key || !value) {
      return;
    }

    form.addEventListener('submit', function () {
      write(key, value);
    });
  }

  // Resume page: hand the continuation back to the server so it can render the
  // input into a form the user submits themselves.
  function restore() {
    var form = document.getElementById('saml-sudo-resume-form');

    if (!form || form.dataset.submitted === 'true') {
      return;
    }

    var key = form.getAttribute('data-saml-sudo-restore-key');
    var field = document.getElementById('saml-sudo-continuation');

    if (!key || !field) {
      return;
    }

    var value = read(key);

    if (!value) {
      return;
    }

    field.value = value;
    form.dataset.submitted = 'true';
    HTMLFormElement.prototype.submit.call(form);
  }

  // Continue page: keep the stored copy while the restored input is waiting on
  // screen. A second tab can be waiting for the one SAML confirmation already
  // in progress in another tab. Drop it only when the user explicitly submits
  // the restored form.
  function forgetOnContinue() {
    var node = document.getElementById('saml-sudo-continue');
    var form = document.getElementById('saml-sudo-continue-form');

    if (!node || !form) {
      return;
    }

    var key = node.getAttribute('data-saml-sudo-forget-key');

    if (key) {
      form.addEventListener('submit', function () {
        forget(key);
      });
    }
  }

  function run() {
    stashOnConfirm();
    restore();
    forgetOnContinue();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', run, { once: true });
  } else {
    run();
  }
}());
