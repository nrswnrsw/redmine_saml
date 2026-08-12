(function () {
  'use strict';

  function submitSamlRequest() {
    var form = document.getElementById('saml-request-form');

    if (!form || form.dataset.submitted === 'true') {
      return;
    }

    form.dataset.submitted = 'true';
    HTMLFormElement.prototype.submit.call(form);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', submitSamlRequest, { once: true });
  } else {
    submitSamlRequest();
  }
}());
