const { test, expect } = require('@playwright/test');
const zlib = require('zlib');

const REDMINE_ORIGIN = 'http://127.0.0.1:3000';
const KEYCLOAK_ORIGIN = 'http://127.0.0.1:8080';
const KEYCLOAK_SAML_PATH = '/realms/redmine-e2e/protocol/saml';
const REDMINE_CALLBACK_PATH = '/auth/saml/callback';
const REDMINE_ENTITY_ID = `${REDMINE_ORIGIN}/auth/saml/metadata`;
const SAML_NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

const KEYCLOAK_USERNAME = 'samltest';
const KEYCLOAK_PASSWORD = 'samltest-password';

// A plain Redmine page that require_sudo_mode protects for any signed in user,
// so Sudo Mode can be exercised by navigating rather than by submitting a form.
const SUDO_PROTECTED_PATH = '/my/api_key';
const SUDO_REAUTH_FORM = '#saml-sudo-reauth-form';
const SUDO_CONTINUATION_PREFIX = 'redmine_saml_sudo_continuation:';

// The Sudo Mode window the E2E workflow configures, in milliseconds. Redmine
// only refreshes the window on requests that actually use Sudo Mode, so a
// probe that still finds it active pushes it forward again; waiting for it to
// lapse therefore has to probe more slowly than the window itself.
const SUDO_WINDOW_MS = 10000;

async function signInAtKeycloak(page) {
  await page.locator('#username').fill(KEYCLOAK_USERNAME);
  await page.locator('#password').fill(KEYCLOAK_PASSWORD);
  await page.locator('#kc-login').click();
}

// Keycloak may answer a new AuthnRequest straight from its existing SSO
// session, or ask for the credentials again. Both outcomes are correct, since
// the plugin never asks for ForceAuthn, so whichever happens first decides.
async function signInAtKeycloakIfPrompted(page, callbackRequestPromise) {
  const promptShown = page.locator('#kc-login')
    .waitFor({ state: 'visible' })
    .then(() => true)
    .catch(() => false);
  const answeredFromSsoSession = callbackRequestPromise.then(() => false);

  if (!await Promise.race([promptShown, answeredFromSsoSession])) {
    return false;
  }

  await signInAtKeycloak(page);

  return true;
}

async function openSudoProtectedPage(page) {
  await page.goto(`${REDMINE_ORIGIN}${SUDO_PROTECTED_PATH}`, { waitUntil: 'domcontentloaded' });
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function samlParameter(request, name) {
  const url = new URL(request.url());

  if (request.method() === 'GET') {
    return url.searchParams.get(name);
  }

  return new URLSearchParams(request.postData() || '').get(name);
}

function isKeycloakSamlRequest(request, parameter) {
  const url = new URL(request.url());

  return url.origin === KEYCLOAK_ORIGIN &&
    url.pathname === KEYCLOAK_SAML_PATH &&
    samlParameter(request, parameter);
}

function isRedmineSamlRequestPhase(request) {
  const url = new URL(request.url());

  return url.origin === REDMINE_ORIGIN &&
    url.pathname === '/auth/saml' &&
    request.method() === 'POST';
}

function isRedmineSamlCallback(request) {
  const url = new URL(request.url());

  return url.origin === REDMINE_ORIGIN &&
    url.pathname === REDMINE_CALLBACK_PATH &&
    samlParameter(request, 'SAMLResponse');
}

function isRedmineSlsRequest(request, parameter) {
  const url = new URL(request.url());

  return url.origin === REDMINE_ORIGIN &&
    url.pathname === '/auth/saml/sls' &&
    samlParameter(request, parameter);
}

function isRedmineLogoutRequest(request) {
  const url = new URL(request.url());

  return url.origin === REDMINE_ORIGIN &&
    url.pathname === '/logout' &&
    request.method() === 'POST';
}

function decodeRedirectMessage(message) {
  return zlib.inflateRawSync(Buffer.from(message, 'base64')).toString('utf8');
}

function decodePostMessage(message) {
  return Buffer.from(message, 'base64').toString('utf8');
}

test('login to Redmine through real SAML IdP', async ({ page }) => {
  let redmineRequestPhaseCount = 0;
  page.on('request', request => {
    if (isRedmineSamlRequestPhase(request)) {
      redmineRequestPhaseCount += 1;
    }
  });
  const redmineRequestPhasePromise = page.waitForRequest(isRedmineSamlRequestPhase);
  const redmineRequestPhaseResponsePromise = page.waitForResponse(
    response => isRedmineSamlRequestPhase(response.request())
  );
  const keycloakAuthnRequestPromise = page.waitForRequest(
    request => isKeycloakSamlRequest(request, 'SAMLRequest')
  );

  await page.goto(`${REDMINE_ORIGIN}/login`, { waitUntil: 'commit' });

  const [redmineRequestPhase, redmineRequestPhaseResponse, keycloakAuthnRequest] = await Promise.all([
    redmineRequestPhasePromise,
    redmineRequestPhaseResponsePromise,
    keycloakAuthnRequestPromise
  ]);

  expect(redmineRequestPhase.method()).toBe('POST');
  const requestPhaseParameters = new URLSearchParams(redmineRequestPhase.postData() || '');
  expect(requestPhaseParameters.get('authenticity_token')).toBeTruthy();
  expect(redmineRequestPhaseResponse.status()).toBe(302);
  const requestPhaseLocation = redmineRequestPhaseResponse.headers().location;
  expect(requestPhaseLocation).toContain(`${KEYCLOAK_ORIGIN}${KEYCLOAK_SAML_PATH}`);
  expect(new URL(requestPhaseLocation).searchParams.get('SAMLRequest')).toBeTruthy();

  expect(keycloakAuthnRequest.method()).toBe('GET');
  const authnRequestXml = decodeRedirectMessage(
    samlParameter(keycloakAuthnRequest, 'SAMLRequest')
  );
  expect(authnRequestXml).toMatch(/<(?:[\w-]+:)?AuthnRequest\b/);
  expect(authnRequestXml).toMatch(
    new RegExp(`\\bDestination=['"]${escapeRegExp(KEYCLOAK_ORIGIN + KEYCLOAK_SAML_PATH)}['"]`)
  );
  expect(authnRequestXml).toMatch(
    new RegExp(`\\bAssertionConsumerServiceURL=['"]${escapeRegExp(REDMINE_ORIGIN + REDMINE_CALLBACK_PATH)}['"]`)
  );
  expect(authnRequestXml).toMatch(
    new RegExp(`<(?:[\\w-]+:)?Issuer[^>]*>${escapeRegExp(REDMINE_ENTITY_ID)}</(?:[\\w-]+:)?Issuer>`)
  );
  expect(authnRequestXml).toMatch(
    new RegExp(`\\bFormat=['"]${escapeRegExp(SAML_NAME_ID_FORMAT)}['"]`)
  );

  const authnRequestId = authnRequestXml.match(/\bID=['"]([^'"]+)['"]/);
  expect(authnRequestId).not.toBeNull();

  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );

  const redmineCallbackPromise = page.waitForRequest(isRedmineSamlCallback);
  await signInAtKeycloak(page);

  const redmineCallback = await redmineCallbackPromise;
  expect(redmineCallback.method()).toBe('POST');
  const samlResponseXml = decodePostMessage(
    samlParameter(redmineCallback, 'SAMLResponse')
  );
  expect(samlResponseXml).toMatch(/<(?:[\w-]+:)?Response\b/);
  expect(samlResponseXml).toMatch(/<(?:[\w-]+:)?Signature\b/);
  expect(samlResponseXml).toMatch(
    new RegExp(`\\bDestination=['"]${escapeRegExp(REDMINE_ORIGIN + REDMINE_CALLBACK_PATH)}['"]`)
  );
  expect(samlResponseXml).toMatch(
    new RegExp(`\\bInResponseTo=['"]${escapeRegExp(authnRequestId[1])}['"]`)
  );

  await expect(page).toHaveURL(
    /127\.0\.0\.1:3000\/my\/page/
  );

  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveText('samltest');
  expect(redmineRequestPhaseCount).toBe(1);
});

test('confirm Redmine Sudo Mode through real SAML re-authentication', async ({ page }) => {
  test.setTimeout(90000);

  // A real SAML login, so the Redmine session is a SAML one.
  await page.goto(`${REDMINE_ORIGIN}/login`, { waitUntil: 'commit' });
  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );
  await signInAtKeycloak(page);
  await expect(page).toHaveURL(
    /127\.0\.0\.1:3000\/my\/page/
  );
  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveText('samltest');

  // Signing in activates Sudo Mode, so the protected page opens right away.
  await openSudoProtectedPage(page);
  await expect(page).toHaveURL(`${REDMINE_ORIGIN}${SUDO_PROTECTED_PATH}`);
  await expect(page.locator(SUDO_REAUTH_FORM)).toHaveCount(0);

  // Then the Sudo Mode window lapses and the same page asks for confirmation.
  await expect.poll(async () => {
    await openSudoProtectedPage(page);

    return page.locator(SUDO_REAUTH_FORM).count();
  }, { intervals: [SUDO_WINDOW_MS + 1000], timeout: 60000 }).toBe(1);

  // The SAML confirmation, not the local Redmine password prompt.
  await expect(page.locator(SUDO_REAUTH_FORM)).toHaveAttribute('action', '/saml/sudo_reauth');
  await expect(page.locator('input[name=sudo_password]')).toHaveCount(0);

  const sudoAuthnRequestPromise = page.waitForRequest(
    request => isKeycloakSamlRequest(request, 'SAMLRequest')
  );
  const sudoCallbackPromise = page.waitForRequest(isRedmineSamlCallback);

  await page.locator(`${SUDO_REAUTH_FORM} button[type=submit]`).click();

  // The confirmation reaches the real IdP as an ordinary AuthnRequest.
  const sudoAuthnRequest = await sudoAuthnRequestPromise;
  const sudoAuthnRequestXml = decodeRedirectMessage(
    samlParameter(sudoAuthnRequest, 'SAMLRequest')
  );
  expect(sudoAuthnRequestXml).toMatch(/<(?:[\w-]+:)?AuthnRequest\b/);
  expect(sudoAuthnRequestXml).toMatch(
    new RegExp(`\\bAssertionConsumerServiceURL=['"]${escapeRegExp(REDMINE_ORIGIN + REDMINE_CALLBACK_PATH)}['"]`)
  );
  expect(sudoAuthnRequestXml).toMatch(
    new RegExp(`<(?:[\\w-]+:)?Issuer[^>]*>${escapeRegExp(REDMINE_ENTITY_ID)}</(?:[\\w-]+:)?Issuer>`)
  );
  // The plugin adds no authentication condition of its own for a confirmation.
  expect(sudoAuthnRequestXml).not.toMatch(/\bForceAuthn=/);
  expect(sudoAuthnRequestXml).not.toMatch(/\bIsPassive=/);

  const sudoRequestId = sudoAuthnRequestXml.match(/\bID=['"]([^'"]+)['"]/);
  expect(sudoRequestId).not.toBeNull();
  const sudoRelayState = samlParameter(sudoAuthnRequest, 'RelayState');
  expect(sudoRelayState).toMatch(/^redmine_saml_sudo\//);

  await signInAtKeycloakIfPrompted(page, sudoCallbackPromise);

  // The IdP answers to the existing callback endpoint, for this AuthnRequest.
  const sudoCallback = await sudoCallbackPromise;
  expect(sudoCallback.method()).toBe('POST');
  expect(samlParameter(sudoCallback, 'RelayState')).toBe(sudoRelayState);
  const sudoResponseXml = decodePostMessage(
    samlParameter(sudoCallback, 'SAMLResponse')
  );
  expect(sudoResponseXml).toMatch(/<(?:[\w-]+:)?Response\b/);
  expect(sudoResponseXml).toMatch(/<(?:[\w-]+:)?Signature\b/);
  expect(sudoResponseXml).toMatch(
    new RegExp(`\\bDestination=['"]${escapeRegExp(REDMINE_ORIGIN + REDMINE_CALLBACK_PATH)}['"]`)
  );
  expect(sudoResponseXml).toMatch(
    new RegExp(`\\bInResponseTo=['"]${escapeRegExp(sudoRequestId[1])}['"]`)
  );

  // Back in Redmine, as the same user and without an error.
  await expect(page).toHaveURL(`${REDMINE_ORIGIN}/`);
  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveText('samltest');
  // A rejected confirmation would land on the same page with this flash, so
  // its absence is what separates success from rejection here.
  await expect(page.locator('#flash_error')).toHaveCount(0);

  // Sudo Mode is fresh again, so the protected page opens without a prompt.
  await openSudoProtectedPage(page);
  await expect(page).toHaveURL(`${REDMINE_ORIGIN}${SUDO_PROTECTED_PATH}`);
  await expect(page.locator(SUDO_REAUTH_FORM)).toHaveCount(0);
  await expect(page.locator('input[name=sudo_password]')).toHaveCount(0);
});

test('resume a protected account update only after explicit confirmation', async ({ page }) => {
  test.setTimeout(90000);

  await page.goto(`${REDMINE_ORIGIN}/login`, { waitUntil: 'commit' });
  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );
  await signInAtKeycloak(page);
  await expect(page).toHaveURL(
    /127\.0\.0\.1:3000\/my\/page/
  );

  await page.goto(`${REDMINE_ORIGIN}/my/account`, { waitUntil: 'domcontentloaded' });
  const originalFirstName = await page.locator('#user_firstname').inputValue();
  const continuedFirstName = `SAML cont ${Date.now()}`;
  await page.locator('#user_firstname').fill(continuedFirstName);

  // Let the E2E-only ten second Sudo window lapse, then submit an actual
  // protected PUT carrying unsaved form input.
  await page.waitForTimeout(SUDO_WINDOW_MS + 1000);
  await page.locator('#my_account_form input[type=submit]:visible').click();

  await expect(page.locator(SUDO_REAUTH_FORM)).toHaveCount(1);
  await expect(page.locator('input[name=sudo_password]')).toHaveCount(0);
  const continuationKey = await page.locator(SUDO_REAUTH_FORM)
    .getAttribute('data-saml-sudo-stash-key');
  const sealedContinuation = await page.locator(SUDO_REAUTH_FORM)
    .getAttribute('data-saml-sudo-stash');
  expect(continuationKey).toMatch(/^[0-9a-f]{32}$/);
  expect(sealedContinuation).toBeTruthy();
  expect(sealedContinuation).not.toContain(continuedFirstName);

  const sudoAuthnRequestPromise = page.waitForRequest(
    request => isKeycloakSamlRequest(request, 'SAMLRequest')
  );
  const sudoCallbackPromise = page.waitForRequest(isRedmineSamlCallback);
  await page.locator(`${SUDO_REAUTH_FORM} button[type=submit]`).click();

  const sudoAuthnRequest = await sudoAuthnRequestPromise;
  const sudoAuthnRequestXml = decodeRedirectMessage(
    samlParameter(sudoAuthnRequest, 'SAMLRequest')
  );
  const sudoRequestId = sudoAuthnRequestXml.match(/\bID=['"]([^'"]+)['"]/);
  expect(sudoRequestId).not.toBeNull();
  const sudoRelayState = samlParameter(sudoAuthnRequest, 'RelayState');
  expect(sudoRelayState).toMatch(/^redmine_saml_sudo\//);

  await signInAtKeycloakIfPrompted(page, sudoCallbackPromise);

  const sudoCallback = await sudoCallbackPromise;
  expect(sudoCallback.method()).toBe('POST');
  expect(samlParameter(sudoCallback, 'RelayState')).toBe(sudoRelayState);
  const sudoResponseXml = decodePostMessage(
    samlParameter(sudoCallback, 'SAMLResponse')
  );
  expect(sudoResponseXml).toMatch(/<(?:[\w-]+:)?Signature\b/);
  expect(sudoResponseXml).toMatch(
    new RegExp(`\\bInResponseTo=['"]${escapeRegExp(sudoRequestId[1])}['"]`)
  );

  // The real callback reaches the real resume URL. Its script reads this
  // tab's sessionStorage and renders an ordinary form, but still performs no
  // account update.
  await expect(page).toHaveURL(`${REDMINE_ORIGIN}/saml/sudo_resume`);
  const continueForm = page.locator('#saml-sudo-continue-form');
  await expect(continueForm).toHaveAttribute('action', '/my/account');
  await expect(continueForm.locator('input[name=_method]')).toHaveValue('PUT');
  await expect(continueForm.locator('input[name="user[firstname]"]'))
    .toHaveValue(continuedFirstName);

  const storedBeforeContinue = await page.evaluate(
    ([prefix, key]) => window.sessionStorage.getItem(prefix + key),
    [SUDO_CONTINUATION_PREFIX, continuationKey]
  );
  expect(storedBeforeContinue).toBe(sealedContinuation);

  const accountObserverPage = await page.context().newPage();
  await accountObserverPage.goto(`${REDMINE_ORIGIN}/my/account`, { waitUntil: 'domcontentloaded' });
  await expect(accountObserverPage.locator('#user_firstname')).toHaveValue(originalFirstName);
  await accountObserverPage.close();

  const accountUpdatePromise = page.waitForRequest(request => {
    const url = new URL(request.url());

    return url.origin === REDMINE_ORIGIN &&
      url.pathname === '/my/account' &&
      request.method() === 'POST' &&
      new URLSearchParams(request.postData() || '').get('_method') === 'PUT';
  });
  await continueForm.locator('input[type=submit]').click();
  await accountUpdatePromise;

  await expect(page).toHaveURL(`${REDMINE_ORIGIN}/my/account`);
  await expect(page.locator('#flash_notice')).toBeVisible();
  await expect(page.locator('#user_firstname')).toHaveValue(continuedFirstName);
  await expect(page.locator(SUDO_REAUTH_FORM)).toHaveCount(0);

  const storedAfterContinue = await page.evaluate(
    ([prefix, key]) => window.sessionStorage.getItem(prefix + key),
    [SUDO_CONTINUATION_PREFIX, continuationKey]
  );
  expect(storedAfterContinue).toBeNull();
});

test('log out of Redmine and Keycloak through real SAML SLO', async ({ page }) => {
  test.setTimeout(60000);

  await page.goto(`${REDMINE_ORIGIN}/login`, { waitUntil: 'commit' });

  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );

  await signInAtKeycloak(page);

  await expect(page).toHaveURL(
    /127\.0\.0\.1:3000\/my\/page/
  );
  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveText('samltest');

  const csrfParamMeta = page.locator('meta[name="csrf-param"]');
  const csrfTokenMeta = page.locator('meta[name="csrf-token"]');
  await expect(csrfParamMeta).toHaveAttribute('content', 'authenticity_token');
  await expect(csrfTokenMeta).toHaveAttribute('content', /.+/);
  const csrfParameterName = await csrfParamMeta.getAttribute('content');
  const csrfToken = await csrfTokenMeta.getAttribute('content');

  const redmineLogoutRequestPromise = page.waitForRequest(isRedmineLogoutRequest);
  const redmineLogoutHttpResponsePromise = page.waitForResponse(
    response => isRedmineLogoutRequest(response.request())
  );
  const keycloakLogoutRequestPromise = page.waitForRequest(
    request => isKeycloakSamlRequest(request, 'SAMLRequest')
  );
  const redmineLogoutResponsePromise = page.waitForRequest(
    request => isRedmineSlsRequest(request, 'SAMLResponse')
  );
  const redmineSlsResponsePromise = page.waitForResponse(
    response => isRedmineSlsRequest(response.request(), 'SAMLResponse')
  );

  await page.locator('#account .dropdown-trigger').click();
  await page.getByRole('link', { name: 'Sign out', exact: true }).click();

  const [
    redmineLogoutRequest,
    redmineLogoutHttpResponse,
    keycloakLogoutRequest,
    redmineLogoutResponse,
    redmineSlsResponse
  ] = await Promise.all([
    redmineLogoutRequestPromise,
    redmineLogoutHttpResponsePromise,
    keycloakLogoutRequestPromise,
    redmineLogoutResponsePromise,
    redmineSlsResponsePromise
  ]);

  expect(redmineLogoutRequest.method()).toBe('POST');
  const redmineLogoutParameters = new URLSearchParams(redmineLogoutRequest.postData() || '');
  expect(redmineLogoutParameters.get('_method')).toBe('post');
  expect(redmineLogoutParameters.get(csrfParameterName)).toBe(csrfToken);
  expect(redmineLogoutHttpResponse.status()).toBe(302);
  const redmineLogoutLocation = redmineLogoutHttpResponse.headers().location;
  expect(redmineLogoutLocation).toContain(`${KEYCLOAK_ORIGIN}${KEYCLOAK_SAML_PATH}`);
  expect(new URL(redmineLogoutLocation).searchParams.get('SAMLRequest')).toBeTruthy();

  expect(keycloakLogoutRequest.method()).toBe('GET');
  const logoutRequestXml = decodeRedirectMessage(
    samlParameter(keycloakLogoutRequest, 'SAMLRequest')
  );
  expect(logoutRequestXml).toMatch(/<(?:[\w-]+:)?LogoutRequest\b/);
  expect(logoutRequestXml).toContain(`${KEYCLOAK_ORIGIN}${KEYCLOAK_SAML_PATH}`);

  const requestId = logoutRequestXml.match(/\bID=['"]([^'"]+)['"]/);
  expect(requestId).not.toBeNull();

  expect(redmineLogoutResponse.method()).toBe('POST');
  const logoutResponseXml = decodePostMessage(
    samlParameter(redmineLogoutResponse, 'SAMLResponse')
  );
  expect(logoutResponseXml).toMatch(/<(?:[\w-]+:)?LogoutResponse\b/);
  expect(logoutResponseXml).toMatch(/<(?:[\w-]+:)?Signature\b/);
  expect(logoutResponseXml).toContain(`${REDMINE_ORIGIN}/auth/saml/sls`);
  expect(logoutResponseXml).toMatch(
    new RegExp(`\\bInResponseTo=['"]${requestId[1]}['"]`)
  );
  expect(logoutResponseXml).toContain('urn:oasis:names:tc:SAML:2.0:status:Success');
  expect(redmineSlsResponse.status()).toBe(302);

  await expect(page).toHaveURL(`${REDMINE_ORIGIN}/`);
  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveCount(0);

  await page.goto(`${REDMINE_ORIGIN}/my/page`, { waitUntil: 'commit' });
  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );
  await expect(page.locator('#username')).toBeVisible();
  await expect(page.locator('#password')).toBeVisible();
  await expect(page.locator('#kc-login')).toBeVisible();
});
