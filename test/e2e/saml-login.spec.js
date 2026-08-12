const { test, expect } = require('@playwright/test');
const zlib = require('zlib');

const REDMINE_ORIGIN = 'http://127.0.0.1:3000';
const KEYCLOAK_ORIGIN = 'http://127.0.0.1:8080';
const KEYCLOAK_SAML_PATH = '/realms/redmine-e2e/protocol/saml';
const REDMINE_CALLBACK_PATH = '/auth/saml/callback';
const REDMINE_ENTITY_ID = `${REDMINE_ORIGIN}/auth/saml/metadata`;
const SAML_NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

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
  await page.locator('#username').fill('samltest');
  await page.locator('#password').fill('samltest-password');
  await page.locator('#kc-login').click();

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

test('log out of Redmine and Keycloak through real SAML SLO', async ({ page }) => {
  test.setTimeout(60000);

  await page.goto(`${REDMINE_ORIGIN}/login`, { waitUntil: 'commit' });

  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );

  await page.locator('#username').fill('samltest');
  await page.locator('#password').fill('samltest-password');
  await page.locator('#kc-login').click();

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
