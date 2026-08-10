const { test, expect } = require('@playwright/test');
const zlib = require('zlib');

const REDMINE_ORIGIN = 'http://127.0.0.1:3000';
const KEYCLOAK_ORIGIN = 'http://127.0.0.1:8080';
const KEYCLOAK_SAML_PATH = '/realms/redmine-e2e/protocol/saml';

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
  await page.goto('http://127.0.0.1:3000/login');

  const samlButton = page.locator('#saml-login button');
  await expect(samlButton).toHaveText('Login with SSO');

  await samlButton.click();

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
});

test('log out of Redmine and Keycloak through real SAML SLO', async ({ page }) => {
  test.setTimeout(60000);

  await page.goto(`${REDMINE_ORIGIN}/login`);

  const samlButton = page.locator('#saml-login button');
  await expect(samlButton).toHaveText('Login with SSO');
  await samlButton.click();

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

  await page.goto(`${REDMINE_ORIGIN}/my/page`);
  await expect(page).toHaveURL(/127\.0\.0\.1:3000\/login(?:\?|$)/);
  await expect(
    page.locator('div.flyout-menu__avatar a.user.active')
  ).toHaveCount(0);

  const secondSamlButton = page.locator('#saml-login button');
  await expect(secondSamlButton).toHaveText('Login with SSO');
  await secondSamlButton.click();

  await expect(page).toHaveURL(
    /127\.0\.0\.1:8080\/realms\/redmine-e2e/
  );
  await expect(page.locator('#username')).toBeVisible();
  await expect(page.locator('#password')).toBeVisible();
  await expect(page.locator('#kc-login')).toBeVisible();
});
