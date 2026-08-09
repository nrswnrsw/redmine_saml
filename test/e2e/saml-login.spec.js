const { test, expect } = require('@playwright/test');

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
