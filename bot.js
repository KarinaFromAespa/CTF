const puppeteer = require('puppeteer-core');

const CHROME_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';
const BOT_ORIGIN  = process.env.BOT_ORIGIN || 'http://127.0.0.1:3000';
const FLAG        = process.env.FLAG || 'FLAG{replace_me}';
const NAV_TIMEOUT = 15_000;
const LINGER_MS   = 5_000;

let active = 0;
const MAX_CONCURRENT = 2;

async function visitAsAdmin(urlPath) {
  if (active >= MAX_CONCURRENT) {
    throw new Error('Bot is busy — try again in a few seconds.');
  }

  active++;
  let browser;

  try {
    console.log('[bot] launching chromium …');
    browser = await puppeteer.launch({
      executablePath: CHROME_PATH,
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-extensions',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-sync',
        '--disable-translate',
        '--no-first-run',
        '--no-zygote',
        '--single-process',
        '--mute-audio',
        '--hide-scrollbars',
      ],
    });

    const page   = await browser.newPage();
    const domain = new URL(BOT_ORIGIN).hostname;

    await page.setCookie({
      name:     'flag',
      value:    FLAG,
      domain,
      path:     '/',
      httpOnly: false,
      secure:   false,
      sameSite: 'Lax',
    });

    const target = `${BOT_ORIGIN}${urlPath}`;
    console.log(`[bot] visiting ${target}`);

    await page.goto(target, {
      waitUntil: 'networkidle2',
      timeout:   NAV_TIMEOUT,
    });

    await new Promise(r => setTimeout(r, LINGER_MS));
    console.log('[bot] done');
  } catch (err) {
    console.error('[bot] error:', err instanceof Error ? err.message : err);
    throw err;
  } finally {
    active--;
    await browser?.close().catch(() => {});
  }
}

module.exports = { visitAsAdmin };
