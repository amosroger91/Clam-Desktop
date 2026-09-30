// CI can demand a signed release without ever printing signing credentials.
if (process.env.SENTINEL_REQUIRE_SIGNING === '1' && !process.env.CSC_LINK && !process.env.WIN_CSC_LINK)
  throw Error('A signed release was requested but no electron-builder signing identity is configured');
if (!process.env.CSC_LINK && !process.env.WIN_CSC_LINK)
  console.log('Building an unsigned preview. Set CSC_LINK / CSC_KEY_PASSWORD for publisher-signed releases.');
