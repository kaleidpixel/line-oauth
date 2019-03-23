LINE OAuth
=========
Integrating LINE Login with your web app.

## Requirements

This package requires PHP >=5.4

## Installation

Install via composer - edit your `composer.json` to require the package.

```json
{
    "require": {
        "kaleidpixel/line-oauth": "0.*"
    }
}
```

Then run `composer update` in your terminal to pull it in.

Or use `composer require kaleidpixel/line-oauth`

## How to

### login.php
```php
<?php
require_once dirname(dirname(__FILE__)) . '/vendor/autoload.php';

use KaleidPixel\OAuth\LineOAuth;

$connection = new LineOAuth(API_KEY_LINE, API_SECRET_LINE);
$_SESSION['user']['oauth_token'] = $connection->state;
$_SESSION['user']['oauth_provider'] = 'line';

header("Location: {$connection->oauthUrl(OAUTH_CALLBACK_URL)}");
```

### callback.php
```php
<?php
require_once dirname(dirname(__FILE__)) . '/vendor/autoload.php';

use KaleidPixel\OAuth\LineOAuth;

if (isset($_REQUEST['code']) && $_REQUEST['state'] === $_SESSION['user']['oauth_token']) {
    $connection = new LineOAuth(API_KEY_LINE, API_SECRET_LINE, $_SESSION['user']['oauth_token']);
    $token = $connection->getToken($_REQUEST['code'], OAUTH_CALLBACK_URL);

    if (!is_null($token)) {
        $user = $connection->getUser($token);

        if(!empty($user)) {
            $_SESSION['user']['provider'] = $_SESSION['user']['oauth_provider'];
            $_SESSION['user']['provider_id'] = $user->userId;
            $_SESSION['user']['name'] = $user->displayName;
        }
    }
}

var_dump($_SESSION);
```