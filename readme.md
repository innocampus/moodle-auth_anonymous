# Anonymous Auth

A moodle auth plugin to log in as an anonymous user who is then able to interact and save data without being identifiable. It is intended to be used when paired with courses containing a survey, feedback form or other self-assesment type activity.

A simple request is made to the moodle Logon page with an encoded URL which is detected by this plugin hook. If it matches, it will create a user record and authenticate, optionally adding the user to a cohort.

Passwords are generated automatically based on the (salted) key but not cached.

## Why

Because Guest access can't write to the database, only read. Sometimes you need to guarantee a user isn't able to be identified but still be able to capture data.

## Security

Firstly, properly lock down what the anonymous user can do once logged in. Could this be used to spam my site? Absolutely, so be careful where you use the url! Use POST to make it less obvious to the casual observer. You should specify a regular expression to match the key; if the key is rejected, the plugin will not trigger and your other authentication providers can take over. Or modify the plugin to use openssl_decrypt() with a reversible encryption algorithm such as aes-256-cbc instead of base64...

## Example (php GET)

```php

    $params = http_build_query([
        "key" => $identity,
        "anon" => 1,
        "course" => $courseId,
        "ts" => time()
    ]);
    header('Location: https://elearning.yourdomain.com/login/index.php?auth=' . base64_encode($params));

```

| Parameter | Meaning |
| --- | --- |
| key      | A value representing the user. Used in hash functions to generate a username and password. Can be pattern-validated against a regular expression before being accepted. |
| anon     | Must equal '1' |
| course   | If set and greater than 1, open /course/view.php?id=X after a sucessful login |
| ts       | Current unix timestamp, used to ensure link validity |

Parameters **must be** base64 encoded and passed either as the entire query string (GET), or as the `auth` parameter (GET or POST).

## Set up

This belongs in `/auth/anonymous` in your moodle folder. Use the plugin istaller if you can. You should also enable the authentication method through `Site Administration > Plugins > (Authentication) > Manage Authentication` and push its priority to the top.

## Todo / Maybe

   -[ ] Option to switch to openssl encryption for auth parameter

## Licence

GPL-3
