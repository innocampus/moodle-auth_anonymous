# Anonymous Auth

A moodle auth plugin to log in as an anonymous user who is then able to interact and save data without being identifiable. It is intended to be used when paired with courses containing a survey, feedback form or other self-assesment type activity.

A simple request is made to the moodle Logon page with an encoded URL which is detected by this plugin hook. If it matches, it will create a user record and authenticate, optionally adding the user to a cohort.

Passwords are generated automatically based on the (salted) key but not cached.

## Why

Because Guest access can't write to the database, only read. Sometimes you need to guarantee a user isn't able to be identified but still be able to capture data.

## Security

Firstly, properly lock down what the anonymous user can do once logged in. Could this be used to spam my site? Absolutely, so be careful where you use the url! Use POST to make it less obvious to the casual observer. You should set a key prefix; keys without it are ignored, so the plugin does not trigger and your other authentication providers can take over. Changing the prefix also invalidates every link issued so far.

Note that none of this authenticates anybody: the encoding is not a signature and the prefix is not a secret, so a conforming key can always be constructed by hand. That is inherent to anonymous login — treat these links as an entry point, not as a credential.

## Logging in

Link to `/auth/anonymous/login.php`, optionally with a `course` id:

```
https://elearning.yourdomain.com/auth/anonymous/login.php
https://elearning.yourdomain.com/auth/anonymous/login.php?course=42
```

It mints a key and a timestamp and forwards to the login page. Link here rather than building the URL yourself: the timestamp is checked against the link timeout, so a URL built while rendering a page starts ageing as soon as that page is cached, and every visitor of it shares one identity.

Build the URL yourself only when an external system issues the links, in which case the parameters below apply.

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
| key      | A value representing the user. Used in hash functions to generate a username and password. Must carry the configured key prefix, and is limited to 255 characters. |
| anon     | Must equal '1' |
| course   | If set and greater than 1, open /course/view.php?id=X after a sucessful login |
| ts       | Current unix timestamp, used to ensure link validity |

Parameters **must be** base64 encoded and passed either as the entire query string (GET), or as the `auth` parameter (GET or POST).

## Set up

This belongs in `/auth/anonymous` in your moodle folder. Use the plugin istaller if you can. You should also enable the authentication method through `Site Administration > Plugins > (Authentication) > Manage Authentication` and push its priority to the top.

## Limiting Login

I used this plugin in conjunction with a [course theme](https://github.com/frumbert/theme_arid). When the user browsed outside the course the theme was loaded in, you would be automatically logged off as the site fell back on Boost. There's a routine in the lib.php file for automatic log off that you can call.

For instance in boost's `config.php` you can drop this at the bottom to automatically log the user out if Boost is loaded.

```php
// execute this when the theme loads
// don't allow anonymous logon in this theme
if (file_exists($CFG->dirroot . '/auth/anonymous/lib.php')) {
    require_once($CFG->dirroot . '/auth/anonymous/lib.php');
    auth_anonymous_autologout();
}
```

## Todo / Maybe

   -[ ] Option to switch to openssl encryption for auth parameter (e.g. aes-cbc-256)

## Licence

GPL-3
