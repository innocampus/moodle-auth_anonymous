<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Definition of the {@see \auth_anonymous\config} class.
 *
 * @package auth_anonymous
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_anonymous;

use dml_exception;

/**
 * Encapsulates all plugin config parameters and their defaults.
 *
 * The purpose of this class is to provide a type safe config object for the plugin.
 * Call the {@see get} method instead of the built-in {@see get_config} function.
 *
 * @package auth_anonymous
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final readonly class config {
    const DEFAULT_FIRSTNAME = 'anonymous';
    const DEFAULT_LASTNAME = 'user';
    const DEFAULT_EMAIL = 'nobody@127.0.0.1';
    const DEFAULT_COHORT = 'anonymous';
    const DEFAULT_COURSE = 0;
    const DEFAULT_KEY_PREFIX = '';
    const DEFAULT_TIMEOUT = 0;
    const DEFAULT_ROLE = 0;
    const DEFAULT_LOGOUT_URL = '';


    public function __construct(
        public string $firstname = self::DEFAULT_FIRSTNAME,
        public string $lastname = self::DEFAULT_LASTNAME,
        public string $email = self::DEFAULT_EMAIL,
        public string $cohort = self::DEFAULT_COHORT,
        public int $course = self::DEFAULT_COURSE,
        public string $keyprefix = self::DEFAULT_KEY_PREFIX,
        public int $timeout = self::DEFAULT_TIMEOUT,
        public int $role = self::DEFAULT_ROLE,
        public string $logouturl = self::DEFAULT_LOGOUT_URL,
    ) {}

    /**
     * Returns the current plugin config as an instance of this class.
     *
     * @throws dml_exception
     */
    public static function get(): self {
        $untyped = get_config('auth_anonymous');
        return new self(
            firstname: $untyped->firstname ?: self::DEFAULT_FIRSTNAME,
            lastname: $untyped->lastname ?: self::DEFAULT_LASTNAME,
            email: $untyped->email ?: self::DEFAULT_EMAIL,
            cohort: $untyped->cohort ?: self::DEFAULT_COHORT,
            course: $untyped->course ?: self::DEFAULT_COURSE,
            keyprefix: $untyped->keyprefix ?? self::DEFAULT_KEY_PREFIX,
            timeout: $untyped->timeout ?: self::DEFAULT_TIMEOUT,
            role: $untyped->assignrole ?: self::DEFAULT_ROLE,
            logouturl: $untyped->logouturl ?: self::DEFAULT_LOGOUT_URL,
        );
    }
}
