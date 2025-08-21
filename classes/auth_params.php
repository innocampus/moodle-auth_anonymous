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
 * Definition of the {@see \auth_anonymous\auth_params} class.
 *
 * @package auth_anonymous
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_anonymous;

/**
 * Encapsulates parameters provided to the authentication plugin at the login page hook.
 *
 * @package auth_anonymous
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final readonly class auth_params {
    /**
     * Instantiates a new object.
     *
     * @param bool $anon Flag to explicitly tell the login hook to use anonymous authentication.
     * @param string $key Unique key for the user being authenticated.
     * @param int $ts UNIX timestamp for when the URL was generated.
     * @param int $course ID of a course to redirect the user to after authentication; `0` (default) disables this.
     * @param string $cohort Name of a cohort to add the user to after authentication; empty string (default) disables this.
     */
    public function __construct(
        public bool $anon = false,
        public string $key = '',
        public int $ts = 0,
        public int $course = 0,
        public string $cohort = '',
    ) {}

    /**
     * Construct a new instance from an associative array, with keys that match the properties.
     *
     * @param array $params Associative array to use for construction.
     * @return self New instance.
     */
    public static function from_array(array $params): self {
        return new self(
            anon: $params['anon'] ?? false,
            key: $params['key'] ?? '',
            ts: $params['ts'] ?? 0,
            course: $params['course'] ?? 0,
            cohort: $params['cohort'] ?? '',
        );
    }
}
