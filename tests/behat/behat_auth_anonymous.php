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
 * Definition of the {@see behat_auth_anonymous} class.
 *
 * @package auth_anonymous
 * @author  2025 Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * {@noinspection PhpIllegalPsrClassPathInspection}
 */

require_once(__DIR__ . '/../../../../lib/behat/behat_base.php');

/**
 * Behat steps definitions.
 *
 * @package auth_anonymous
 * @author  2025 Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_auth_anonymous extends behat_base {

    /**
     * Visits the login page with the `auth` query parameter set for anonymous authentication.
     *
     * @Given /^I follow an anonymous login link$/
     *
     * {@noinspection PhpUnused}
     * @throws moodle_exception
     */
    public function i_follow_an_anonymous_login_link(): void {
        $params = [
            'anon' => 1,
            'key' => random_string(),
            'ts' => time(),
        ];
        $querystring = http_build_query($params, arg_separator: '&');
        $auth = base64_encode($querystring);
        $url = new moodle_url('/login/index.php', ['auth' => $auth]);
        $this->getSession()->visit($this->locate_path($url->out_as_local_url()));
    }
}
