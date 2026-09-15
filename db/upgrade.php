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
 * This file keeps track of upgrades to auth_anonymous.
 *
 * @package   auth_anonymous
 * @author    Daniel Fainberg, TU Berlin
 * @copyright 2026 Daniel Fainberg, TU Berlin
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Upgrade code for auth_anonymous.
 *
 * @param int $oldversion the version we are upgrading from.
 */
function xmldb_auth_anonymous_upgrade($oldversion = 0) {
    global $OUTPUT;

    if ($oldversion < 2026091500) {
        // Only a pattern anchoring a literal at the start translates into a prefix.
        $regex = get_config('auth_anonymous', 'regex');
        if (!empty($regex)) {
            if (preg_match('/^\/?\^([A-Za-z0-9_-]+)/', $regex, $matches)) {
                set_config('keyprefix', $matches[1], 'auth_anonymous');
            } else {
                echo $OUTPUT->notification(
                    get_string('upgrade_regexnotmigrated', 'auth_anonymous', s($regex)),
                    'notifyproblem',
                );
            }
        }
        unset_config('regex', 'auth_anonymous');

        upgrade_plugin_savepoint(true, 2026091500, 'auth', 'anonymous');
    }

    return true;
}
