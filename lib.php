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
 *
 * @package     auth_anonymous
 * @license     http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

/**
 * inline logout (no actions)
 * can be called by a process (e.g. theme renderer) to ensure a user that has authenticated with anonymous gets logged out
 * performs actions similar to require_logout() except doesn't process auth plugin pre and post hooks or redirects
 */
function auth_anonymous_autologout() {
global $USER, $DB;
    if (isloggedin() && !isguestuser() && $USER->auth === 'anonymous') {

        $sid = session_id();
        $event = \core\event\user_loggedout::create(
            array(
                'userid' => $USER->id,
                'objectid' => $USER->id,
                'other' => array('sessionid' => $sid),
            )
        );
        if ($session = $DB->get_record('sessions', array('sid'=>$sid))) {
            $event->add_record_snapshot('sessions', $session);
        }
        // Delete session record and drop $_SESSION content.
        \core\session\manager::terminate_current();

        // Trigger event AFTER action.
        $event->trigger();

        // not sure if this is necessary, but it doesn't hurt
        \core\session\manager::kill_user_sessions($USER->id);

        // back to no user
        $USER = new stdClass();
        $USER->id = 0;

    }

}