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
 * Definition of the {@see \auth_anonymous\admin\setting_course} class.
 *
 * @package   auth_anonymous
 * @copyright 2026 Daniel Fainberg, TU Berlin
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_anonymous\admin;

use admin_setting_configtext;
use coding_exception;
use core\lang_string;
use dml_exception;

/**
 * Text field holding the ID of an existing course, or `0` for no course.
 *
 * @package   auth_anonymous
 * @copyright 2026 Daniel Fainberg, TU Berlin
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class setting_course extends admin_setting_configtext {
    /**
     * Instantiates a new setting.
     *
     * @param string $name Full setting name, i.e. `auth_anonymous/<setting>`.
     * @param lang_string|string $visiblename Localised setting label.
     * @param lang_string|string $description Localised setting description.
     * @param int $defaultsetting Course ID to use when the setting is empty.
     */
    public function __construct(
        string $name,
        lang_string|string $visiblename,
        lang_string|string $description,
        int $defaultsetting,
    ) {
        parent::__construct($name, $visiblename, $description, $defaultsetting, PARAM_INT);
    }

    /**
     * Rejects anything that is not `0` or the ID of an existing course.
     *
     * Without this, a mistyped ID is only noticed when a user logs in and silently lands on the
     * standard return URL instead of the course.
     *
     * @param string $data Value entered in the form.
     * @return string|true Localised error message, or `true` if the value is acceptable.
     * @throws coding_exception
     * @throws dml_exception
     */
    public function validate($data): string|bool {
        global $DB;
        if (($parentresult = parent::validate($data)) !== true) {
            return $parentresult;
        }
        if ((int) $data !== 0 && !$DB->record_exists('course', ['id' => (int) $data])) {
            return get_string('invalidcourseid', 'error');
        }
        return true;
    }
}
