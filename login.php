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
 * Entry point for starting an anonymous login.
 *
 * Link here instead of building login URLs elsewhere, so that key and timestamp are generated when
 * the user acts rather than when the linking page is rendered.
 *
 * @package   auth_anonymous
 * @author    Daniel Fainberg, TU Berlin
 * @copyright 2026 Daniel Fainberg, TU Berlin
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

use auth_anonymous\auth;

require_once(__DIR__ . '/../../config.php');

if (!is_enabled_auth('anonymous')) {
    throw new moodle_exception('pluginisdisabled', 'auth_anonymous');
}

$courseid = optional_param('course', 0, PARAM_INT);

redirect(auth::get_login_url($courseid));
