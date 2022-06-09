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
 * Admin settings and defaults.
 *
 * @package    auth
 * @subpackage anonmyous
 * @author tim.stclair@gmail.com
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

if ($ADMIN->fulltree) {

    $settings->add(new admin_setting_heading(
        'auth_anonymous/info',
        '',
        get_string('settings_desc', 'auth_anonymous')
    ));

    $settings->add(new admin_setting_configtext(
        'auth_anonymous/cohort',
        get_string('cohort','cohort'),
        get_string('cohort_desc', 'auth_anonymous'),
        'anonymous',
        PARAM_RAW_TRIMMED
    ));

    $settings->add(new admin_setting_configtext(
        'auth_anonymous/firstname',
        get_string('firstname'),
        '',
        'anonymous',
        PARAM_RAW_TRIMMED
    ));

    $settings->add(new admin_setting_configtext(
        'auth_anonymous/lastname',
        get_string('lastname'),
        '',
        'user',
        PARAM_RAW_TRIMMED
    ));

    $settings->add(new admin_setting_configtext(
        'auth_anonymous/email',
        get_string('email'),
        '',
        'nobody@127.0.0.1',
        PARAM_RAW_TRIMMED
    ));

    $settings->add(new admin_setting_configselect(
        'auth_anonymous/timeout',
        get_string('timeout', 'auth_anonymous'),
        get_string('timeout_desc', 'auth_anonymous'),
        0,
        [
            0 => get_string('never'),
            60 => get_string('numminutes','moodle', 1),
            300 => get_string('numminutes','moodle', 5),
            3600 => get_string('numhours','moodle', 1),
            18000 => get_string('numhours','moodle', 5),
        ],
        PARAM_INT
     ));

    $settings->add(new admin_setting_configtext(
        'auth_anonymous/logouturl',
        get_string('logouturl', 'auth_anonymous'),
        get_string('logouturl_desc', 'auth_anonymous'),
        '',
        PARAM_RAW_TRIMMED
     ));
}