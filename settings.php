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
 * @package auth_anonymous
 * @author  tim.stclair@gmail.com
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 *
 * {@noinspection PhpUndefinedVariableInspection, PhpUnhandledExceptionInspection}
 */

use core\lang_string;
use auth_anonymous\config;

defined('MOODLE_INTERNAL') || die;

global $ADMIN;

if ($ADMIN->fulltree) {

    $settings->add(new admin_setting_heading(
        name: 'auth_anonymous/info',
        heading: '',
        information: new lang_string('settings_desc', 'auth_anonymous'),
    ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/cohort',
        visiblename: new lang_string('cohort','cohort'),
        description: new lang_string('cohort_desc', 'auth_anonymous'),
        defaultsetting: config::DEFAULT_COHORT,
        paramtype: PARAM_RAW_TRIMMED,
    ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/firstname',
        visiblename: new lang_string('firstname'),
        description: '',
        defaultsetting: config::DEFAULT_FIRSTNAME,
        paramtype: PARAM_RAW_TRIMMED,
    ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/lastname',
        visiblename: new lang_string('lastname'),
        description: '',
        defaultsetting: config::DEFAULT_LASTNAME,
        paramtype: PARAM_RAW_TRIMMED,
    ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/email',
        visiblename: new lang_string('email'),
        description: '',
        defaultsetting: config::DEFAULT_EMAIL,
        paramtype: PARAM_RAW_TRIMMED,
    ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/regex',
        visiblename: new lang_string('keyregex', 'auth_anonymous'),
        description: new lang_string('keyregex_desc', 'auth_anonymous'),
        defaultsetting: config::DEFAULT_REGEX,
        paramtype: PARAM_RAW_TRIMMED,
    ));

    $settings->add(new admin_setting_configselect(
        name: 'auth_anonymous/timeout',
        visiblename: new lang_string('timeout', 'auth_anonymous'),
        description: new lang_string('timeout_desc', 'auth_anonymous'),
        defaultsetting: config::DEFAULT_TIMEOUT,
        choices: [
            0 => new lang_string('never'),
            60 => new lang_string('numminutes','moodle', 1),
            300 => new lang_string('numminutes','moodle', 5),
            3600 => new lang_string('numhours','moodle', 1),
            18000 => new lang_string('numhours','moodle', 5),
        ],
     ));

    $rolechoices = [0 => new lang_string('none')];
    $systemroles = role_fix_names(
        roleoptions: get_all_roles(),
        context: context_system::instance(),
        rolenamedisplay: ROLENAME_ORIGINAL,
    );
    foreach ($systemroles as $role) {
        $rolechoices[$role->id] = $role->localname;
    }
    $settings->add(new admin_setting_configselect(
        // TODO: Rename to `role`.
        name: 'auth_anonymous/assignrole',
        visiblename: new lang_string('role', 'auth_anonymous'),
        description: new lang_string('role_desc', 'auth_anonymous'),
        defaultsetting: config::DEFAULT_ROLE,
        choices: $rolechoices,
     ));

    $settings->add(new admin_setting_configtext(
        name: 'auth_anonymous/logouturl',
        visiblename: new lang_string('logouturl', 'auth_anonymous'),
        description: new lang_string('logouturl_desc', 'auth_anonymous'),
        defaultsetting: config::DEFAULT_LOGOUT_URL,
        paramtype: PARAM_RAW_TRIMMED,
     ));

}
