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
 * Definition of the {@see \auth_anonymous\auth} class.
 *
 * @package auth_anonymous
 * @author  tim.stclair@gmail.com
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace auth_anonymous;

defined('MOODLE_INTERNAL') || die();
global $CFG;
require_once("$CFG->libdir/authlib.php");
require_once("$CFG->dirroot/cohort/lib.php");

use auth_plugin_base;
use coding_exception;
use context_system;
use core\event\user_created;
use core\event\user_updated;
use dml_exception;
use moodle_exception;
use moodle_url;
use stdClass;


/**
 * Implements the authentication functionality.
 *
 * @see https://docs.moodle.org/dev/Authentication_plugins
 *
 * @package auth_anonymous
 * @author  tim.stclair@gmail.com
 * @author  Daniel Fainberg, TU Berlin
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth extends auth_plugin_base {
    const KEYNAME = "key"; // param to look for in the decoded url data

    private string $firstname;
    private string $lastname;
    private string $email;
    private string $cohort;
    private int $timeout;
    private string $validator;
    private int $role;

    /**
     * Fetches plugin config and assigns internal properties as needed.
     *
     * @throws dml_exception
     */
    public function __construct() {
        $this->authtype = 'anonymous';
        $this->config = get_config('auth_anonymous');

        $this->firstname = $this->config->firstname ?: "anonymous";
        $this->lastname = $this->config->lastname ?: "user";
        $this->email = $this->config->email ?: "anonymous@127.0.0.1";
        $this->cohort = $this->config->cohort ?: "anonymous";
        $this->timeout = $this->config->timeout ?: 0;
        $this->validator = $this->config->regex ?: '/./'; // meaning "match any value"
        $this->role = $this->config->assignrole ?: 0;
    }

    /**
     * Returns `true` if the username and password work and `false` if they are wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes).
     * @param string $password The password (with system magic quotes).
     * @return bool Authentication success or failure.
     * @throws dml_exception
     */
    public function user_login($username, $password): bool {
        global $CFG, $DB;
        if (!$username or !$password) {
            // Don't allow blank usernames or passwords.
            return false;
        }
        // We just set the password, so it will be valid.
        if ($user = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id])) {
            return validate_internal_user_password($user, $password);
        }
        return false;
    }

    /**
     * We do not authenticate directly via the Moodle user table.
     *
     * @return false
     */
    public function is_internal(): false {
        return false;
    }

    /**
     * Performs the actual registration/login logic.
     *
     * Called at the start of the login page. This is the main landing point
     * for the anonymous authentication as we are doing sso i.e., we trust the calls
     * and simply log the user in. If the account doesn't exist, then we simply
     * create it.
     *
     * @throws moodle_exception
     */
    public function loginpage_hook(): void {
        global $CFG, $DB, $FULLME;
        $auth = optional_param('auth', '', PARAM_ALPHANUM);
        if (empty($auth)) {
            $params = $this->retrieve_encoded_params($this->retrieve_query_string($FULLME));
        } else {
            $params = $this->retrieve_encoded_params($auth);
        }
        // If the 'anon' key is not set within the query params, we are not processing this request.
        if (!($params && isset($params['anon']) && $params['anon'] === '1')) {
            return;
        }
        // If the parameters are invalid, we are not processing this request.
        // TODO: Validate all parameters once using a class.
        if (!($this->validate_parameters($params) and $this->validate_time($params['ts']) and $this->validate_key($params[self::KEYNAME]))) {
            return;
        }
        $identifier = md5($this->authtype . $params[self::KEYNAME]); // will yield a 32 char hash
        if (!$DB->record_exists('user', ['username' => $identifier, 'mnethostid' => $CFG->mnet_localhost_id, 'auth' => $this->authtype])) {
            $this->create_anonymous_user($identifier, $params[self::KEYNAME]);
        } else {
            // Update the password so that `validate_internal_user_password` doesn't see 'not cached'.
            // TODO: Check if this is really necessary.
            $this->update_anonymous_user_password($identifier);
        }
        $this->login_anonymous_user($identifier, $params);
    }

    /**
     * Creates a new anonymous user with the specified username and idnumber.
     *
     * @param string $username Value to assign to the new user's `username` field.
     * @param string $idnumber Value to assign to the new user's `idnumber` field.
     * @throws moodle_exception
     */
    private function create_anonymous_user(string $username, string $idnumber): void {
        // TODO: See if we can't just use the built-in `user_create_user()`.
        global $CFG, $DB;
        $user = new stdClass;
        $user->username = $username;
        $user->idnumber = $idnumber;
        $user->password = hash_internal_user_password($this->get_user_password($username));
        $user->firstname = $this->firstname;
        $user->lastname = $this->lastname;
        $user->email = $this->email;
        $user->country = '';
        $user->auth = $this->authtype;
        $user->mailformat = 0;
        $user->maildisplay = 0;
        $user->autosubscribe = 0;
        $user->mnethostid = $CFG->mnet_localhost_id;
        $user->confirmed = 1;
        $user->id = $DB->insert_record('user', $user);
        user_created::create_from_userid($user->id)->trigger();
    }

    /**
     * Sets the password for the user with the provided username.
     *
     * @param string $username Username of the user for whom to set the password.
     * @throws moodle_exception
     */
    private function update_anonymous_user_password(string $username): void {
        global $DB;
        $user = $DB->get_record('user', ['username' => $username]);
        $user->password = hash_internal_user_password($this->get_user_password($username));
        $DB->update_record('user', $user);
        user_updated::create_from_userid($user->id)->trigger();
    }

    /**
     * Attempts to log in an anonymous user from the login page hook.
     *
     * @param string $username Username of the user to authenticate.
     * @param array $params Other parameters for the anonymous login.
     * @throws moodle_exception
     */
    private function login_anonymous_user(string $username, array $params): void {
        global $CFG, $DB, $USER;
        $altlogin = $CFG->alternateloginurl;
        $CFG->alternateloginurl = '';
        if ($user = authenticate_user_login($username, $this->get_user_password($username))) {
            complete_user_login($user);
            set_moodle_cookie($USER->username);
            // Use the default cohort if none was sent in the query parameters.
            $cohortname = $params['cohort'] ?? $this->cohort;
            // Enrol user into the cohort so they have access to all related courses.
            if ($cohortid = $DB->get_field('cohort', 'id', ['idnumber' => $cohortname])) {
                // This also internally triggers the `cohort_member_added` event.
                cohort_add_member($cohortid, $user->id);
            }
            if (($courseid = $params['course'] ?? 0) > 0 && $DB->record_exists('course', ['id' => $courseid])) {
                $urltogo = "/course/view.php?id=$courseid";
            } else {
                $urltogo = core_login_get_return_url();
            }
            redirect(new moodle_url($urltogo));
            // STOP! don't let any other auth plugin take over, including the built-in auth.
            // TODO: Check if this is really necessary.
            die();
        } else {
            // Restore alternate login url, let subsequent plugins take over.
            $CFG->alternateloginurl = $altlogin;
        }
    }

    /**
     * Constructs the not yet hashed password for an anonymous user from his username.
     *
     * @param string $username Username of the user for whom to make the password.
     * @return string Raw (unhashed) password for the given user.
     */
    private function get_user_password(string $username): string {
        // TODO: Switch to peppers.
        return $username . ($CFG->passwordsaltmain ?? '');
    }

    /**
     * Confirms that the relevant parameters exist.
     *
     * @param array $params Associative array of parameters.
     * @return bool `true` if the keys {@see self::KEYNAME} and `ts` are present.
     */
    private function validate_parameters(array $params): bool {
        return (isset($params[self::KEYNAME]) and isset($params['ts']));
    }

    /**
     * Validates that the time is within the allowed window from the current UNIX time.
     *
     * @param int $time Timestamp since UNIX epoch.
     * @return bool `true` if the provided timestamp is no more than {@see timeout} seconds in the past and not in the future.
     */
    private function validate_time(int $time): bool {
        if ($this->timeout === 0) return true;
        if ($time > time()) return false; // future time
        return time() - $time <= $this->timeout;
    }

    /**
     * Validates the key with the {@see validator} RegEx.
     *
     * @param string $key Key to validate.
     * @return bool `true` if the key matches the {@see validator} RegEx.
     */
    private function validate_key(string $key): bool {
        if (!str_starts_with($this->validator, '/')) $this->validator = '/'.$this->validator;
        if (!str_ends_with($this->validator, '/')) $this->validator = $this->validator.'/';
        return preg_match($this->validator, $key);
    }

    /**
     * Retrieves the query string from a URL.
     *
     * @param string $url Any URL string.
     * @return string Anything past the first occurrence of a question mark or an empty string, if no query parameters are present.
     */
    private function retrieve_query_string(string $url): string {
        if ($quespos = strpos($url, '?')) {
            return substr($url, $quespos + 1);
        }
        return '';
    }

    /**
     * Given a base64 encoded string, decodes and retrieves the query parameters.
     *
     * @param string $encstr Base64 encoded string.
     * @return array Associative array of decoded query parameters.
     */
    private function retrieve_encoded_params(string $encstr): array {
        $params = [];
        if ($decstr = base64_decode($encstr, strict: true)) {
            parse_str($decstr, $params);
        }
        return $params;
    }

    /**
     * Facilitates logout behavior.
     *
     * If we have a custom logout URL set AND the user is authenticated with this plugin, this overrides the redirect URL.
     */
    public function logoutpage_hook(): void {
        global $redirect, $USER;
        if ($USER->id > 0 && $USER->auth === $this->authtype && isset($this->config->logouturl)) {
            $redirect = $this->config->logouturl;
        }
    }

    /**
     * If a role for the anonymous user is configured, assigns the user to it.
     *
     * @throws coding_exception
     * @throws dml_exception
     */
    function sync_roles($user): void {
        if ($user && $this->role !== 0) {
            $systemcontext = context_system::instance();
            role_assign($this->role, $user->id, $systemcontext->id, 'auth_anonymous');
        }
    }
}
