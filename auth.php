<?php

/**
 * anonymous authentication plugin
 *
 * @package    auth
 * @subpackage anonymous
 * @author tim.stclair@gmail.com
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once ($CFG->libdir . '/authlib.php');
require_once ($CFG->dirroot . '/cohort/lib.php');

/**
 * Avant authentication plugin extends the base class.
 */
class auth_plugin_anonymous extends auth_plugin_base
{

    const KEYNAME = "key"; // param to look for in the decoded url data
    const FIRSTNAME = "anonymous";
    const LASTNAME = "user";
    const EMAIL = "anonymous@127.0.0.1";
    const COHORT = "anonymous"; // the idnumber of the cohort to add the user to (used for enrolment into the course)
    const TIMEOUT = 0; //18000; // set to 0 to bypass timeout

    private $salt = '93d5dded6d6cc57a62dbadda6d2fc260';

    /**
     * Constructor
     */
    public function __construct() {
        $this->authtype = 'anonymous';
        $this->config = get_config('auth_anonymous');
    }

    /**
     * Returns true if the passed username and password validate.
     *
     * @param string $username  the passed username
     * @param string $password  cleartext password
     * @return boolean
     */
    public function user_login($username, $password) {
        global $CFG, $DB;
        if ($user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id))) {
            // The following should always return false for this plugin as we
            // don't store passwords internally. However we keep the check here
            // for consistency.
            $valid = validate_internal_user_password($user, $password);
            return $valid;
        }
        return false;
    }

    /**
     * We do not authenticate directly to moodle user table
     *
     * @return boolean
     */
    public function is_internal() {
        return false;
    }

    /**
     * Called at the start of the login page. This is the main landing point
     * for the anonymous authentication as we are doing sso ie we trust the calls
     * and simply log the user in. If the account doesn't exist then we simply
     * create it.
     */
    public function loginpage_hook() {
        global $FULLME, $DB, $CFG, $USER;

        $auth = optional_param('auth', '', PARAM_ALPHANUM);
        $altlogin = $CFG->alternateloginurl;
        if (empty($auth)) {
            $params = $this->retrieve_encoded_params($this->retrieve_query_string($FULLME));
        } else {
            $params = $this->retrieve_encoded_params($auth);
        }

        // if key 'anon' is set within encoded params, we should process this request using this plugin
        if ($hook_is_active = ($params && isset($params['anon']) && $params['anon'] === '1')) {
            $CFG->alternateloginurl = '';
        }

        if ($hook_is_active && ($this->validate_parameters($params) and $this->validate_time($params['ts']))) {
            $identifier = md5($this->authtype . $params[self::KEYNAME]); // will yield a 32 char hash
            // $identifier = substr($this->authtype . $params[self::KEYNAME], 0, 100); // crop to username field length

            if (!$DB->record_exists('user', ['username' => $identifier, 'mnethostid' => $CFG->mnet_localhost_id, 'auth' => $this->authtype])) {
                $user = new stdClass;
                $user->username = $identifier;
                $user->idnumber = $params[self::KEYNAME];
                $user->password = hash_internal_user_password($identifier . $this->salt);
                $user->firstname = self::FIRSTNAME;
                $user->lastname = self::LASTNAME;
                $user->email = self::EMAIL;
                $user->country = 'AU';
                $user->auth = $this->authtype;
                $user->mailformat = 0;
                $user->maildisplay = 0;
                $user->autosubscribe = 0;
                $user->mnethostid = $CFG->mnet_localhost_id;
                $user->confirmed = 1;

                $user->id = $DB->insert_record('user', $user);
                $user = $DB->get_record('user', array('id' => $user->id));
                \core\event\user_created::create_from_userid($user->id)->trigger();
            }

            if ($user = authenticate_user_login($identifier, $identifier . $this->salt)) {

                complete_user_login($user);
                set_moodle_cookie($USER->username);

                // enrol users into the anonymous cohort so they have access to all courses
                if ($DB->record_exists('cohort', array('idnumber'=> self::COHORT ))) {
                    $cohortrow = $DB->get_record('cohort', array('idnumber' => self::COHORT));
                    if (!$DB->record_exists('cohort_members', array('cohortid'=>$cohortrow->id, 'userid'=>$user->id))) {
                        cohort_add_member($cohortrow->id, $user->id); // internally triggers cohort_member_added event
                    }
                }

                if ($courseid = isset($params['course']) ? $params['course'] : 0 > 0) {
                    $urltogo = "/course/view.php?id=$courseid";
                } else {
                    $urltogo = core_login_get_return_url();
                }

                redirect(new moodle_url($urltogo));
                die();  // STOP! don't let any other auth plugin take over, including the built-in auth

            } else {
                // restore alternate login url, let subsequent plugins take over
                $CFG->alternateloginurl = $altlogin;
            }

        }
    }

    /**
     * Confirm the expected parameters that are passed in exist
     *
     * @param array $params
     * @return boolean
     */
    private function validate_parameters($params) {
        return (isset($params[self::KEYNAME]) and isset($params['ts']));
    }

    /**
     * Validate a time parameter to be within the allowed minutes of current unix time
     *
     * @param int $time
     * @return boolean
     */
    private function validate_time($time) {
        if (self::TIMEOUT === 0) return true;
        return (abs(time() - intval($time)) < self::TIMEOUT);
    }

    /**
     * Retrieve the query string from a url
     *
     * @param string $url  full url
     * @return string
     */
    private function retrieve_query_string($url) {
        if ($quespos = strpos($url, '?')) {
            return substr($url, $quespos + 1);
        }
        else {
            return '';
        }
    }

    /**
     * Given a base64 encoded string, decode and retrieve the GET style params
     *
     * @param string $encstr  base64 encoded string
     * @return array
     */
    private function retrieve_encoded_params($encstr) {
        $params = array();

        if ($decstr = base64_decode($encstr, true)) {
            if ($gps = explode('&', $decstr)) {
                foreach ($gps as $gp) {
                    $pp = explode('=', $gp);
                    $params[$pp[0]] = isset($pp[1]) ? rawurldecode($pp[1]) : "";
                }
            }
        }
        return $params;
    }

    /**
     * user has clicked LOG OUT
     * If we have a custom logout set AND authenticated with this plugin, override it
     *
     * @global object
     * @global string
     */
    public function logoutpage_hook() {
        global $redirect, $USER;
        if ($USER->id > 0 && $USER->auth === $this->authtype && isset($this->config->logouturl)) {
            $redirect = $this->config->logouturl;
        }
    }


    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param stdClass $config
     * @return void
     */
    function process_config($config) {
        // Save settings.
        set_config('logouturl', $config->logouturl, 'auth_anonymous');
        return true;
    }
}
