<?php
/**
 * Aurora authentication plugin language strings
 *
 * @package    auth
 * @subpackage anonmyous
 * @author tim.stclair@gmail.com
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();


$string['auth_anonymousdescription'] = 'Login requests are sent from external system as a form submission to the moodle login page.';
$string['pluginname'] = 'Anonymous Authentication';

$string['cohort_desc'] = 'The idnumber of a cohort to add the user to (optional; skipped if the cohort cannot be found).';

$string['logouturl'] = 'Logout url';
$string['logouturl_desc'] = 'If set, users who log out using this authentication method will be redirected to this url afterwards.';

$string['keyregex'] = 'Key regex';
$string['keyregex_desc'] = 'A regular expression to validate the key against. If set, the key must match this regex to be valid.';

$string['settings_desc'] = 'When authenticating as an anonymous user, a user record matching the key specified will be found or created and used for standard login. Users require a firstname, lastname and email to be set so these will be set to the values or defaults shown below.';

$string['timeout'] = 'Link timeout';
$string['timeout_desc'] = 'The link contains a timestamp. This setting determines how long before it is rejected.';