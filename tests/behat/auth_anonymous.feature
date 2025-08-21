@auth @auth_anonymous
Feature: Anonymous authentication.

  Background:
    Given the following config values are set as admin:
      | auth      | anonymous     |                |
      | firstname | behat_anon    | auth_anonymous |
      | lastname  | anon_lastname | auth_anonymous |

  @javascript
  Scenario: Automatically having an account created, being and staying logged in.
    When I follow an anonymous login link
    Then I should see "Welcome, behat_anon! 👋"
    When I close all opened windows
    And I am on homepage
    Then I should see "You are logged in as behat_anon anon_lastname"
