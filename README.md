# GCPSUDOBOT
A slackbot for time limited, conditional IAM grants to GCP infrastructure.

## Usage

There is a slash command registered under `/sudo`.  That will require a user specifying a Reason, Role, and Resource.  Once specified, the user's google group membership will be looked up, and that rule will be authorized against a PolicyRule containing Group, Role and Resource combinations.


![alt text](<screenshots/Screenshot 2024-03-21 at 11.21.39 AM.png>)

Hiting submit will post a message into the slack channel that is configured with the `SLACK_CHANNEL` env var.

![alt text](<screenshots/Screenshot 2024-03-21 at 11.21.52 AM.png>)

That message can be approved or denied. If approved, the bot will do a conditional IAM grant on the specified resource with that role. In this case, I am going to deny it, and the bot will edit the message to show that it has been denied.

![alt text](<screenshots/Screenshot 2024-03-21 at 11.22.11 AM.png>)



## Defining PolicyRules

PolicyRules is the structure defining the authorization the slackbot will allow.  It consists of a list of Rules, each of which consist of a map of Groups, Roles, and Resources. Without PolicyRules defined, every request will be denied by default. There is no support for wildcards, individual membership, or hierarchical rules. 

A user requesting to escalate their permissions must be in the correct google group, and the role and resource they requested must be in a rule that includes that group.

The `POLCIY_RULES` env var must be set to a valid JSON containing the configuration for authorization that should be used. 

Resources must be organizations or projects. Folders are currently not supported.

Roles should generally point to a custom role granting the necessary roles for that permission.

It's structure looks like so:

```
{
  "policy_rules": [
    {
      "groups": {
        "on-call@gmail.com": {}
      },
      "roles": {
        "organizations/0000000000/roles/on_call_elevated": {}
      },
      "resources": {
        "organizations/0000000000": {}
      }
    },
    {
      "groups": {
        "on-call@gmail.com": {}
      },
      "roles": {
        "organizations/0000000000/roles/on_call_elevated": {}
      },
      "resources": {
        "projects/testing": {}
      }
    },
    {
      "groups": {
        "prod-db-access@gmail.com": {}
      },
      "roles": {
        "roles/cloudsql.admin": {}
      },
      "resources": {
        "projects/testing": {}
      }
    },
    {
      "groups": {
        "on-call@gmail.com": {}
        "on-call-sudo@gmail.com": {}
      },
      "roles": {
        "organizations/0000000000/roles/root": {}
      },
      "resources": {
        "organizations/0000000000": {}
        "projects/testing": {}
      }
    }
  ]
}
```


## Deployment

This is designed to be designed deployed with GCP Cloud Functions with a unique service account, that is granted the permission to change IAM in an organization or high level folder. That grants the bot the permission to do IAM changes on any resources below it. For granting roles on project level resources the cloudfunction's service account should be granted the `roles/resourcemanager.projectIamAdmin`.


## Local Development
Create a slack workspace for testing.

Utilize ngrok to setup a temporary URL you can configure in slack. The URL needs to be put into interactivity and slash commands.
`ngrok http --domain=<YOUR_DOMAIN_HERE> 8080`

Use your domain to create a new SLACK_APP_MANIFEST_DEV.yml, and then install a new app in your slack workspace using that manifest.  You'll then need to grab the Slack Channel you want to use, SigningSecret and Slack API Token, and use them to fill in the environment variables below:

`SLACK_API_TOKEN="xoxb-XXXXXXXXXXXX-XXXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX" SLACK_SECRET="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" SLACK_CHANNEL="XXXXXXXXX" MOCK_GOOGLE_APIS="true" go run cmd/main.go`

This is mocking the Google API calls, which you'll almost assuredly want for local development.  But if you do need to run real IAM requests locally, you can utilize ADC assuming you have valid credentials yourself. However, be very cautious to not point at any non-test resources while doing that work.

## Permission to check google group membership

One of the critical functionalities of this bot is to verify a user requesting permissions to escalate their permissions belongs in a specific google group with access to that role.  In order to do this, the serivce account that this bot uses needs to be Delegated Domain-Wide Authority to impersonate a Gsuite Administrator. Critically, when setting this up it should only be granted the scope: https://www.googleapis.com/auth/admin.directory.group.readonly. For setup instructions, see: https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority. 

## Security Design:

This slackbot is built to allow engineers to elevate their IAM permissions in GCP according to a predefined policy, with another user having to approve the request. These elevated permissions are conditionally granted for 2 hours, but that is configurable.

The PolicyRule is a list of Rules objects composed of the Groups,Roles, and Resources that Rule authorizes. By default it denies all authorization requests, unless a specific rule matches.  There is no support for wildcards. Roles generally map to custom IAM roles in GCP, created at the org level. Since the policy rules are defined as an env var, it's important for the configuration to be defined in code so that the normal changemanagement procedures apply. It is recommended to configure GITOWNERS on the file where POLICY_RULES is defined and require multiple reviewers. It’s easier to spend more time upfront scrutinizing the policy because a review will only be required once for each new Rule.

The slackbot is deployed as an unauthenticated cloud function, so it is open to the internet. That access is locked down by verifying the requests came from slack and rejecting all others. When registering the bot to our slack workspace, a unique signing secret is generated.  All requests from slack to the bot are verified by a signing secret unique to this instance of the bot. Any unverified requests to the slackbot result in an error message.  Additionally all requests to and from slack happen over HTTPS. 

An additional mechanism to prevent access from the entire internet is to setup an IP Allowlist, by using a CloudNAT with a static IP from the Cloud Function, it can appear that traffic to Slack is coming from a stable IP. The IP Allowlist can then be configured in the slack manifest. https://cloud.google.com/functions/docs/networking/network-settings#associate-static-ip & https://api.slack.com/authentication/best-practices#configure-allowed-ip


Authentication is provided primarily by Slack.  The workspace domain you use to login to slack should be configured as the `VALID_DOMAIN` env var. This prevents users from other domains being able to approve or have requests approved.

Authorization happens through two main mechanisms.

Google group membership is looked up to determine all of the groups a user belongs to.
A policy contains a list of ACL’s that describe which google groups are allowed access to GCP resources with specific roles. An ACL cannot be used for an individual account.
Only `VALID_DOMAIN` email addresses can be used to request or approve.

The authorization checks happen both when creating the escalation request, and again after the approval is submitted.  This makes it so that even if somehow a malicious slack response was sent, at worst it can only grant permissions that are valid according to the policy.

The bot itself can only grant access to resources at its level or below it’s service account in the GCP hierarchy. (Technically the service account could be added in multiple spots, but usually easier to have it in one spot and propagate down the tree). The service account must be granted `roles/resourcemanager.projectIamAdmin` and/or the following permissions if wanting to control changes at the organizational level: 

```
    resourcemanager.organizations.get
    resourcemanager.organizations.getIamPolicy
    resourcemanager.organizations.setIamPolicy
```

The google group lookup needs to utilize the admin sdk’s directory api. This endpoint requires a user to be a Google Workspace Admin.  This bot requires it’s service account to have been granted domain-wide delegation in order to impersonate a Google Workspace User.  Critically, when setting up the domain-wide delegation, it’s important to set it’s oauth scopes to only allow read only access to see the members of Google Groups. This scope is also set in the bot’s code, but that could potentially be changed by non-Workspace Administrators.

It’s critically important to restrict access to the bot’s GCP Project, as deploying arbitrary code could be used to implement malicious policies (disable authz checks).

Onboarding/Offboarding access should generally happen naturally as users are added/removed from google groups.

The go vuln tool is used as part of the CI process to ensure that vulnerabilities that apply to this codebase are found quickly and patched.

The oauth scopes that this bot uses are the minimal possible scopes in order to function, and they are defined in the slack manifest.

## Contributing:

Happy to accept contributions, please open a PR. 

Quick overview of the codebase can be found here:

`function.go` - This is the entrypoint to the codebase, with ActionHandler and SlashHandler being the entrypoint for cloudfunctions.

`types/` - Defines global types for the codebase.

`gcp/` - Code related to listing Google Group Membership or Getting/Setting IAM Policies. Please use caution in this section, as bugs here could irrevocably delete GCP IAM policies.

`config/` - Defines the config for running the slackbot, along with some default values that the tests use.

`authz/` - This handles authorization, for both pre and post approval.

`slacking/` - This handles parsing slack messages as well as the slack UI components for the modals and messages.

`cmd/` - this is used for local development to run a server exposing the SlashHandler and ActionHandler on `:8080`



## Future Improvements:

* Allow self approval for certain rules
* Look-up current on-call to allow more aggressive permission escalations
* Add 2fa with TOTP to certain rolls
* Finish implementing the IP allowlist in slack
* mTLS
* Slack Token Rotation - seems hard to manage without a long lived process as we'd be responsible for exchanging the token periodically

## Known issues

The bot currently doesn't cleanup any of it's conditional grants. The IAM grants may stop working at 50+ grants on a single user, in which case you just need to manually remove them. A future improvement should be adding TTL's to the grants to delete them a certain time after they've expired.

## Special Thanks

Want to give thanks to Pachyderm for allowing me to open source some internal tooling I built while I worked there, including an early predecessor of this bot.
