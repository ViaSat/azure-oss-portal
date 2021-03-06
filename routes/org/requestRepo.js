//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

var express = require('express');
var router = express.Router();
var async = require('async');
var utils = require('../../utils');

router.use(function (req, res, next) {
    req.oss.addBreadcrumb(req, 'Request a new repo');
    next();
});

router.post('/', function (req, res, next) {
    var org = req.org;
    var oss = org.oss;
    if (!req.body.name || (req.body.name.length !== undefined && req.body.name.length === 0)) {
        return next(new Error('Please provide a repo name.'));
    }
    if (req.body.name.indexOf(' ') >= 0) {
        return next(utils.wrapError(null, 'Repos cannot have spaces in their name. Consider a dash.', true));
    }
    if (!req.body.justification || (req.body.justification.length !== undefined && req.body.justification.length === 0)) {
        return next(utils.wrapError(null, 'A justification is required.', true));
    }
    if (!(req.body.visibility == 'public' || req.body.visibility == 'private')) {
        req.body.visibility = 'public';
    }
    if (!req.body.teamCount) {
        return next(new Error('Invalid.'));
    }
    var teamsRequested = [];
    var teamCount = Math.floor(req.body.teamCount);
    var i = 0;
    for (i = 0; i < teamCount; i++) {
        var existingTeamId = req.body['existingTeam' + i];
        if (existingTeamId) {
            existingTeamId = Math.floor(existingTeamId);
            var perm = req.body['existingTeamPermission' + i];
            if (existingTeamId > 0 && perm == 'pull' || perm == 'push' || perm == 'admin') {
                var tr = {
                    id: existingTeamId,
                    permission: perm,
                };
                teamsRequested.push(tr);
            }
        }
    }
    var dc = req.app.settings.dataclient;
    var team = org.getRepoApproversTeam();
    var approvalRequest = {
        ghu: oss.usernames.github,
        ghid: oss.id.github,
        justification: req.body.justification,
        requested: ((new Date()).getTime()).toString(),
        active: false,
        teamid: team.id,
        type: 'repo',
        org: org.name.toLowerCase(),
        repoName: req.body.name,
        repoDescription: req.body.description,
        repoUrl: req.body.url,
        repoVisibility: req.body.visibility,
        email: oss.modernUser().contactEmail(),
    };
    approvalRequest.teamsCount = teamsRequested.length;
    for (i = 0; i < teamsRequested.length; i++) {
        approvalRequest['teamid' + i] = teamsRequested[i].id;
        approvalRequest['teamid' + i + 'p'] = teamsRequested[i].permission;
    }
    team.getMemberLinks(function (error, maintainers) {
        if (error) {
            return next(new Error('It seems that the repo approvers information is unknown, or something happened when trying to query information about the team you are trying to apply to. Please file a bug or try again later. Sorry!'));
        }
        if (maintainers === undefined || maintainers.length === undefined || maintainers.length === 0) {
            return next(new Error('It seems that the repo approvers for this team is unknown. Please file a bug. Thanks.'));
        }
        var randomMaintainer = maintainers[Math.floor(Math.random() * maintainers.length)];
        if (!randomMaintainer.link.ghu) {
            return next(new Error('For some reason the randomly picked maintainer is not setup in the compliance system properly. Please report this bug.'));
        }
        var assignTo = randomMaintainer.link.ghu;
        var allMaintainers = [];
        for (var i = 0; i < maintainers.length; i++) {
            if (maintainers[i].link.ghu) {
                allMaintainers.push('@' + maintainers[i].link.ghu);
            }
        }
        var consolidatedMaintainers = allMaintainers.join(', ');
        dc.insertGeneralApprovalRequest('repo', approvalRequest, function (error, requestId) {
            if (error) {
                return next(error);
            }
            var body = 'Hi,\n' + oss.usernames.github + ' has requested a new repo for the ' + org.name + ' ' +
                       'organization.' + '\n\n' +
                       consolidatedMaintainers + ': Can a repo approver for this org review the request now at ' + '\n' +
                       'https://azureopensource.azurewebsites.net/approvals/' + requestId + '?\n\n' + 
                       '<small>Note: This issue was generated by the open source portal.</small>' + '\n\n' +
                       '<small>If you use this issue to comment with the team maintainers(s), please understand that your comment will be visible by all members of the organization.</small>';
            var workflowRepository = org.getWorkflowRepository();
            workflowRepository.createIssue({
                title: 'Request to create a repo - ' + oss.usernames.github,
                body: body,
            }, function (error, issue, headers) {
                if (error) {
                    return next(utils.wrapError(error, 'A tracking issue could not be created to monitor this request. Please contact the admins and provide this URL to them. Thanks.'));
                }
                req.oss.saveUserAlert(req, 'Your repo request has been submitted and will be reviewed by one of the repo approvers for the org for naming consistency, business justification, etc. Thanks!', 'Repo Request Submitted', 'success');
                    if (issue.id && issue.number) {
                    dc.updateApprovalRequest(requestId, {
                        issueid: issue.id.toString(),
                        issue: issue.number.toString(),
                        active: true
                        }, function (error) {
                            workflowRepository.updateIssue(issue.number, {
                                assignee: assignTo,
                            }, function (gitError) {
                                if (error) {
                                    return next(error);
                                } else {
                                    // CONSIDER: Log gitError. Since assignment fails for users
                                    // who have not used the portal, it should not actually
                                    // block the workflow from assignment.
                                    oss.render(req, res, 'message', 'Repo request submitted', {
                                    messageTitle: req.body.name.toUpperCase() + ' REPO',
                                    message: 'Your request has been submitted for review to the approvers group for the requested organization.'
                                });
                            }
                        });
                    });
                } else {
                    return res.redirect('/');
                }
            });
        });
    });
});

router.get('/', function (req, res, next) {
    var org = req.org;
    var orgName = org.name.toLowerCase();
    var highlightedTeams = org.inner.settings.highlightedTeams;
    var allowPrivateRepos = org.inner.settings.type == 'publicprivate';
    org.getTeams(false /* do not use cached */, function (error, teams) {
        if (error) {
          return next(utils.wrapError(error, 'Could not read the entire list of read (pull) teams from GitHub. Please try again later or report this error if you continue seeing it.'));
        }
        var team;
        try {
            team = org.getRepoApproversTeam();
        } catch (ex) {
            // If the organization does not have a repo approvers team, we assume
            // that they allow any of their members to create repos directly on
            // the GitHub site.
            var err = new Error('This organization allows the creation of repositories directly on GitHub.');
            err.skipLog = true;
            err.fancyLink = {
                link: 'https://github.com/organizations/' + org.name + '/repositories/new',
                title: 'Create a new repo directly on GitHub',
            };
            return next(err);
        }
        team.getMemberLinks(function (error, approvers) {
              if (error) {
                  return next(new Error('Could not retrieve the repo approvers for ' + orgName));
              }
              var selectTeams = [];
              var i = 1;
              var featuredTeamsCount = highlightedTeams.length;
              for (; i < featuredTeamsCount + 1; i++) {
                  var ht = highlightedTeams[i - 1];
                  ht.number = i;
                  ht.name = org.team(ht.id).name;
                  selectTeams.push(ht);
              }
              var allMembersTeam = org.getAllMembersTeam();
              ++featuredTeamsCount;
              selectTeams.push({
                  number: i++,
                  name: allMembersTeam.name,
                  id: allMembersTeam.id,
                  info: 'This team automatically contains all members of the "' + org.name + '" organization who have linked corporate identities. Broad read access suggested.',
              });
              for (; i < featuredTeamsCount + 5; i++) {
                  selectTeams.push({
                      number: i
                  });
              }
              org.oss.render(req, res, 'org/requestRepo', 'Request a a new repository', {
                orgName: orgName,
                orgConfig: org.inner.settings,
                allowPrivateRepos: allowPrivateRepos,
                approvers: approvers,
                teams: teams,
                org: org,
                selectTeams: selectTeams,
              });
          });
    });
});

module.exports = router;
