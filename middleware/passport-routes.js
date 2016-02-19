//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

module.exports = function configurePassport(app, passport) {
    // ----------------------------------------------------------------------------
    // passport integration with GitHub
    // ----------------------------------------------------------------------------
    app.get('/signin/github', function (req, res) {
        if (req.session && req.headers && req.headers.referer) {
            req.session.referer = req.headers.referer;
        }
        return res.redirect('/auth/github');
    });

    app.get('/auth/github',
        passport.authenticate('github'),
        function (req, res){
            // The request will be redirected to GitHub for authentication, so this
            // function will not be called.
        });

    app.get('/auth/github/callback', 
        passport.authenticate('github', { failureRedirect: '/failure/github' }),
        function (req, res) {
            var url = '/';
            if (req.session && req.session.referer) {
                url = req.session.referer;
                delete req.session.referer;
            }
            res.redirect(url);
        });

    app.get('/signout', function (req, res) {
        req.logout();
        res.redirect('/');
    });

    // ----------------------------------------------------------------------------
    // Expanded GitHub auth scope routes
    // ----------------------------------------------------------------------------
    app.get('/signin/github/increased-scope', 
        function (req, res) {
            if (req.session && req.headers && req.headers.referer) {
                req.session.referer = req.headers.referer;
            }
            return res.redirect('/auth/github/increased-scope');
        }
    );

    app.get('/auth/github/increased-scope', passport.authorize('expanded-github-scope'));

    app.get('/auth/github/callback/increased-scope', 
        passport.authorize('expanded-github-scope'), 
        function (req, res, next) {
            var account = req.account;
            var user = req.user;
            user.github.increasedScope = account;
            var url = '/';
            if (req.session && req.session.referer) {
                url = req.session.referer;
                delete req.session.referer;
            }
            res.redirect(url);
        });

    // ----------------------------------------------------------------------------
    // passport integration with Azure Active Directory
    // ----------------------------------------------------------------------------
    app.get('/auth/saml', passport.authorize('saml'));

    app.post('/auth/saml/callback',
        passport.authorize('saml'),
        function(req, res, next) {
            acct = req.account
            if (acct !== null && acct.sAMAccountName && acct.displayName) {
                req.user.corp = {
                    displayName: acct.displayName,
                    // oid: account._json.oid,
                    username: acct.sAMAccountName,
                };
                var url = '/';
                if (req.session && req.session.referer) {
                    url = req.session.referer;
                    delete req.session.referer;
                }
                return res.redirect(url);
            } else {
                // console.log(next)
                throw new Error('Corporate-side SAML authentication failed.');
            }
        }
    );

    app.get('/signin/corp', function(req, res){
        if (req.session && req.headers && req.headers.referer) {
            if (req.session.referer === undefined) {
                req.session.referer = req.headers.referer;
            }
        }
        return res.redirect('/auth/saml');
    });

    app.get('/signout/corp', function(req, res){
        if (req.user && req.user.corp) {
            delete req.user.corp;
        }
        res.redirect('/');
    });

    app.get('/auth/saml/sp-metadata', 
        function(req, res){
            res.set('Content-Type', 'text/xml')
            res.send(
                passport._strategy('saml').generateServiceProviderMetadata(app.get('runtimeConfig').saml.decryptionCert)
            );
        }
    );
};
