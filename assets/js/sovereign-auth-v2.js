/**
 * Sovereign Auth — Frontend Controller  v1.1.0
 *
 * FIXES (carried over from v1.0.1):
 *  Bug #1 — All buttons have type="button" to prevent native form submission.
 *  Bug #8 — bufferToB64url() uses a for-loop instead of spread, avoiding
 *            "Maximum call stack size exceeded" on large attestation payloads.
 *
 * ARCH CHANGE — No recovery fallback in Lite version.
 *
 * HOTFIX UI — Double username:
 *   init() now aggressively hides every known WP native form element with
 *   element.style.setProperty('display','none','important') in JS, on top of
 *   the PHP <head> inline style and the CSS rules — three independent layers
 *   that together guarantee no WP native field is ever visible.
 *
 * HOTFIX UX — HTTP 409 / username already taken:
 *   A typed SovAuthError carries code + httpStatus from the server.
 *   handleStep1() catches httpStatus===409 and shows the Italian message
 *   "Username already in use, please choose another." with a red border on the field
 *   and auto-selects the text so the user can retype immediately.
 */

( function () {
    'use strict';

    const cfg = window.SovAuthConfig;
    if ( ! cfg ) return;

    /* ════════════════════════════════════════════════════════
       TYPED ERROR
       Carries HTTP status + server error code so callers can
       branch on specific conditions without string matching.
    ════════════════════════════════════════════════════════ */

    class SovAuthError extends Error {
        /**
         * @param {string} message   Human-readable message from the server.
         * @param {string} code      Server-side code (e.g. 'username_exists').
         * @param {number} httpStatus HTTP status (e.g. 409).
         */
        constructor( message, code = '', httpStatus = 0 ) {
            super( message );
            this.name       = 'SovAuthError';
            this.code       = code;
            this.httpStatus = httpStatus;
        }
    }

    /* ════════════════════════════════════════════════════════
       BASE64URL
    ════════════════════════════════════════════════════════ */

    function b64urlToBuffer( b64url ) {
        const b64    = b64url.replace( /-/g, '+' ).replace( /_/g, '/' );
        const padded = b64.padEnd( b64.length + ( ( 4 - b64.length % 4 ) % 4 ), '=' );
        const binary = atob( padded );
        const bytes  = new Uint8Array( binary.length );
        for ( let i = 0; i < binary.length; i++ ) bytes[ i ] = binary.charCodeAt( i );
        return bytes.buffer;
    }

    /**
     * Bug #8 fix: loop, not spread.
     * String.fromCharCode(...bytes) blows the call-stack on large buffers
     * (e.g. RSA public keys, long attestation blobs in RS256 authenticators).
     */
    function bufferToB64url( buffer ) {
        const bytes  = new Uint8Array( buffer );
        let   binary = '';
        for ( let i = 0; i < bytes.length; i++ ) {
            binary += String.fromCharCode( bytes[ i ] );
        }
        return btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=/g, '' );
    }

    /* ════════════════════════════════════════════════════════
       REST WRAPPER & PROOF OF WORK
    ════════════════════════════════════════════════════════ */

    async function solvePoW( path, bodyStr ) {
        let nonce = 0;
        const challenge = cfg.powChallenge;
        const encoder   = new TextEncoder();
        
        while ( true ) {
            const nonceStr = nonce.toString();
            const input    = challenge + nonceStr + path + ( bodyStr || '' );
            const buffer   = await crypto.subtle.digest( 'SHA-256', encoder.encode( input ) );
            const bytes    = new Uint8Array( buffer );
            
            // Check for '00000' hex prefix.
            // This means the first two bytes are 0x00, and the upper 4 bits of the third byte are 0x0.
            if ( bytes[0] === 0 && bytes[1] === 0 && ( bytes[2] & 0xF0 ) === 0 ) {
                return challenge + ':' + nonceStr;
            }
            
            nonce++;
            // Yield to main thread every 2000 iterations to prevent UI freeze
            if ( nonce % 2000 === 0 ) await new Promise( r => setTimeout( r, 0 ) );
        }
    }

    /**
     * Typed REST call. Throws SovAuthError on non-2xx responses,
     * carrying both the server's error code and the HTTP status.
     */
    async function api( path, body = null, method = 'POST' ) {
        const bodyStr = body && method !== 'GET' ? JSON.stringify( body ) : null;
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': cfg.nonce },
            credentials: 'same-origin',
        };
        if ( bodyStr ) opts.body = bodyStr;

        if ( cfg.torMode && method === 'POST' ) {
            // Compute Proof of Work before sending POST requests
            const fullPath = '/sovereign-auth/v1' + path;
            opts.headers[ 'X-SovAuth-PoW' ] = await solvePoW( fullPath, bodyStr );
        }

        const res  = await fetch( cfg.api + path, opts );
        const data = await res.json();

        if ( ! res.ok ) {
            throw new SovAuthError(
                data.message  || `HTTP ${res.status}`,
                data.code     || '',
                res.status
            );
        }
        return data;
    }

    /* ════════════════════════════════════════════════════════
       WEBAUTHN — REGISTRATION
    ════════════════════════════════════════════════════════ */

    async function webauthnRegister( pendingToken, webauthnOptions ) {
        if ( ! window.PublicKeyCredential ) {
            throw new SovAuthError( cfg.i18n.errWebauthnSupport );
        }

        const pubKey = {
            ...webauthnOptions,
            challenge          : b64urlToBuffer( webauthnOptions.challenge ),
            user               : { ...webauthnOptions.user, id: b64urlToBuffer( webauthnOptions.user.id ) },
            excludeCredentials : ( webauthnOptions.excludeCredentials || [] ).map( c => (
                { ...c, id: b64urlToBuffer( c.id ) }
            ) ),
        };

        const credential = await navigator.credentials.create( { publicKey: pubKey } );
        if ( ! credential ) throw new SovAuthError( cfg.i18n.errNoCred );

        return api( '/webauthn/register/verify', {
            pending_token : pendingToken,
            credential    : {
                id    : credential.id,
                rawId : bufferToB64url( credential.rawId ),
                type  : credential.type,
                response: {
                    clientDataJSON    : bufferToB64url( credential.response.clientDataJSON ),
                    attestationObject : bufferToB64url( credential.response.attestationObject ),
                },
            },
            device_name: getDeviceName(),
        } );
    }

    /* ════════════════════════════════════════════════════════
       WEBAUTHN — AUTHENTICATION
    ════════════════════════════════════════════════════════ */

    async function webauthnLogin() {
        if ( ! window.PublicKeyCredential ) {
            throw new SovAuthError( cfg.i18n.errWebauthnSupport );
        }

        const opts = await api( '/webauthn/auth/options' );

        const assertion = await navigator.credentials.get( {
            publicKey: {
                challenge        : b64urlToBuffer( opts.challenge ),
                rpId             : opts.rpId,
                timeout          : opts.timeout,
                userVerification : opts.userVerification,
                allowCredentials : [],
            },
        } );

        if ( ! assertion ) throw new SovAuthError( cfg.i18n.errAuthCancel );

        return api( '/webauthn/auth/verify', {
            challenge_key : opts.challengeKey,
            credential    : {
                id    : assertion.id,
                rawId : bufferToB64url( assertion.rawId ),
                type  : assertion.type,
                response: {
                    clientDataJSON    : bufferToB64url( assertion.response.clientDataJSON ),
                    authenticatorData : bufferToB64url( assertion.response.authenticatorData ),
                    signature         : bufferToB64url( assertion.response.signature ),
                    userHandle        : assertion.response.userHandle
                                        ? bufferToB64url( assertion.response.userHandle )
                                        : null,
                },
            },
            remember: false,
        } );
    }



    /* ════════════════════════════════════════════════════════
       UTILITIES
    ════════════════════════════════════════════════════════ */

    function getDeviceName() {
        const ua = navigator.userAgent;
        if ( /iPhone/.test( ua ) )  return 'iPhone';
        if ( /iPad/.test( ua ) )    return 'iPad';
        if ( /Android/.test( ua ) ) return 'Android';
        if ( /Mac/.test( ua ) )     return 'Mac';
        if ( /Windows/.test( ua ) ) return 'Windows PC';
        return 'Device';
    }

    function qs( sel, ctx = document ) { return ctx.querySelector( sel ); }

    /**
     * Element factory.
     * Bug #1 fix: 'type' attribute is passed explicitly on every <button>.
     */
    function el( tag, attrs = {}, ...children ) {
        const node = document.createElement( tag );
        Object.entries( attrs ).forEach( ( [ k, v ] ) => {
            if ( k === 'class' ) node.className = v;
            else if ( k.startsWith( 'on' ) ) node.addEventListener( k.slice( 2 ), v );
            else node.setAttribute( k, v );
        } );
        children.forEach( c => node.append( typeof c === 'string' ? document.createTextNode( c ) : c ) );
        return node;
    }



    /* ════════════════════════════════════════════════════════
       LOGIN UI
    ════════════════════════════════════════════════════════ */

    function buildLoginUI( root ) {
        root.innerHTML = '';

        root.append( bioPanel, errBox );

        if ( ! cfg.isPremium ) {
            const fallbackRow = el( 'div', { style: 'margin-top: 20px; text-align: center; font-size: 13px;' },
                el( 'a', { href: '#', onclick: showNativeForm, style: 'color: #2271b1; text-decoration: none;' }, 'Accedi con Password' ),
                el( 'span', { style: 'margin: 0 10px; color: #ccd0d4;' }, '|' ),
                el( 'a', { href: '?action=lostpassword', style: 'color: #2271b1; text-decoration: none;' }, 'Password dimenticata?' )
            );
            root.append( fallbackRow );
        }

        if ( cfg.canRegister ) {
            const regBtn = el( 'a', { class: 'sov-btn sov-btn--outline', href: cfg.regUrl, style: 'width: 100%; margin-top: 20px;' }, cfg.i18n.btnGoRegister );
            root.append( regBtn );
        }

        /* ── Helpers ── */



        function showNativeForm( ev ) {
            if ( ev ) ev.preventDefault();
            root.style.display = 'none';
            const wpSelectors = [
                '#loginform > *:not(.sovauth-root)',
                '#user_login', '#user_pass', '#wp-submit', '.user-pass-wrap', '.login-submit', 'label[for="user_login"]', 'label[for="user_pass"]'
            ].join( ', ' );
            document.querySelectorAll( wpSelectors ).forEach( node => {
                node.style.setProperty( 'display', 'block', 'important' );
            } );
        }

        function setStatus( id, msg, type = 'info' ) {
            const node = qs( `#${id}` );
            if ( node ) { node.textContent = msg; node.className = `sov-status sov-status--${type}`; }
        }
        function setErr( msg ) {
            errBox.textContent = msg;
            errBox.classList.remove( 'sov-hidden' );
        }
        function clearErr() { errBox.classList.add( 'sov-hidden' ); }

        function setLoading( id, on ) {
            const btn = qs( `#${id}` );
            if ( ! btn ) return;
            btn.disabled    = on;
            btn.dataset.orig = btn.dataset.orig || btn.textContent;
            btn.textContent  = on ? '…' : btn.dataset.orig;
        }

        /* ── Handlers ── */

        async function handleBioLogin() {
            clearErr();
            setLoading( 'sov-bio-btn', true );
            setStatus( 'sov-bio-status', cfg.i18n.statusWaitBio, 'info' );
            try {
                const res = await webauthnLogin();
                setStatus( 'sov-bio-status', cfg.i18n.statusAuthSuccess, 'success' );
                window.location.href = res.redirect;
            } catch ( e ) {
                setLoading( 'sov-bio-btn', false );
                setErr( e.message );
                setStatus( 'sov-bio-status', cfg.i18n.statusAuthFail, 'error' );
            }
        }


    }

    /* ════════════════════════════════════════════════════════
       REGISTER UI
    ════════════════════════════════════════════════════════ */

    function buildRegisterUI( root ) {
        root.innerHTML = '';

        /* ── Step 1: username — no PIN ── */
        const usernameIn = el( 'input', {
            type: 'text', id: 'sov-reg-username',
            placeholder: cfg.i18n.phUsername,
            class: 'sov-input',
            autocomplete: 'username', minlength: '3', maxlength: '60',
        } );

        let emailIn = null;
        const step1Children = [ el( 'p', { class: 'sov-lead' }, cfg.i18n.lblNoEmail ), usernameIn ];

        if ( ! cfg.isPremium ) {
            emailIn = el( 'input', {
                type: 'email', id: 'sov-reg-email',
                placeholder: 'Email (per recupero password)',
                class: 'sov-input',
                style: 'margin-top: 15px;',
                required: 'required'
            } );
            step1Children[0].textContent = 'Scegli un username e inserisci la tua email.';
            step1Children.push( emailIn );
        }

        const nextBtn = el( 'button', { type: 'button', class: 'sov-btn sov-btn--primary', id: 'sov-reg-next', onclick: handleStep1 }, cfg.i18n.btnContBio );
        const errBox  = el( 'div', { class: 'sov-error sov-hidden', id: 'sov-reg-error' } );
        
        step1Children.push( nextBtn, errBox );
        const step1   = el( 'div', { class: 'sov-step', id: 'sov-step-1' }, ...step1Children );

        // HOTFIX UX: clear error state when user edits the username field
        // (clearErr is a function declaration → hoisted, safe to reference here)
        usernameIn.addEventListener( 'input', () => {
            usernameIn.classList.remove( 'sov-input--error' );
            clearErr();
        } );

        /* ── Step 2: biometric ── */
        const bioRegBtn = el( 'button', { type: 'button', class: 'sov-btn sov-btn--primary sov-btn--large', id: 'sov-bio-reg-btn', onclick: handleBioRegister }, cfg.i18n.btnRegBio );
        const bioRegSt  = el( 'p', { class: 'sov-status', id: 'sov-bio-reg-status' }, cfg.i18n.lblConfirmBio );
        const step2     = el( 'div', { class: 'sov-step sov-hidden', id: 'sov-step-2' },
            el( 'h3', { class: 'sov-step-title' }, cfg.i18n.lblStep2 ),
            el( 'p',  { class: 'sov-note' },        cfg.i18n.lblBioLocal ),
            bioRegBtn, bioRegSt
        );

        /* ── Step 3: Success ── */
        const step3 = el( 'div', { class: 'sov-step sov-hidden', id: 'sov-step-3' } );

        root.append( step1, step2, step3 );

        if ( cfg.isAdminSetup == 1 ) {
            // Lock Step 1 to current user
            usernameIn.value = cfg.currentUser || 'admin';
            usernameIn.readOnly = true;
            usernameIn.style.opacity = '0.6';
            usernameIn.style.cursor = 'not-allowed';
            step1Children[0].textContent = 'Registrazione dispositivo per l\'account:';
            if ( emailIn ) {
                emailIn.style.display = 'none';
                emailIn.removeAttribute('required');
            }
        }

        /* ── State ── */
        let _pendingToken  = null;
        let _webauthnOpts  = null;

        let _redirect      = null;

        /* ── Helpers ── */

        function setErr( msg ) {
            errBox.textContent = msg;
            errBox.classList.remove( 'sov-hidden' );
        }
        function clearErr() { errBox.classList.add( 'sov-hidden' ); }

        function setLoading( id, on ) {
            const btn = qs( `#${id}` );
            if ( ! btn ) return;
            btn.disabled     = on;
            btn.dataset.orig = btn.dataset.orig || btn.textContent;
            btn.textContent  = on ? '…' : btn.dataset.orig;
        }

        function goto( stepId ) {
            [ 'sov-step-1', 'sov-step-2', 'sov-step-3' ].forEach( id =>
                qs( `#${id}` ).classList.toggle( 'sov-hidden', id !== stepId )
            );
        }

        /* ── Step handlers ── */

        /**
         * HOTFIX UX — 409 handling:
         * If the server returns HTTP 409 (username_exists), show the Italian
         * message, mark the field with a red border, and focus+select so
         * the user can type a new name immediately without extra clicks.
         */
        async function handleStep1() {
            clearErr();
            
            if ( cfg.isAdminSetup == 1 ) {
                goto( 'sov-step-2' );
                return;
            }

            usernameIn.classList.remove( 'sov-input--error' );
            if ( emailIn ) emailIn.classList.remove( 'sov-input--error' );
            const username = usernameIn.value.trim();
            if ( username.length < 3 ) {
                setErr( cfg.i18n.errUserLength );
                return;
            }
            let reqBody = { username };
            if ( ! cfg.isPremium ) {
                const email = emailIn.value.trim();
                if ( ! email || ! email.includes( '@' ) ) {
                    setErr( 'Inserisci un indirizzo email valido.' );
                    return;
                }
                reqBody.email = email;
            }

            setLoading( 'sov-reg-next', true );
            try {
                const res     = await api( '/user/create', reqBody );
                _pendingToken = res.pending_token;
                _webauthnOpts = res.webauthn_options;
                goto( 'sov-step-2' );
            } catch ( e ) {
                setLoading( 'sov-reg-next', false );
                if ( e instanceof SovAuthError && e.httpStatus === 409 ) {
                    // Username taken — user must pick another, no flow reset needed
                    usernameIn.classList.add( 'sov-input--error' );
                    setErr( cfg.i18n.errUserTaken );
                    usernameIn.select();
                    usernameIn.focus();
                } else {
                    setErr( e.message );
                }
            }
        }

        async function handleBioRegister() {
            bioRegSt.textContent = cfg.i18n.statusWaitBioConf;
            setLoading( 'sov-bio-reg-btn', true );
            try {
                let res;
                if ( cfg.isAdminSetup == 1 ) {
                    const opts = await api( '/webauthn/register/options', { tor_mode: cfg.torMode } );
                    res = await webauthnRegister( null, opts );
                } else {
                    res = await webauthnRegister( _pendingToken, _webauthnOpts );
                }
                

                _redirect      = res.redirect || cfg.redirect;

                qs( '#sov-step-3' ).innerHTML = `
                    <h3 class="sov-step-title">Done!</h3>
                    <p class="sov-lead" style="color:#00a32a;font-weight:bold;">Registration complete.</p>
                    <p class="sov-note">Your biometric device has been registered. There is no recovery in this version.</p>
                    <button type="button" class="sov-btn sov-btn--primary" style="margin-top:20px;" onclick="window.location.href='${_redirect}'">Go to Dashboard</button>
                `;
                goto( 'sov-step-3' );
            } catch ( e ) {
                bioRegSt.textContent = cfg.i18n.statusFailed + e.message;
                bioRegSt.className   = 'sov-status sov-status--error';
                setLoading( 'sov-bio-reg-btn', false );
            }
        }



        function goDashboard() {
            if ( _redirect ) window.location.href = _redirect;
        }

    }

    /* ════════════════════════════════════════════════════════
       INIT
       HOTFIX UI — three-layer WP native field suppression:
         Layer 1: PHP login_head → inline <style id="sovauth-pre"> in <head>
         Layer 2: sovereign-auth.css rules
         Layer 3: THIS — JS inline style with !important wins even theme
                  CSS that uses !important on the same properties.
    ════════════════════════════════════════════════════════ */

    function init() {
        /* ── Layer 3: aggressive JS inline-style suppression ── */
        const wpSelectors = [
            /* Form children — catches everything across all WP versions */
            '#loginform    > *:not(.sovauth-root)',
            '#registerform > *:not(.sovauth-root)',
            /* Individual elements — belt-and-suspenders for theme edge cases */
            '#user_login',
            '#user_pass',
            '#user_email',
            '#wp-submit',
            'label[for="user_login"]',
            'label[for="user_pass"]',
            'label[for="user_email"]',
            '.user-pass-wrap',
            '.wp-pwd',
            '.forgetmenot',
            '.login-remember',
            '.login-submit',
            /* Elements outside the <form> */
            '#nav',
            '#backtoblog',
            '.login .nav',
            '.login #backtoblog',
            '#login_error',
            '.message',
            '.privacy-policy-page-link',
        ].join( ', ' );

        document.querySelectorAll( wpSelectors ).forEach( node => {
            node.style.setProperty( 'display', 'none', 'important' );
        } );

        /* ── Build our UIs ── */
        const loginRoot    = document.getElementById( 'sovauth-login-root'    );
        const registerRoot = document.getElementById( 'sovauth-register-root' );

        if ( loginRoot    ) buildLoginUI( loginRoot );
        if ( registerRoot ) buildRegisterUI( registerRoot );
    }

    if ( document.readyState === 'loading' ) {
        document.addEventListener( 'DOMContentLoaded', init );
    } else {
        init();
    }

} )();
