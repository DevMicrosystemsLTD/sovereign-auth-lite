( function () {
    'use strict';

    const cfg = window.SovAuthDash;
    if ( ! cfg ) return;

    /* ════════════════════════════════════════════════════════
       BASE64URL & UTILS
    ════════════════════════════════════════════════════════ */

    function b64urlToBuffer( b64url ) {
        const b64    = b64url.replace( /-/g, '+' ).replace( /_/g, '/' );
        const padded = b64.padEnd( b64.length + ( ( 4 - b64.length % 4 ) % 4 ), '=' );
        const binary = atob( padded );
        const bytes  = new Uint8Array( binary.length );
        for ( let i = 0; i < binary.length; i++ ) bytes[ i ] = binary.charCodeAt( i );
        return bytes.buffer;
    }

    function bufferToB64url( buffer ) {
        const bytes  = new Uint8Array( buffer );
        let   binary = '';
        for ( let i = 0; i < bytes.length; i++ ) {
            binary += String.fromCharCode( bytes[ i ] );
        }
        return btoa( binary ).replace( /\+/g, '-' ).replace( /\//g, '_' ).replace( /=/g, '' );
    }

    function getDeviceName() {
        const ua = navigator.userAgent;
        if ( /iPhone/.test( ua ) )  return 'iPhone';
        if ( /iPad/.test( ua ) )    return 'iPad';
        if ( /Android/.test( ua ) ) return 'Android';
        if ( /Mac/.test( ua ) )     return 'Mac';
        if ( /Windows/.test( ua ) ) return 'Windows PC';
        return 'Device';
    }

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
            
            if ( bytes[0] === 0 && bytes[1] === 0 && ( bytes[2] & 0xF0 ) === 0 ) {
                return challenge + ':' + nonceStr;
            }
            
            nonce++;
            if ( nonce % 2000 === 0 ) await new Promise( r => setTimeout( r, 0 ) );
        }
    }

    async function api( path, body = null, method = 'POST' ) {
        const bodyStr = body && method !== 'GET' ? JSON.stringify( body ) : null;
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': cfg.nonce },
            credentials: 'same-origin',
        };
        if ( bodyStr ) opts.body = bodyStr;

        if ( cfg.torMode && ( method === 'POST' || method === 'DELETE' ) ) {
            const fullPath = '/sovereign-auth/v1' + path;
            opts.headers[ 'X-SovAuth-PoW' ] = await solvePoW( fullPath, bodyStr );
        }

        const res  = await fetch( cfg.api + path, opts );
        const data = await res.json();

        if ( ! res.ok ) {
            throw new Error( data.message || `HTTP ${res.status}` );
        }
        return data;
    }

    /* ════════════════════════════════════════════════════════
       UI CONTROLLERS
    ════════════════════════════════════════════════════════ */

    const root     = document.getElementById( 'sovauth-dashboard-root' );
    if ( ! root ) return;

    const listEl   = document.getElementById( 'sov-dash-list' );
    const errorEl  = document.getElementById( 'sov-dash-error' );
    const succEl   = document.getElementById( 'sov-dash-success' );
    const addBtn   = document.getElementById( 'sov-dash-add-btn' );

    function setErr( msg ) {
        if ( ! msg ) { errorEl.classList.add( 'sov-hidden' ); return; }
        errorEl.textContent = msg;
        errorEl.classList.remove( 'sov-hidden' );
        succEl.classList.add( 'sov-hidden' );
    }

    function setSuccess( msg ) {
        succEl.textContent = msg;
        succEl.classList.remove( 'sov-hidden' );
        errorEl.classList.add( 'sov-hidden' );
        setTimeout( () => succEl.classList.add( 'sov-hidden' ), 5000 );
    }

    async function loadDevices() {
        try {
            const devices = await api( '/credentials', null, 'GET' );
            renderDevices( devices );
        } catch ( e ) {
            setErr( e.message );
            listEl.innerHTML = '';
        }
    }

    function renderDevices( devices ) {
        listEl.innerHTML = '';
        if ( devices.length === 0 ) {
            listEl.innerHTML = `<p class="sov-status sov-status--info">${cfg.i18n.loading}</p>`;
            return;
        }

        if ( ! cfg.isPremium && devices.length >= 1 ) {
            addBtn.disabled = true;
            addBtn.title = "The free version allows only 1 device. Upgrade to Pro to add more.";
            addBtn.textContent = "Upgrade to Pro for more devices";
        } else {
            addBtn.disabled = false;
            addBtn.title = "";
            addBtn.textContent = "+ Registra Dispositivo"; // Or whatever it was, actually it's "+ Registra Ora" in admin, we should preserve its original text
            // In init we don't have original text saved, so we just use what's likely there, or better:
            if ( ! addBtn.dataset.origText ) addBtn.dataset.origText = addBtn.textContent;
            addBtn.textContent = addBtn.dataset.origText;
        }

        devices.forEach( dev => {
            const name = dev.device_name || cfg.i18n.unknownDevice;
            const date = new Date( dev.created_at.replace( / /g, 'T' ) ).toLocaleDateString();
            const used = dev.last_used ? new Date( dev.last_used.replace( / /g, 'T' ) ).toLocaleDateString() : cfg.i18n.neverUsed;

            const revokeBtn = el( 'button', { type: 'button', class: 'sov-btn sov-btn--danger' }, cfg.i18n.revoke );
            revokeBtn.onclick = () => handleRevoke( dev.id, revokeBtn );

            // Prevent deleting the last device if there is only 1
            if ( devices.length <= 1 ) {
                revokeBtn.disabled = true;
                revokeBtn.title = "Add another device to remove this one.";
            }

            const item = el( 'div', { class: 'sov-device-item' },
                el( 'div', { class: 'sov-device-info' },
                    el( 'span', { class: 'sov-device-name' }, name ),
                    el( 'span', { class: 'sov-device-meta' }, `Registered: ${date} • Last used: ${used}` )
                ),
                revokeBtn
            );
            listEl.append( item );
        } );
    }

    async function handleRevoke( id, btn ) {
        if ( ! confirm( cfg.i18n.confirmRevoke ) ) return;
        setErr( null );
        btn.disabled = true;
        btn.textContent = '...';
        try {
            await api( `/credentials/${id}`, null, 'DELETE' );
            await loadDevices(); // refresh list
        } catch ( e ) {
            setErr( e.message );
            btn.disabled = false;
            btn.textContent = cfg.i18n.revoke;
        }
    }

    async function handleAddDevice() {
        setErr( null );
        addBtn.disabled = true;
        const origText = addBtn.textContent;
        addBtn.textContent = cfg.i18n.waitBio;

        try {
            if ( ! window.PublicKeyCredential ) {
                throw new Error( cfg.i18n.errWebauthnSupport );
            }

            // 1. Get options
            const opts = await api( '/webauthn/register/options', {} ); // Empty body for add-device

            const pubKey = {
                ...opts,
                challenge          : b64urlToBuffer( opts.challenge ),
                user               : { ...opts.user, id: b64urlToBuffer( opts.user.id ) },
                excludeCredentials : ( opts.excludeCredentials || [] ).map( c => (
                    { ...c, id: b64urlToBuffer( c.id ) }
                ) ),
            };

            // 2. Prompt biometrics
            const credential = await navigator.credentials.create( { publicKey: pubKey } );
            if ( ! credential ) throw new Error( cfg.i18n.errNoCred );

            // 3. Verify and store
            const res = await api( '/webauthn/register/verify', {
                pending_token : '', // Empty token indicates add-device flow for logged in user
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



            setSuccess( cfg.i18n.successAdd );
            await loadDevices();

        } catch ( e ) {
            setErr( e.message );
        } finally {
            addBtn.disabled = false;
            addBtn.textContent = origText;
        }
    }


    if ( addBtn ) {
        addBtn.addEventListener( 'click', handleAddDevice );
    }

    // Init
    if ( listEl ) {
        loadDevices();
    }

} )();
