// </async> Client-Side Security Module

(function() {
    'use strict';

    // DISABLED FOR LOCALHOST - Uncomment for production
    return;

    // This security module applies to all pages.

    // A flag to prevent multiple triggers
    let violationTriggered = false;

    /**
     * Logs the violation and redirects the user to a "forbidden" page.
     */
    function triggerSecurityViolation() {
        if (violationTriggered) {
            return;
        }
        violationTriggered = true;

        try {
            // Attempt to clear console to hide any specific error messages
            console.clear();
            console.log('%c STOP!', 'color: red; font-size: 48px; font-weight: bold;');
            console.log('%c This area is restricted. Closing or interacting with developer tools is a violation of our terms of service.', 'font-size: 16px;');
        } catch (e) {
            // Console might be hooked. Ignore errors.
        }

        // Post a violation report to the backend for logging.
        // This is a fire-and-forget request that won't be cancelled by the redirect.
        try {
            if (navigator.sendBeacon) {
                navigator.sendBeacon('/api/security-violation', new Blob());
            } else {
                // Fallback for older browsers, though keepalive is not universally supported.
                fetch('/api/security-violation', { method: 'POST', keepalive: true }).catch(() => {});
            }
        } catch(e) {
            // sendBeacon might not be available or might fail.
        }
        
        // Use a very short timeout to ensure the beacon has a chance to be sent before redirect.
        setTimeout(() => {
            // Redirect to the forbidden page
            window.location.href = '/forbidden';
        }, 100);
    }

    /**
     * Prevents the default context menu (right-click).
     * @param {MouseEvent} e - The mouse event.
     */
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
    });

    /**
     * Prevents common keyboard shortcuts for developer tools and source viewing.
     * @param {KeyboardEvent} e - The keyboard event.
     */
    document.addEventListener('keydown', (e) => {
        // Block F12
        if (e.key === 'F12' || e.keyCode === 123) {
            e.preventDefault();
            triggerSecurityViolation();
            return;
        }
        // Block Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C
        if (e.ctrlKey && e.shiftKey && ['I', 'J', 'C'].includes(e.key.toUpperCase())) {
            e.preventDefault();
            triggerSecurityViolation();
            return;
        }
        // Block Ctrl+U (View Source)
        if (e.ctrlKey && e.key.toUpperCase() === 'U') {
            e.preventDefault();
            triggerSecurityViolation();
            return;
        }
    });

    /**
     * A check that uses the 'debugger' statement.
     * If dev tools are open, the 'debugger' statement will pause execution.
     * We can measure the time it takes to execute to infer if tools are open.
     * This is more reliable across browsers than dimension checks.
     */
    const debuggerCheck = () => {
        const startTime = new Date().getTime();
        // This line will only pause if developer tools are open
        debugger;
        const endTime = new Date().getTime();

        // If the time difference is significant, it means the debugger paused execution.
        // Increased threshold to avoid false positives on slow devices/browsers.
        if (endTime - startTime > 500) {
             triggerSecurityViolation();
        }
    };

    // Run checks periodically to catch dev tools being opened after page load.
    // The dimension-based check was removed as it caused false positives on some browsers (e.g., Firefox, iOS Safari).
    const checkInterval = setInterval(() => {
        try {
            debuggerCheck();
        } catch(e) {
            // If an error occurs (e.g., in a weird browser state), clear the interval to be safe
            clearInterval(checkInterval);
        }
    }, 1500);

})();
