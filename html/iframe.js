var sessionID;
window.onload = (_e) => {
  sessionID = encodeURIComponent(sessionStorage.getItem('sessionID'));
};
window.onbeforeunload = (_e) => {
  navigator.sendBeacon('/endSession?sessionID=' + sessionID);
};
