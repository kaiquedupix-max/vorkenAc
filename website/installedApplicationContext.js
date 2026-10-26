// Location is context for generic name/entropy heuristics, not file authenticity.
export function installedApplicationContext(value, evidence = {}) {
  const path = String(value || '').replaceAll('/', '\\').toLowerCase();
  if (path.split('\\').some(part => part === '..' || part === '.')) return false;
  const name = path.split('\\').pop();
  const signer = String(evidence.signerSubject || evidence.processSigner || '');
  if (evidence.signed === true && /Microsoft/i.test(signer) &&
      /^[a-z]:\\(?:windows\\|program files(?: \(x86\))?\\windowsapps\\)/.test(path)) return true;
  if (/^[a-z]:\\/.test(path) && /\\(?:steam|steamlibrary|steamapps|ubisoft|ubisoft game launcher)\\/.test(path)) return true;
  // Older execution artifacts sometimes contain only the executable name.
  return /^(?:microsoftstore|winstore\.app|xbox|xboxapp|xboxpcapp|gamingservices|gamingservicesnet|gamebar|gamebarftserver|gamebarpresencewriter)\.exe$/.test(name);
}
