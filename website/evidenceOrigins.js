const paths = item => [item?.targetPath,item?.currentPath,item?.originalPath,item?.path,item?.filePath,item?.artifact_value]
  .filter(value=>typeof value==='string'&&/^(?:[a-z]:[\\/]|\\\\)/i.test(value))
  .map(value=>value.replaceAll('/','\\').toLowerCase());

export function withDownloadOrigins(finding,payload={}) {
  const evidence=finding.evidence&&typeof finding.evidence==='object'?finding.evidence:{};
  const targets=new Set([...paths(finding),...paths(evidence)]);
  const matches=(Array.isArray(payload.browserDownloads)?payload.browserDownloads:[])
    .filter(item=>paths(item).some(path=>targets.has(path)))
    .map(item=>Object.fromEntries(['browser','profile','fileName','targetPath','currentPath','originalPath',
      'sourceUrl','finalUrl','pageUrl','referrerUrl','siteUrl','urlChain','startTimeUtc','endTimeUtc']
      .filter(key=>item[key]!=null).map(key=>[key,item[key]])));
  return {...evidence,...(matches.length?{downloadOrigins:matches}:{} )};
}
