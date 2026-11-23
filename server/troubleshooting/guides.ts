// Phase 1FM: static, vetted first-response guidance only.
// Never infer device health or execute remote Windows commands.
export type TroubleCategory='PERFORMANCE'|'NETWORK'|'SYSTEM'|'HARDWARE'|'SECURITY'|'APPLICATION'|'PRIVACY';
export interface TroubleGuide{
 id:string;
 title:string;
 category:TroubleCategory;
 summary:string;
 keywords:readonly string[];
 firstChecks:readonly string[];
 escalateWhen:readonly string[];
 caution:string;
}
export class TroubleQueryError extends Error {}
const guide=(id:string,title:string,category:TroubleCategory,summary:string,keywords:string[],
 firstChecks:string[],escalateWhen:string[],caution:string):TroubleGuide=>({
 id,title,category,summary,keywords,firstChecks,escalateWhen,caution
});
export const WINDOWS_GUIDES:readonly TroubleGuide[]=Object.freeze([
 guide('pc-slow','My PC is slow','PERFORMANCE','Check resource pressure and recent changes before considering repairs.',
  ['lag','slow computer','high cpu','high memory','sluggish'],
  ['Save your work and restart the PC once.','Open Task Manager > Processes and sort by CPU, Memory and Disk to identify sustained usage.','Check available storage in Settings > System > Storage and review recently installed applications.'],
  ['Device remains unusable after a restart.','An unknown process consumes resources persistently.'],
  'Do not run registry cleaners, third-party optimizers or delete system folders.'),
 guide('wifi-no-internet','Wi-Fi connected but no internet','NETWORK','Separate a Wi-Fi link issue from an ISP or browser issue.',
  ['wifi connected','wi-fi no internet','dns','router','internet unavailable'],
  ['Try a second website and test another device on the same Wi-Fi.','Check Settings > Network & Internet for connection status and airplane mode.','Restart the router only if you administer it, after checking service advisories.'],
  ['Multiple devices have no internet.','The network is managed by a workplace or school.'],
  'Do not reset managed network settings or expose Wi-Fi passwords.'),
 guide('windows-update-fails',"Windows Update won't install",'SYSTEM','Collect the update error and basic system conditions first.',
  ['windows update error','update stuck','failed installation','patch'],
  ['Note the exact Windows Update error code and KB number.','Verify free storage and restart the PC.','Open Settings > Windows Update and use the built-in troubleshooter if available.'],
  ['The same update repeatedly rolls back.','Disk encryption or organizational update policy is involved.'],
  'Avoid deleting update caches or running elevated repair scripts without an approved backup and plan.'),
 guide('disk-almost-full','My disk is almost full','PERFORMANCE','Find large files safely without touching protected system folders.',
  ['low storage','c drive full','storage space','disk full'],
  ['Open Settings > System > Storage and review category breakdowns.','Review your own Downloads and Recycle Bin before deleting anything.','Move personal files to an independently verified backup destination if needed.'],
  ['Free space stays critically low.','Disk health warnings or unexpected growth appear.'],
  'Never mass-delete system, application, backup or another user’s files.'),
 guide('blue-screen','Blue screen of death','SYSTEM','Record the stop code and recent hardware or driver changes.',
  ['bsod','stop code','crash','blue screen','reboot loop'],
  ['Photograph the stop code and note when it happens.','Disconnect only recently attached nonessential peripherals while powered off.','Review Windows Update history and recent driver or hardware changes.'],
  ['Crashes repeat or Windows cannot start.','There are signs of storage failure or data corruption.'],
  'Back up important data when possible; do not disable security controls or flash firmware casually.'),
 guide('no-sound','No sound from my speakers','HARDWARE','Check the output route before changing drivers.',
  ['audio missing','speakers','mute','sound output','headphones'],
  ['Confirm the application and system are not muted.','Open Settings > System > Sound and choose the intended output device.','Test with another application or headphones to isolate the problem.'],
  ['The device is absent from Sound settings.','Sound fails after a driver or hardware change.'],
  'Do not uninstall multiple audio drivers or change firmware without a recovery plan.'),
 guide('bluetooth-not-connecting',"Bluetooth won't connect",'HARDWARE','Check device pairing and battery before resetting adapters.',
  ['bluetooth pairing','wireless mouse','wireless headset','device not found'],
  ['Verify Bluetooth is on and airplane mode is off.','Charge the accessory and place it near the PC.','Review Settings > Bluetooth & devices and remove/re-pair only your own accessory if safe.'],
  ['Bluetooth adapter is missing.','A managed or security-sensitive device cannot pair.'],
  'Avoid deleting other users’ paired devices or disabling company security policies.'),
 guide('printer-not-printing',"My printer won't print",'HARDWARE','Identify queue, connection and printer-side errors.',
  ['print queue','printer offline','paper jam','printing failure'],
  ['Check the printer display for paper, ink or error codes.','Confirm the correct printer is selected and check its queue.','Print a built-in test page if the printer is available and you have permission.'],
  ['A shared office printer is affected.','Print jobs contain confidential customer data.'],
  'Do not clear a shared print queue or reinstall enterprise printers without authorization.'),
 guide('screen-flicker-black','Screen flickering or black screen','HARDWARE','Determine whether the display, cable or system is at fault.',
  ['monitor black','display flickering','blank screen','screen flashing'],
  ['Check monitor power, brightness and cable seating while safe to do so.','Try an external display only if supported.','Note whether the issue occurs before Windows login or only after sign-in.'],
  ['There is visible physical damage, burning smell or overheating.','The system remains inaccessible.'],
  'Power down immediately if there is heat, smoke or electrical damage; do not open energized equipment.'),
 guide('slow-startup','My PC takes forever to boot','PERFORMANCE','Look at startup impact without disabling protection.',
  ['boot slow','startup slow','login takes long','boot time'],
  ['Record whether delay occurs before or after Windows sign-in.','Review Task Manager > Startup apps for high-impact optional programs.','Check storage free space and pending Windows updates.'],
  ['Boot failures, disk errors or repeated forced restarts occur.','A work-managed startup policy may be involved.'],
  'Do not disable disk encryption, endpoint protection or unknown services to speed boot.'),
 guide('suspected-malware','I think my PC has a virus','SECURITY','Prioritize safety, account protection and authorized incident handling.',
  ['malware','virus','ransomware','infected','security alert','phishing'],
  ['Avoid opening the suspicious attachment or file again.','Open Windows Security and review protection status and scan results.','For a managed PC, report suspected compromise promptly to your security team.'],
  ['Ransom notes, unusual sign-ins, unknown admin prompts or data theft are suspected.','Security tools report a high-severity threat.'],
  'Do not erase evidence, install unknown antivirus tools or share passwords. Follow organization incident procedures.'),
 guide('outlook-crashing','Outlook keeps crashing','APPLICATION','Isolate account, add-in and version problems safely.',
  ['outlook closes','email crashes','office mail','pst','ost'],
  ['Note whether Outlook crashes at launch or while reading a message.','Check if mail works in the authorized web interface.','Review recently installed Outlook/Office add-ins and updates.'],
  ['An entire organization or mailbox is affected.','A mailbox data file appears damaged or important mail is missing.'],
  'Never delete PST/OST files or remove account profiles without a confirmed backup and approval.'),
 guide('start-menu-frozen','Start Menu or taskbar is frozen','SYSTEM','Identify whether Explorer or the whole PC is unresponsive.',
  ['taskbar frozen','start button broken','windows explorer','shell freeze'],
  ['Try Ctrl+Alt+Delete and check if the sign-in/security screen responds.','Save work if possible and restart normally.','Note if the freeze began after an update or app installation.'],
  ['The whole PC repeatedly locks up.','There is evidence of a corrupt user profile or managed policy.'],
  'Avoid killing unknown system services, modifying the registry or forcing shutdown during updates.'),
 guide('battery-drains-fast','My laptop battery drains too fast','HARDWARE','Review battery use and safe charging conditions.',
  ['battery life','battery drain','laptop power','battery health'],
  ['Review Settings > System > Power & battery for recent usage.','Reduce unnecessary screen brightness and background apps.','Check whether battery drain happens while sleeping or during active use.'],
  ['Battery is swollen, unusually hot or physically damaged.','Runtime falls suddenly or the system shuts down unexpectedly.'],
  'Stop using a swollen or overheating battery; do not puncture it or attempt self-repair.'),
 guide('vpn-no-internet','VPN connected but no internet','NETWORK','Check whether DNS, routing or workplace policy is involved.',
  ['vpn no internet','corporate vpn','tunnel connected','vpn dns'],
  ['Confirm whether non-VPN internet works if your organization permits testing.','Record VPN client name, error details and which internal services fail.','Check for a known organizational VPN incident before reconnecting.'],
  ['The VPN is company managed.','Access to sensitive systems or split-tunnel policy may be affected.'],
  'Do not disable VPN, firewall or DNS policy to work around managed network restrictions.'),
 guide('copilot-disable',"Windows Copilot won't turn off",'PRIVACY','Review supported settings and device-management controls.',
  ['copilot disable','copilot remove','ai sidebar','windows copilot'],
  ['Check Windows Settings > Apps and taskbar personalization for available Copilot controls.','Record the Windows edition/version and whether the device is organization managed.','Ask IT to confirm the applicable management policy if settings are locked.'],
  ['The feature is enforced by a device policy.','Sensitive content appears in an unexpected AI interaction.'],
  'Do not use unverified registry tweaks or unapproved debloat scripts.'),
 guide('preinstalled-apps','Too many pre-installed apps','PERFORMANCE','Review installed applications without removing dependencies.',
  ['bloatware','preloaded apps','unwanted software','preinstalled'],
  ['Open Settings > Apps > Installed apps.','Identify vendor software you do not use and verify its purpose.','Uninstall only optional applications you own and understand, using normal Windows controls.'],
  ['A company image or licensed security software is involved.','An app cannot be uninstalled normally.'],
  'Avoid bulk-debloat scripts and do not remove drivers, recovery utilities or endpoint agents.'),
 guide('windows-privacy-telemetry','Windows is sending too much data','PRIVACY','Distinguish settings and network traffic from unverified telemetry claims.',
  ['telemetry','privacy data','diagnostic data','tracking'],
  ['Review Settings > Privacy & security > Diagnostics & feedback where available.','Review app permissions in Privacy & security.','Ask a device administrator about mandatory diagnostic settings on managed PCs.'],
  ['Unknown outbound traffic suggests compromise.','A regulated or organization-owned device has privacy concerns.'],
  'Do not block unknown Windows services or firewall destinations without understanding dependencies.'),
 guide('driver-update-broke',"A driver update broke something",'SYSTEM','Record the driver and symptoms before making changes.',
  ['driver rollback','graphics driver','device manager','new driver'],
  ['Note the affected device and the installation date.','Review Windows Update > Update history and Device Manager device status.','Consider the supported driver rollback option only after confirming the correct device and backup.'],
  ['Windows fails to boot.','Storage, networking or encryption drivers are affected.'],
  'Do not install drivers from third-party download sites or flash firmware without vendor guidance.'),
 guide('win11-context-menu',"Right-click menu is annoying in Win11",'SYSTEM','Use built-in Windows 11 options without registry hacks.',
  ['context menu','right click','show more options','windows 11 menu'],
  ['Use Show more options in the right-click menu when needed.','Check whether the app provides a supported context-menu integration.','Record the Windows build if context-menu behavior is unexpectedly broken.'],
  ['Explorer crashes when right-clicking.','Enterprise policy restricts shell extensions.'],
  'Do not install shell-patching tools or registry hacks merely to change menu appearance.')
]);
export const TROUBLE_CATEGORIES:readonly TroubleCategory[]=[
 'PERFORMANCE','NETWORK','SYSTEM','HARDWARE','SECURITY','APPLICATION','PRIVACY'
];
export function validateTroubleSearch(query:unknown,category:unknown):{query:string;category:TroubleCategory|''}{
 if(query!==undefined&&typeof query!=='string')throw new TroubleQueryError('Invalid search term');
 if(category!==undefined&&typeof category!=='string')throw new TroubleQueryError('Invalid category');
 const q=(query??'') as string;
 if(q.length>120||/[\u0000-\u001f\u007f]/.test(q))throw new TroubleQueryError('Invalid search term');
 if(category!==undefined&&category!==''&&!TROUBLE_CATEGORIES.includes(category as TroubleCategory))
  throw new TroubleQueryError('Invalid category');
 return {query:q.trim().normalize('NFKC').toLocaleLowerCase('en'),category:(category??'') as TroubleCategory|''};
}
export function searchTroubleGuides(query:unknown=undefined,category:unknown=undefined):TroubleGuide[]{
 const filter=validateTroubleSearch(query,category);
 const terms=filter.query.split(/\s+/u).filter(Boolean);
 return WINDOWS_GUIDES.filter(g=>(!filter.category||g.category===filter.category)&&
  terms.every(term=>[g.title,g.summary,...g.keywords,g.id.replace(/-/g,' ')].some(s=>
   s.toLocaleLowerCase('en').includes(term))));
}
export function troubleGuideById(id:unknown):TroubleGuide|undefined{
 return typeof id==='string'&&/^[a-z0-9-]{1,64}$/.test(id)?
  WINDOWS_GUIDES.find(g=>g.id===id):undefined;
}
