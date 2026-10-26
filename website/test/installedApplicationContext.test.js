import test from 'node:test';
import assert from 'node:assert/strict';
import {installedApplicationContext as context} from '../installedApplicationContext.js';
test('game libraries and Microsoft app names avoid generic executable heuristics',()=>{
 for(const path of ['C:\\Users\\r6fox\\AppData\\Local\\Ubisoft\\r6s\\RainbowSix.exe','C:\\Users\\joao\\AppData\\Local\\Ubisoft\\r6s\\RainbowSix.exe','D:\\SteamLibrary\\steamapps\\common\\Game\\game.exe','microsoftstore.exe','XboxPcApp.exe','GamingServices.exe']) assert.equal(context(path),true,path);
 assert.equal(context('C:\\Temp\\random.exe'),false);
 assert.equal(context('C:\\Ubisoft-fake\\random.exe'),false);
 assert.equal(context('C:\\Steam\\..\\Temp\\random.exe'),false);
 assert.equal(context('C:\\Windows\\System32\\example.exe',{signed:true,signerSubject:'Microsoft Corporation'}),true);
 assert.equal(context('C:\\Windows\\System32\\example.exe',{signed:false}),false);
});
