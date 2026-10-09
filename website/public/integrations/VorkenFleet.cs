using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Libraries;

namespace Oxide.Plugins
{
    [Info("Vorken Fleet", "Vorken", "1.1.0")]
    [Description("Sincroniza banimentos e associação por time entre servidores do mesmo cliente Vorken.")]
    public class VorkenFleet : RustPlugin
    {
        private Settings settings;
        private SavedState state;
        private bool syncing;
        private bool applying;
        private bool stopping;
        private string StoreName => Name + "/" + ConVar.Server.identity;

        private class Settings
        {
            public string PanelUrl = "https://vorkenac.guerrafriarust.com.br";
            public string ServerKey = "";
            public float SyncSeconds = 10;
        }
        private class SavedState
        {
            public Dictionary<string, ManagedBan> Managed = new Dictionary<string, ManagedBan>();
            public List<LocalEvent> Events = new List<LocalEvent>();
            public long NotificationCursor;
            public long AppliedRevision;
        }
        private class ManagedBan
        {
            public long Expiry;
            public string Reason;
        }
        private class LocalEvent
        {
            public string id;
            public string type;
            public string steamId;
            public string playerName;
            public string reason;
            public long expiry;
            public List<string> team;
        }
        private class RemoteBan
        {
            public string steam_id;
            public string player_name;
            public string reason;
            public DateTime? expires_at;
            public bool direct;
        }
        private class Notification { public long id; public string message; }
        private class SyncReply
        {
            public List<RemoteBan> bans;
            public List<Notification> notifications;
            public List<string> acknowledgedEvents;
            public long revision;
        }

        protected override void LoadDefaultConfig() { settings = new Settings(); Config.WriteObject(settings, true); }
        private void Init()
        {
            settings = Config.ReadObject<Settings>() ?? new Settings();
            try { state = Interface.Oxide.DataFileSystem.ReadObject<SavedState>(StoreName) ?? new SavedState(); }
            catch { state = new SavedState(); }
            if (string.IsNullOrWhiteSpace(settings.ServerKey)) PrintWarning("Cadastre este servidor no painel e configure ServerKey. Nenhum banimento será alterado até conectar.");
        }
        private void OnServerInitialized()
        {
            timer.Every(Math.Max(5, settings.SyncSeconds), Sync);
            timer.Every(30, ExpireAssociations);
            Sync();
        }
        private void SaveState() { Interface.Oxide.DataFileSystem.WriteObject(StoreName, state); }
        private void Unload() { stopping = true; if (state != null) SaveState(); }
        private List<List<string>> Teams()
        {
            var manager = RelationshipManager.ServerInstance;
            if (manager == null) return new List<List<string>>();
            return manager.teams.Values.Select(t => t.members.Select(id => id.ToString()).ToList()).ToList();
        }
        private List<string> TeamFor(ulong id)
        {
            var manager = RelationshipManager.ServerInstance;
            var team = manager == null ? null : manager.FindPlayersTeam(id);
            return team == null ? new List<string> { id.ToString() } : team.members.Select(member => member.ToString()).ToList();
        }
        private void OnPlayerBanned(string playerName, ulong steamId, string address, string reason, long expiry)
        {
            if (applying || state == null) return;
            state.Events.Add(new LocalEvent {id=Guid.NewGuid().ToString("N"), type="ban", steamId=steamId.ToString(), playerName=playerName, reason=reason, expiry=expiry, team=TeamFor(steamId)});
            SaveState();
            NextTick(Sync);
        }
        private void OnPlayerUnbanned(string playerName, ulong steamId, string address)
        {
            if (applying || state == null) return;
            // A local unban is an explicit decision and must reach the entire client group.
            state.Events.Add(new LocalEvent {id=Guid.NewGuid().ToString("N"), type="unban", steamId=steamId.ToString(), playerName=playerName});
            state.Managed.Remove(steamId.ToString());
            SaveState();
            NextTick(Sync);
        }
        private void Sync()
        {
            if (syncing || stopping || string.IsNullOrWhiteSpace(settings.ServerKey)) return;
            Uri uri;
            if (!Uri.TryCreate(settings.PanelUrl, UriKind.Absolute, out uri) || uri.Scheme != "https")
            {
                PrintWarning("PanelUrl deve usar HTTPS. Verifique a configuração.");
                return;
            }
            syncing = true;
            var body = JsonConvert.SerializeObject(new {teams=Teams(), events=state.Events.Take(50).ToList(), notificationCursor=state.NotificationCursor, appliedRevision=state.AppliedRevision});
            webrequest.Enqueue(settings.PanelUrl.TrimEnd('/') + "/api/fleet/sync", body, (code, response) =>
            {
                syncing = false;
                if (stopping) return;
                if (code != 200) { PrintWarning("Sincronização pendente (HTTP " + code + "). Os eventos serão reenviados."); return; }
                try
                {
                    var reply = JsonConvert.DeserializeObject<SyncReply>(response);
                    if (reply == null || reply.bans == null || reply.notifications == null || reply.acknowledgedEvents == null) throw new Exception("Resposta incompleta");
                    Apply(reply);
                    state.Events.RemoveAll(e => reply.acknowledgedEvents.Contains(e.id));
                    state.AppliedRevision = reply.revision;
                    SaveState();
                }
                catch (Exception error) { PrintWarning("Resposta não aplicada: " + error.Message); }
            }, this, RequestMethod.POST, new Dictionary<string, string> { ["Content-Type"]="application/json", ["Authorization"]="Bearer " + settings.ServerKey }, 20f);
        }
        private void Apply(SyncReply reply)
        {
            var desired = new HashSet<string>();
            // Local decisions made while the request was in flight win over its older snapshot.
            var pending = new HashSet<string>(state.Events.Where(e => !reply.acknowledgedEvents.Contains(e.id)).Select(e => e.steamId));
            applying = true;
            try
            {
                foreach (var ban in reply.bans)
                {
                    ulong id;
                    if (!ulong.TryParse(ban.steam_id, out id)) throw new Exception("SteamID inválido");
                    long expiry = ban.expires_at.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(ban.expires_at.Value, DateTimeKind.Utc)).ToUnixTimeSeconds() : -1;
                    if (expiry > 0 && expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) continue;
                    desired.Add(ban.steam_id);
                    if (pending.Contains(ban.steam_id)) continue;
                    ManagedBan previous;
                    if (!state.Managed.TryGetValue(ban.steam_id, out previous) || previous.Expiry != expiry || previous.Reason != ban.reason)
                    {
                        ServerUsers.Set(id, ServerUsers.UserGroup.Banned, ban.player_name ?? ban.steam_id, ban.reason, expiry);
                        state.Managed[ban.steam_id] = new ManagedBan {Expiry=expiry,Reason=ban.reason};
                    }
                    var player = BasePlayer.FindByID(id);
                    if (player != null && player.IsConnected) player.Kick("VORKEN: " + ban.reason);
                }
                foreach (var id in state.Managed.Keys.ToList())
                {
                    if (desired.Contains(id) || pending.Contains(id)) continue;
                    ServerUsers.Remove(ulong.Parse(id));
                    state.Managed.Remove(id);
                }
                ServerUsers.Save();
                SaveState();
                foreach (var notice in reply.notifications.OrderBy(n => n.id))
                {
                    if (notice.id <= state.NotificationCursor) continue;
                    // Persist acknowledgement locally to avoid repeating chat on network retries/restarts.
                    state.NotificationCursor = notice.id;
                    SaveState();
                    PrintToChat(notice.message);
                }
            }
            finally { applying = false; }
        }
        private void ExpireAssociations()
        {
            if (state == null) return;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            applying = true;
            try
            {
                foreach (var pair in state.Managed.ToList())
                {
                    if (pair.Value.Expiry <= 0 || pair.Value.Expiry > now) continue;
                    ServerUsers.Remove(ulong.Parse(pair.Key));
                    state.Managed.Remove(pair.Key);
                }
                ServerUsers.Save();
                SaveState();
            }
            finally { applying = false; }
        }
    }
}
