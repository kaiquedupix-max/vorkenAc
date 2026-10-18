                else if (command.action == "unban")
                {
                    var user = ServerUsers.Get(steamId);
                    if (user != null && user.group == ServerUsers.UserGroup.Banned)
                    {
                        if (command.expectedReasons == null || Array.IndexOf(command.expectedReasons, user.notes) < 0)
                            throw new Exception("Ban atual difere do registro Vorken. Revise manualmente; nenhuma alteracao feita.");
                        ServerUsers.Remove(steamId);
                        ServerUsers.Save();
                    }
                    receipt.ok = true;
                    receipt.result = "Reversao confirmada no Rust. Historico preservado no Vorken.";
                }
