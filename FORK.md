# Fork: Telenet username/password login

This is a fork of [Sholofly/lghorizon](https://github.com/Sholofly/lghorizon).
Its only change: for **Telenet (`be-nl`)** the setup and re-authentication forms
accept your **Telenet password**, so you no longer need to get a refresh token yourself.

How it works:

- `custom_components/lghorizon/telenet_login.py` (new) runs Telenet's own SSO login.
  That is OAuth2 authorization code + PKCE against Okta (secure.telenet.be), the same
  flow as `credential_login.py` in ChristoVanDurme/woelf-control4-telenet-tvbox.
  It returns a refresh token.
- `config_flow.py` adds an optional password field for `be-nl`. If a password is filled
  in and no refresh token, it logs in first. It then continues on the unchanged upstream
  refresh-token path. The password is **never stored**: the config entry only holds the
  refresh token, as upstream does, and the integration rotates that token itself.
- Small changes in `translations/en.json` and `nl.json` (labels), and in `manifest.json`
  (version suffix `-telenet.N`, documentation link).

All fork changes are marked with `# fork` in the code.

## Updating to a new upstream release

```bash
git fetch upstream --tags
git checkout telenet-login
git rebase --onto vX.Y.Z vOLD telenet-login   # vOLD = upstream tag we were based on
# fix conflicts (usually only config_flow.py), then set the manifest version to
# "X.Y.Z-telenet.1"
git push --force-with-lease origin telenet-login
gh release create vX.Y.Z-telenet.1 --target telenet-login --title "vX.Y.Z-telenet.1"
```

Then deploy `custom_components/lghorizon` to Home Assistant and restart it.
