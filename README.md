# CAP-AU Mastodon reporter bot

This is a crude reporting bot that takes the CAP-AU feed from the QFES website,
renders maps using OpenStreetMap, then posts the result to Mastodon.  The end
result can be seen live on Mastodon and BlueSky:

- [Mastodon](https://mastodon.longlandclan.id.au/@qldfire)
- [BlueSky](https://bsky.app/profile/qldfire.mastodon.longlandclan.id.au.ap.brid.gy)
  (via [fed.brid.gy](https://fed.brid.gy/ap/@qldfire@mastodon.longlandclan.id.au))

## Requirements

- Python 3.x (3.12 known to work)
- [python-requests](https://3.python-requests.org)
- [jinja2](https://jinja.palletsprojects.com/en/stable)
- [Mastodon.py](https://mastodonpy.readthedocs.io)
- [staticmaps](https://github.com/flopp/py-staticmaps)
- [lxml](https://lxml.de)

`staticmaps` will need Cairo libraries too.

## Deployment

It is recommended you use a `venv` unless you're certain that your operating
system's packages will be sufficiently recent.  For what it's worth, the author
uses Gentoo's standard packages for all except `staticmaps` and `Mastodon.py`.

You'll need to modify [the example config](example-config.yml) to your needs.

From there, run it from cron as often as you feel necessary.  Be sensible!

# Disclaimer

**PLEASE USE THIS CODE RESPONSIBLY**.  There is no guarantee made or implied by
the release of this code.  Efforts have been made to ensure that it does not
unreasonably stress QFD's web server (which seems to be an Amazon S3 bucket) or
OpenStreetMap tile servers.

Your bot should state that this is unofficial (unless you really are a
representative of the QFD deciding to use this code for an official service…
in which case, welcome!).  At no point should this code or the data obtained
by it, be used to mislead people into thinking this is an official service,
nor should users be lulled into solely trusting this as a formal data source.

# Contact details

Questions… you can reach me by:

- opening an issue on this project
- mentioning `@stuartl@longlandclan.id.au` on the Fediverse platforms
  (Mastodon, et all)
- mentioning `@stuartl.mastodon.longlandclan.id.au.ap.brid.gy` on BlueSky
- contacting me by email: lop off the first `@` on my fediverse handle and
  you've got my email address
